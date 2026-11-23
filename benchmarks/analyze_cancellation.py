#!/usr/bin/env python3
"""Check the exact native B-03 population and independently compute latency ranks."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import re
import sys

from analyze import lines, parse, read, require

MODES = ('spin', 'detached', 'output')
CONCURRENCIES = (1, 4)
STATUSES = {'PASS', 'FAIL', 'NOT RUN', 'INCOMPLETE'}


def ranks(data):
    ordered = sorted(data)
    result = {'max_ns': ordered[-1] if ordered else None, 'min_ns': ordered[0] if ordered else None}
    for percent in (50, 95, 99):
        rank = (len(ordered) * percent + 99) // 100
        result[f'p{percent}_ns'] = ordered[rank - 1] if rank else None
    return result


def checked_latency(row):
    require(row['state'] == 'CANCELLED' and row['cancel_ack']['cancel_requested'] is True,
            'passing row lacks an acknowledged cancellation')
    base = row['cancel_request_ns']
    require(row['submit_ns'] <= row['start_ns'] <= base <= row['cancel_ack_ns'] <= row['finish_ns']
            and base <= row['launcher_reap_ns'] <= row['cleanup_ns'] <= row['finish_ns']
            and base <= row['empty_confirmed_ns'] <= row['cleanup_ns'], 'nonmonotonic cancellation observations')
    require(row['cancel_receipt_ns'] is None and row['kill_request_ns'] is None,
            'unobserved server events contain timestamps')
    require(row['empty_confirmation'] in {'empty', 'removed'}, 'missing cgroup emptiness witness')
    require((row['empty_observed_ns'] is None or row['empty_observed_ns'] >= row['empty_confirmed_ns'])
            and row['launcher_reap_witness'] and re.fullmatch(r'[0-9a-f]{64}', row['output_digest']),
            'missing cleanup or result identity')
    for witness in row['launcher_reap_witness']:
        require(witness['current'] is None or witness['current']['start_ticks'] != witness['original']['start_ticks'],
                'original launcher was still present at cleanup')
    if row['workload'] == 'output':
        require(row['output_ready_bytes_per_stream'] == 131072
                and all(131072 < row[key] <= 1048576 for key in ('stdout_bytes', 'stderr_bytes')),
                'missing real output past readiness')
    return row['cleanup_ns'] - base


def compare_population(work):
    schedule = parse(read(work / 'schedule.json'))
    environment = parse(read(work / 'environment.json'))
    encoded = json.dumps({key: value for key, value in environment.items() if key != 'environment_id'},
                         sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    require(hashlib.sha256(encoded).hexdigest() == environment['environment_id'], 'environment fingerprint differs')
    mode, run_id = schedule['mode'], schedule['run_id']
    require(mode in {'smoke', 'full'} and schedule['benchmark'] == environment['benchmark'] == 'B-03',
            'invalid cancellation schedule or host record')
    seeds = random.Random(schedule['master_seed']).sample(range(1 << 32), 5 if mode == 'full' else 1)
    require(schedule['seeds'] == seeds, 'declared seeds differ from the master plan')
    expected = [(seed, workload, lanes, repetition) for seed in seeds for workload in MODES
                for lanes in CONCURRENCIES for repetition in range(100 if mode == 'full' else 8)]
    sample_bytes, attempt_bytes = read(work / 'samples.jsonl'), read(work / 'attempts.jsonl')
    samples, attempts = lines(sample_bytes), lines(attempt_bytes)
    sample_indices = {row['sample_index'] for row in samples}
    attempt_indices = {row['sample_index'] for row in attempts}
    require(len(sample_indices) == len(samples) == len(expected) == schedule['planned_jobs']
            and sample_indices == set(range(len(expected))) and len(attempt_indices) == len(attempts),
            'wrong sample count, duplicate identity or incomplete schedule')
    for batch in (samples, attempts, schedule['rows']):
        for row in batch:
            index = row['sample_index']
            require(row['run_id'] == run_id and index in sample_indices
                    and (row['seed'], row['workload'], row['concurrency'], row['repetition']) == expected[index],
                    'record differs from the independently derived schedule')
    planned = {row['sample_index']: row for row in schedule['rows']}
    require(len(planned) == len(schedule['rows']) == len(expected) and set(planned) == sample_indices,
            'wrong plan row count or duplicated plan index')
    for row in [*samples, *attempts]:
        control = planned[row['sample_index']]
        require(row['request_id'] == control['request_id'] and row['planned_cancel_delay_ms'] == control['planned_cancel_delay_ms'],
                'sample or attempt has different request identity or cancellation plan')
    require({row['sample_index'] for row in samples if row['status'] != 'NOT RUN'} == attempt_indices,
            'attempt and outcome sets differ')
    counts = Counter(row['status'] for row in samples)
    require(counts.keys() <= STATUSES, 'unknown sample outcome')
    summary = parse(read(work / 'summary.json'))
    require(summary['planned'] == len(expected) and summary['counts'] == counts, 'summary changed the raw denominator')
    groups = []
    for workload in MODES:
        for concurrency in CONCURRENCIES:
            rows = [row for row in samples if row['workload'] == workload and row['concurrency'] == concurrency]
            times = [checked_latency(row) for row in rows if row['status'] == 'PASS']
            recorded = [row for row in summary['groups'] if row['workload'] == workload and row['concurrency'] == concurrency]
            require(len(recorded) == 1, 'missing or duplicate summary group')
            measured = ranks(times)
            group_counts = Counter(row['status'] for row in rows)
            cleanup_pending = sum(row['cleanup_pending_observations'] > 0 for row in rows)
            for key, value in measured.items():
                require(recorded[0]['cancel_request_to_cleanup'][key] == value, 'recorded latency rank differs from raw data')
            require(recorded[0]['counts'] == group_counts and recorded[0]['cleanup_pending_jobs'] == cleanup_pending,
                    'recorded workload counts differ from raw data')
            groups.append({'workload': workload, 'concurrency': concurrency, 'counts': group_counts,
                           'cleanup_pending_jobs': cleanup_pending, 'client_cancel_to_observed_cleanup': measured})
    clean = summary['status'] == 'PASS' and counts == {'PASS': len(expected)}
    if clean:
        teardowns = [row for row in lines(read(work / 'events.jsonl')) if row['type'] == 'shard_teardown']
        require(teardowns and sum(row['jobs'] for row in teardowns) == len(expected)
                and len({row['shard'] for row in teardowns}) == len(teardowns)
                and all(row['status'] == 'PASS' and row['owned_cgroups_remaining'] == 0
                        and row['owned_children_reaped'] is True for row in teardowns), 'incomplete owned teardown evidence')
    return {'status': 'PASS' if clean else 'FAIL', 'mode': mode, 'counts': counts, 'groups': groups,
            'samples_sha256': hashlib.sha256(sample_bytes).hexdigest(),
            'attempts_sha256': hashlib.sha256(attempt_bytes).hexdigest(),
            'timing_scope': 'client cancel request to observed reap and cgroup emptiness',
            'exact_server_receipt_and_kill_issuance': None}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    try:
        report = compare_population(parser.parse_args().work)
        print(json.dumps(report, indent=2, sort_keys=True))
        sys.exit(0 if report['status'] == 'PASS' else 1)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({'status': 'FAIL', 'error': str(error)}), file=sys.stderr)
        sys.exit(1)
