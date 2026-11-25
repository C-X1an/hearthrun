#!/usr/bin/env python3
"""Reconstruct B-06 schedule, retention, overlap and cleanup from owned raw evidence."""
import argparse
import base64
from collections import Counter, defaultdict
from functools import lru_cache
import hashlib
from itertools import groupby
import json
import math
from pathlib import Path
import random
import re
import statistics

CHANNELS = ('attempts.jsonl', 'events.jsonl', 'samples.jsonl', 'samples-recovery.jsonl')
COUNTERS = ('VmRSS_bytes', 'VmHWM_bytes', 'fd_count', 'result_bytes', 'ledger_bytes', 'eviction_marker_bytes')
EMPTY = hashlib.sha256(b'').hexdigest().encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def raw_file(path, bound):
    require(path.resolve(strict=True) == path and path.is_file() and path.stat().st_size <= bound,
            'Unsafe or oversized evidence input')
    return path.read_bytes()


def rows(work, name, summary):
    recovery = summary['recovery']
    limit = recovery['committed_prefix_bytes'][name]
    path = work / name
    require(path.resolve(strict=True) == path and 0 <= limit <= path.stat().st_size <= 384 * 1024 * 1024,
            f'Invalid evidence prefix for {name}')
    require(name in recovery['poisoned_channels'] or limit == path.stat().st_size, f'Undeclared tail in {name}')
    with path.open('rb') as stream:
        while limit:
            raw = stream.readline(min(limit, 128 * 1024) + 1)
            require(0 < len(raw) <= limit and len(raw) <= 128 * 1024 and raw.endswith(b'\n'),
                    f'Incomplete row in committed {name}')
            limit -= len(raw)
            yield json.loads(raw)


@lru_cache(maxsize=5)
def oracle(variant):
    size = (4096, 16384, 65536, 262144, 1048576)[variant]
    data = bytes((index * 17 + variant * 29 + 3) & 255 for index in range(size))
    return size, sha(data)


def population(work):
    raw_plan = raw_file(work / 'schedule.json', 8 * 1024 * 1024)
    plan = json.loads(raw_plan)
    summary = json.loads(raw_file(work / 'summary.json', 128 * 1024))
    mode = plan['mode']
    require(mode in ('smoke', 'full') and summary['mode'] == mode and plan['benchmark'] == summary['benchmark'] == 'B-06',
            'Unexpected campaign kind')
    seeds = random.Random(plan['master_seed']).sample(range(1 << 32), 5 if mode == 'full' else 1)
    jobs_each = 1000 if mode == 'full' else 16
    count = len(seeds) * jobs_each
    require(plan['seeds'] == seeds and plan['planned'] == summary['planned'] == len(plan['rows']) == count
            and plan['jobs_each'] == jobs_each and plan['concurrency'] == 4 and plan['one_live_supervisor_each_seed'] is True
            and summary['samples_complete'] is True and summary['schedule_sha256'] == sha(raw_plan),
            'Incomplete manifest or sample denominator')
    require(summary['authoritative_samples_file'] in CHANNELS[2:], 'Unrecognized authoritative samples channel')
    samples = list(rows(work, summary['authoritative_samples_file'], summary))
    by_index = {row['sample_index']: row for row in samples}
    require(len(samples) == len(by_index) == count and set(by_index) == set(range(count)), 'Missing or duplicate sample')
    identity = ('sample_index', 'run_id', 'seed_index', 'seed', 'job_index', 'request_id', 'wave',
                'variant', 'workload', 'bytes', 'expected_sha256', 'concurrency')
    for index, scheduled in enumerate(plan['rows']):
        seed_index, job_index = divmod(index, jobs_each)
        seed = seeds[seed_index]
        variant = (seed + job_index) % 5
        request = sha(f"B06 {plan['run_id']} {seed} {job_index}".encode())[:32]
        expected = (index, plan['run_id'], seed_index, seed, job_index, request, job_index // 4, variant,
                    f'v{variant}', *oracle(variant), 4)
        require(tuple(scheduled[key] for key in identity) == tuple(by_index[index][key] for key in identity) == expected,
                f'Scheduled identity differs at {index}')
    verdicts = Counter(row['status'] for row in samples)
    require(dict(verdicts) == summary['counts'] and set(verdicts) <= {'PASS', 'FAIL', 'NOT RUN'}, 'Verdict population differs')
    attempts = list(rows(work, 'attempts.jsonl', summary))
    attempted = {row['sample_index']: row for row in attempts}
    require(len(attempted) == len(attempts) and set(attempted) == {i for i, row in by_index.items() if row['status'] != 'NOT RUN'},
            'Attempt population differs')
    for index, attempt in attempted.items():
        sample = by_index[index]
        require(all(attempt[key] == sample[key] for key in (*identity, 'submit_ns', 'submission')),
                'Attempt changed after commit')
    return plan, summary, by_index


def packet_from_record(record, expected):
    packet = {key: record[key] for key in ('v', 'request_id', 'profile_id', 'stage_id')}
    packet.update(op='submit', argv=[expected['workload']], wall_ms=10000)
    encoded = json_bytes(packet)
    require(packet == expected['submission'] and record['canonical_request'] == encoded.decode()
            and record['canonical_request_sha256'] == sha(encoded), 'Canonical request binding differs')
    return packet


def retired(witnesses, initial):
    require([row['original'] for row in witnesses] == initial
            and all(row['current'] is None or row['current']['start_ticks'] != row['original']['start_ticks']
                    for row in witnesses), 'A previously observed process survived owned cleanup')


def check_result(sample, row, initial, fixture, profile, stage):
    job = sample['job_id']
    record = row['record']
    require(record['job_id'] == job == row['job_id'] == initial['job_id'] and record['state'] == 'SUCCEEDED'
            and record['cleanup_confirmed'] is True and record['executable_digest'] == fixture
            and record['profile_digest'] == profile and record['stage_id'] == stage['stage_id']
            and record['stage_manifest_digest'] == stage['manifest_digest'] and record['started_monotonic_ns'] == sample['start_ns'],
            'Durable success or execution provenance differs')
    packet = packet_from_record(record, sample)
    meta = base64.b64decode(row['metadata_raw_base64'], validate=True)
    doc = json.loads(meta)
    size, expected = oracle(sample['variant'])
    require(sha(meta) == row['metadata_sha256'] and doc['job_id'] == job and doc['status'] == 'SUCCEEDED'
            and doc['cleanup_confirmed'] is True and doc['exit_code'] == 0 and doc['signal'] is None
            and doc['stdout_truncated'] is doc['stderr_truncated'] is False
            and doc['artifacts'] == row['actual_artifact_manifest'] == [{'path': 'payload.bin', 'size_bytes': size, 'sha256': expected}]
            and row['bundle_content_bytes'] == len(meta) + size, 'Committed bundle metadata or fixed artifact differs')
    digest = sha(b'HearthRun result bundle v1\0' + len(meta).to_bytes(8, 'big') + meta + (bytes(8) + EMPTY) * 2)
    require(digest == record['result_digest'] == sample['output_digest'], 'Result digest differs')
    receipt = row['cleanup_witness']
    require(receipt['leaf_removed'] is True and receipt['direct_populated_zero'] is None
            and sample['submit_ns'] <= sample['cleanup_ns'] <= row['monotonic_ns'] <= sample['finish_ns'],
            'Invalid observed cleanup evidence or clocks')
    retired(receipt['members'], initial['members'])
    retired(receipt['launchers'], initial['launchers'])
    phase = row['phase_page']
    events = phase['events']
    states = [state for state, _ in groupby(r['event'] for r in events)]
    require(phase['truncated'] is False and states
            == ['QUEUED', 'STARTING', 'RUNNING', 'CLEANUP_PENDING', 'EXPORTING', 'SUCCEEDED']
            and [r['sequence'] for r in events] == list(range(1, record['sequence'] + 1))
            and all(r['job_id'] == job for r in events), 'Success phase witness differs')
    return packet, record, meta


def check_wave(row, jobs, live):
    common = row['overlap_monotonic_ns']
    expected = {job: live[job]['cgroup_inode'] for job in jobs}
    require(len(expected) == 4 and len(set(expected.values())) == 4, 'Missing distinct live cgroups')
    for name, before in (('observations_before', True), ('observations', False)):
        values = row[name]
        require(len(values) == 4 and {x['job_id']: x['cgroup_inode'] for x in values} == expected
                and all(x['state'] == 'RUNNING' and x['populated'] == 1
                        and (x['monotonic_ns'] <= common if before else x['monotonic_ns'] >= common) for x in values),
                'Four owned groups do not bracket one live instant')


def snapshot_point(snapshot, proc, inventories, completed, results):
    kept = set(snapshot['retained_result_ids'])
    removed = set(snapshot['evicted_job_ids'])
    require(not kept & removed and kept | removed == results.keys() and len(kept) <= 100
            and snapshot['retained_results'] == len(kept) and snapshot['eviction_markers'] == len(removed)
            and snapshot['request_records'] == snapshot['metrics']['retained_requests'] == completed
            and snapshot['ledger_catalog']['entries'] == completed and snapshot['orphan_cgroups'] == []
            and snapshot['metrics']['active'] == snapshot['metrics']['queued'] == snapshot['metrics']['cleanup_pending'] == 0,
            'Idle retained identities, live resource or count differs')
    require(all(proc[key] == snapshot[key] for key in COUNTERS[:3]), 'Process metrics differ from raw samples')
    for key in ('results', 'ledger', 'evicted'):
        foot = snapshot[key]
        files = inventories.pop((snapshot['snapshot_id'], key), [])
        require(len(files) == foot['file_count'] and len({file['path'] for file in files}) == len(files)
                and sha(json_bytes(files) + b'\n') == foot['file_inventory_sha256']
                and sum(file['size_bytes'] for file in files) == foot['content_bytes']
                and sum(file['allocated_bytes'] for file in files) <= foot['allocated_bytes'], 'Snapshot file accounting differs')
    require(snapshot['results']['content_bytes'] == sum(results[job][0] for job in kept) <= 1024 ** 3
            and snapshot['evicted']['content_bytes'] == 64 * len(removed), 'Retention byte bounds differ')
    return [completed, *[proc[key] for key in COUNTERS[:3]],
            snapshot['results']['content_bytes'], snapshot['ledger']['content_bytes'], snapshot['evicted']['content_bytes']]


def replay_seed(work, seed_index, samples, events, fixture, report):
    selected = {row['sample_index']: row for row in samples if row['seed_index'] == seed_index}
    group = {row['job_id']: row for row in selected.values()}
    require(len(group) == len(selected), 'Duplicate actual job identity in seed')
    live, results, attempts, acknowledgements = {}, {}, {}, {}
    waves = set()
    points = []
    entries = defaultdict(list)
    spawn = proc = profile = stage = final = None
    for event in events:
        kind = event['type']
        if kind == 'supervisor_spawn':
            require(spawn is None and event['popen_pid'] == event['identity']['pid'], 'Unexpected supervisor restart')
            spawn = (event['identity']['pid'], event['identity']['start_ticks'])
        elif kind == 'installed_profile':
            manifest = base64.b64decode(event['retained_manifest_base64'], validate=True)
            require(profile is None and event['captured_fixture_sha256'] == event['retained_image_sha256'] == fixture
                    and event['profile']['executable_digest'] == fixture and event['profile']['profile_digest'] == sha(manifest)
                    and json.loads(manifest) == {'v': 1, 'profile_id': 'example', 'sha256': fixture}, 'Fixture identity differs')
            profile = sha(manifest)
        elif kind == 'staged_input':
            require(stage is None, 'Unexpected stage replacement')
            stage = event['response']
        elif kind == 'rpc_intent' and event['request']['op'] == 'submit':
            require(event['rpc_id'] not in attempts, 'Duplicate submit operation')
            attempts[event['rpc_id']] = event['request']
        elif kind == 'rpc_response' and event['rpc_id'] in attempts:
            require(event['rpc_id'] not in acknowledgements and event['response']['ok'] is True, 'Unexpected submit acknowledgment')
            acknowledgements[event['rpc_id']] = event['response']['result']
        elif kind == 'live_membership':
            job = event['job_id']
            require(job in group and job not in live and group[job]['sample_index'] == event['sample_index']
                    and len(event['members']) >= 3 and len(event['launchers']) == 1
                    and event['launchers'][0]['ppid'] == spawn[0], 'Unowned or duplicate live observation')
            live[job] = event
        elif kind == 'wave_concurrent_ready':
            wave = event['wave']
            require(wave not in waves, 'Duplicate concurrent wave')
            check_wave(event, [job for job, row in group.items() if row['wave'] == wave], live)
            waves.add(wave)
        elif kind == 'result_evidence':
            job = event['job_id']
            sample = group[job]
            require(job not in results and sample['sample_index'] == event['sample_index'], 'Duplicate or misattributed result')
            packet, record, meta = check_result(sample, event, live[job], fixture, profile, stage)
            rpc = sample['submit_rpc_id']
            require(attempts.pop(rpc) == packet and acknowledgements.pop(rpc) == sample['submit_ack']
                    == {'job_id': job, 'state': 'QUEUED', 'sequence': 1}, 'Captured RPC identity differs')
            results[job] = event['bundle_content_bytes'], record, meta
        elif kind == 'supervisor_proc':
            for field in ('identity', 'identity_after'):
                require((event[field]['pid'], event[field]['start_ticks']) == spawn, 'Unanchored supervisor process sample')
            parsed = {key + '_bytes': int(number) * 1024 for key, number in
                      re.findall(r'^(VmHWM|VmRSS):\s+(\d+) kB$', event['status_raw'], re.M)}
            require(set(parsed) == set(COUNTERS[:2]) and all(event[key] == value for key, value in parsed.items())
                    and event['fd_count'] == len(set(event['fd_numbers'])), 'Unreconciled supervisor proc metric')
            proc = event
        elif kind == 'footprint_files':
            target = entries[(event['snapshot_id'], event['category'])]
            require(len(target) == event['offset'] and len(event['files']) <= 128, 'Unexpected footprint chunk')
            target.extend(event['files'])
        elif kind == 'retention_snapshot':
            completed = len(results)
            require(completed == len(points) * 4 == event['completed_jobs'], 'Snapshot population differs')
            points.append(snapshot_point(event, proc, entries, completed, results))
            final = event
    require(set(results) == set(group) == set(live) and waves == set(range(len(group) // 4))
            and len(points) == len(waves) + 1 and not entries and not attempts and not acknowledgements,
            'Incomplete successful seed evidence')
    require(report['status'] == 'PASS' and report['completed_jobs'] == len(group) and report['supervisor_starts'] == 1
            and report['owned_children_reaped'] is True and report['owned_cgroups_remaining'] == 0
            and not report['teardown_errors'] and (report['spawn_identity']['pid'], report['spawn_identity']['start_ticks']) == spawn,
            'Owned teardown or supervisor identity differs')
    disk = work / f'seed-{seed_index:02d}' / 'state'
    raw = raw_file(disk / 'records/catalog.json', 256 * 1024)
    expected = {job: (result[1]['request_id'], result[1]['canonical_request_sha256']) for job, result in results.items()}
    catalog = json.loads(raw)
    require(sha(raw) == final['ledger_catalog']['sha256'] and len(catalog['entries']) == len(expected)
            and {row['job_id']: (row['request_id'], row['canonical_request_sha256']) for row in catalog['entries']} == expected
            and {p.name for p in (disk / 'records').iterdir()} == {'catalog.json', *(job + '.json' for job in results)}
            and not any((disk / 'scratch').iterdir()) and not (disk / 'control.sock').exists(), 'Final retry catalog or teardown state differs')
    kept = set(final['retained_result_ids'])
    require({p.name for p in (disk / 'results').iterdir()} == kept
            and {p.name for p in (disk / 'evicted').iterdir()} == results.keys() - kept, 'Final retention partition differs')
    for job, (_, record, meta) in results.items():
        require(json.loads(raw_file(disk / f'records/{job}.json', 65536)) == record, 'Final durable job record differs')
        if job in kept:
            directory = disk / 'results' / job
            data = raw_file(directory / 'artifacts/payload.bin', 1024 ** 2)
            require(raw_file(directory / 'result.json', 65536) == meta and sha(data) == group[job]['expected_sha256']
                    and raw_file(directory / 'stdout.bin', 1024 ** 2) == raw_file(directory / 'stderr.bin', 1024 ** 2) == b'',
                    'Retained result bytes differ')
        else:
            require(raw_file(disk / 'evicted' / job, 64) == record['result_digest'].encode(), 'Eviction marker digest differs')
    peak = max(point[2] for point in points)
    require(peak == report['observed_supervisor_peak_rss_bytes'], 'Observed VmHWM summary differs')
    late = [point for point in points if point[0] >= 500]
    slopes = {}
    for index, field in enumerate(COUNTERS, start=1):
        observed = report['late_slopes'][field]
        if len(group) == 1000:
            slope = statistics.linear_regression([p[0] for p in late], [p[index] for p in late]).slope
            require(observed['status'] == 'MEASURED' and observed['n'] == len(late) == 126
                    and math.isclose(slope, observed['per_job'], rel_tol=1e-9, abs_tol=1e-10), 'Late regression differs')
            slopes[field] = slope
        else:
            require(observed['status'] == 'NOT YET MEASURED' and observed['per_job'] is None, 'Unexpected smoke slope')
    return {'seed_index': seed_index, 'jobs': len(group), 'waves': len(waves), 'snapshots': len(points),
            'retained_results': len(kept), 'eviction_markers': len(group) - len(kept), 'peak_rss_bytes_observed': peak,
            'fd_range': [min(p[3] for p in points), max(p[3] for p in points)], 'final_result_bytes': points[-1][4],
            'final_ledger_bytes': points[-1][5], 'late_slopes_per_job': slopes}


def main(work):
    require(work.is_absolute() and work.resolve(strict=True) == work, 'Pass the actual bounded work or rehashed restore path')
    plan, summary, samples = population(work)
    report = {'benchmark': 'B-06', 'mode': plan['mode'], 'planned': plan['planned'], 'counts': summary['counts'],
              'campaign_status': summary['status'], 'schedule_sha256': summary['schedule_sha256']}
    if summary['status'] != 'PASS':
        print(json.dumps({**report, 'status': 'VERIFIED DENOMINATOR', 'scope': 'Preserved failed campaign population'}))
        return
    require(summary['evidence_finalized'] is True and summary['counts'] == {'PASS': plan['planned']}
            and not summary['evidence_errors'] and not summary['finalization_errors']
            and not summary['recovery']['poisoned_channels'], 'Source does not establish a complete PASS')
    env = json.loads(raw_file(work / 'environment.json', 128 * 1024))
    fixture = env['build']['retention']['fixture_sha256']
    driver = env['driver_sha256']
    require(all(re.fullmatch('[0-9a-f]{64}', value) for value in (fixture, driver)), 'Missing executed fixture/driver identity')
    # The journal writes one uninterrupted supervisor's complete segment at a time.
    seed_events = []
    seeds = []
    for event in rows(work, 'events.jsonl', summary):
        if event['type'] == 'storage':
            continue
        require(event['seed_index'] == len(seeds), 'Overlapping or misordered supervised seeds')
        if event['type'] != 'seed_teardown':
            seed_events.append(event)
            continue
        require(len(seeds) < len(summary['seeds']) and summary['seeds'][len(seeds)]
                == {key: value for key, value in event.items() if key != 'type'}, 'Teardown summary does not match raw event')
        seeds.append(replay_seed(work, len(seeds), samples.values(), seed_events, fixture, event))
        seed_events.clear()
    require(not seed_events and len(seeds) == len(plan['seeds']), 'Missing complete seed or teardown')
    print(json.dumps({**report, 'status': 'PASS', 'fixture_sha256': fixture, 'driver_sha256': driver, 'seeds': seeds,
                      'scope': 'Fixed local workload and owned native process, cgroup, filesystem and kernel observations'},
                     sort_keys=True, allow_nan=False))


if __name__ == '__main__':
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--work', type=Path, required=True)
    main(cli.parse_args().work)
