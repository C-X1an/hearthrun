#!/usr/bin/env python3
"""Summarize measured JSONL samples without silently dropping failures."""
import argparse
import json
import math
import statistics
from pathlib import Path


def summarize(rows: list[dict]) -> dict:
    if not rows:
        raise ValueError('No measurements; cannot claim a benchmark')
    identities = set()
    values = []
    failures = 0
    for row in rows:
        for key in ('run_id', 'environment_id', 'policy_digest', 'duration_ms', 'status'):
            if key not in row:
                raise ValueError(f'Missing {key}')
        if row['run_id'] in identities:
            raise ValueError('Duplicate sample identity')
        identities.add(row['run_id'])
        if row['status'] not in {'PASS', 'FAIL', 'BLOCKED'}:
            raise ValueError('Unknown sample status')
        value = row['duration_ms']
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError('Invalid duration')
        if row['status'] == 'PASS':
            values.append(float(value))
        else:
            failures += 1
    if len({(r['environment_id'], r['policy_digest']) for r in rows}) != 1:
        raise ValueError('Stratify different environments/policies before summarizing')
    values.sort()
    def nearest_rank(p):
        return values[max(0, math.ceil(p * len(values)) - 1)] if values else None
    return {'samples_total': len(rows), 'samples_success': len(values), 'samples_failed_or_blocked': failures,
            'success_fraction': len(values) / len(rows), 'latency_population': 'successful samples only; failures reported separately',
            'p50_ms': nearest_rank(.5), 'p95_ms': nearest_rank(.95), 'p99_ms': nearest_rank(.99),
            'mean_ms': statistics.mean(values) if values else None,
            'stdev_ms': statistics.stdev(values) if len(values) > 1 else None,
            'quantile_method': 'nearest rank', 'p99_warning': 'Exploratory below 1000 successful samples' if len(values) < 1000 else None}


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('jsonl', type=Path)
    a = p.parse_args()
    print(json.dumps(summarize([json.loads(x) for x in a.jsonl.read_text().splitlines() if x.strip()]), indent=2))
