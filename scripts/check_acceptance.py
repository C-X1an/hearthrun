#!/usr/bin/env python3
"""Validate the preimplementation acceptance contract without changing its lock."""
import hashlib
import json
from pathlib import Path


def validate(root: Path) -> dict:
    raw = (root / 'spec/acceptance.json').read_bytes()
    expected = (root / 'spec/acceptance.sha256').read_text().split()[0]
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('Acceptance hash mismatch; preserve history and record an exception')
    data = json.loads(raw)
    if data.get('acceptance_spec_locked') is not True:
        raise ValueError('Acceptance specification is not locked')
    requirements = [r['id'] for r in data['requirements']]
    criteria = [a['id'] for a in data['criteria']]
    if len(requirements) != len(set(requirements)) or len(criteria) != len(set(criteria)):
        raise ValueError('Duplicate requirement or acceptance ID')
    for a in data['criteria']:
        if a['parent_requirement'] not in requirements:
            raise ValueError('Unknown parent requirement')
        for key in ('precondition', 'input', 'behavior', 'expected_result', 'tolerance',
                    'test_level', 'evidence_type', 'test_path', 'negative_control'):
            if not a.get(key):
                raise ValueError(f"Missing {key} in {a['id']}")
    return {'status': 'PASS', 'scope': 'contract integrity only',
            'requirements': len(requirements), 'criteria': len(criteria), 'sha256': expected}


if __name__ == '__main__':
    try:
        print(json.dumps(validate(Path(__file__).resolve().parents[1]), indent=2))
    except (OSError, ValueError, KeyError) as error:
        raise SystemExit(str(error))
