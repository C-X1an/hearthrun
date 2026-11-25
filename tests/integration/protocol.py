#!/usr/bin/env python3
"""Exercise fixed malformed submissions on a fresh owned native supervisor."""
import argparse
import importlib.util
import json
from pathlib import Path
import secrets
import signal
import sys

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('hearthrun_protocol_native', Path(__file__).resolve().parents[1] / 'e2e/native.py')
if spec is None or spec.loader is None:
    raise RuntimeError('Native fixture helper unavailable')
native = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = native
spec.loader.exec_module(native)


def exercise(suite):
    code, output, _ = suite.command([str(suite.bin_dir / 'hearthrun-supervisor'), 'install-profile',
                                     str(suite.state), 'example', str(suite.fixture)])
    native.require(code == 0 and native.strict_json(output)['profile_id'] == 'example', 'Approved test installation failed')
    suite.start()
    suite.doctor_case()
    fixture = suite.work / 'data.ndjson'
    native.write_synthetic(fixture, b'{"value":1}\n')
    stage = suite.cli('stage', f'data.ndjson={fixture}')['stage_id']
    budget = suite.cli('metrics')
    catalog = suite.state / 'records/catalog.json'
    before = native.read_file(catalog, native.MAX_CATALOG, owner=True, mode=0o600)
    for label, expected in [('oversized', 'BAD_FRAME'), ('duplicate_key', 'DUPLICATE_KEY'),
                            ('unknown_field', 'UNKNOWN_FIELD'), ('wrong_version', 'UNSUPPORTED_VERSION')]:
        packet = {'v': 2 if label == 'wrong_version' else 1, 'op': 'submit', 'profile_id': 'example',
                  'request_id': secrets.token_hex(16), 'stage_id': stage, 'argv': ['empty'], 'wall_ms': 10000}
        if label == 'unknown_field':
            packet['extra'] = 0
        header = json.dumps(packet, separators=(',', ':')).encode()
        if label == 'duplicate_key':
            header = b'{"\\u0076":1,' + header[1:]
        response = (suite.raw_request(b'', prefix=native.MAX_HEADER + 1) if label == 'oversized'
                    else suite.raw_request(header))
        if response.get('ok') is True:
            admitted = response.get('result', {}).get('job_id', '')
            if isinstance(admitted, str) and native.ID.fullmatch(admitted):
                suite.jobs.add(admitted)
        native.require(response['v'] == 1 and response['ok'] is False
                       and response['error']['code'] == expected and response['error']['retryable'] is False,
                       f'{label} did not return {expected}')
        native.require(suite.cli('metrics') == budget and not suite.inventory() and not suite.group_names()
                       and not any((suite.state / 'results').iterdir()) and not any((suite.state / 'scratch').iterdir())
                       and native.read_file(catalog, native.MAX_CATALOG, owner=True, mode=0o600) == before,
                       f'{label} changed an owned execution or storage boundary')
        native.emit(label, 'PASS', error_code=expected, admitted_jobs=0, committed_results=0, record_count_unchanged=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bin-dir', 'doctor', 'fixture', 'cgroup-root', 'work'):
        parser.add_argument(f'--{name}', required=True)
    suite = native.Harness(parser.parse_args())

    def stop(_signal, _frame):
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        raise native.Failure('termination requested during socket verification')

    signal.signal(signal.SIGTERM, stop)
    status = 1
    try:
        suite.preflight()
        exercise(suite)
        status = 0
    except native.Blocked as error:
        native.emit('protocol', 'BLOCKED', reason=str(error)[:1024])
        status = 78
    except Exception as error:
        native.emit('protocol', 'FAIL', reason=str(error)[:1024])
    finally:
        errors = suite.cleanup()
        if errors:
            native.emit('teardown', 'FAIL', errors=errors[:16])
            status = 1
        elif suite.created_work:
            native.emit('teardown', 'PASS', owned_cgroups_remaining=0)
    return status


if __name__ == '__main__':
    sys.exit(main())
