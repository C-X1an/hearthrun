#!/usr/bin/env python3
"""Run existing scoped native positives; keep locked acceptance fail-closed.

No build, provisioning, evidence import, negative-control execution or completion
override. A scoped PASS is not a completed locked criterion. This first runner
always exits nonzero because it does not dispatch every locked assertion/control.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import sys

sys.dont_write_bytecode = True
MAX_SUMMARY = 128 * 1024
MAX_BINARY = 128 * 1024 * 1024
CASE_TIMEOUT = 300

# These are remaining coverage descriptions, not replacement acceptance rules.
# Every original negative_control is also emitted verbatim in the report.
GAPS = {
    'AC-001': 'Protocol tests and their independent guard control are not dispatched.',
    'AC-002': 'The independent capacity-increment negative control is not dispatched.',
    'AC-003': 'Feature refusals, a real unsupported host and the support-downgrade control are not dispatched.',
    'AC-004': 'First-instruction, each setup failure and early-release control are not dispatched.',
    'AC-005': 'The full named filesystem target suite and host-canary binding control are not dispatched.',
    'AC-006': 'Controlled listeners and their isolated network negative control are not implemented in this runner.',
    'AC-007': 'Injected control-FD provenance and its retention control are not dispatched.',
    'AC-008': 'The syscall/ABI suite and omitted architecture-check control are not dispatched.',
    'AC-009': 'Resource tests and omitted pids.max control are not dispatched.',
    'AC-010': 'The independent leader-only cancellation negative control is not dispatched.',
    'AC-011': 'Delayed terminal observations and premature-terminal control are not dispatched.',
    'AC-012': 'Recovery checkpoints and automatic-replay control are not dispatched.',
    'AC-013': 'Artifact suite and symlink-following control are not dispatched.',
    'AC-014': 'The full seeded quiescence campaign and early-export control are not dispatched.',
    'AC-015': 'Stream retention, event rollover and buffer-growth control are not dispatched.',
    'AC-016': 'Publication faults and ignored-fsync control are not dispatched.',
    'AC-017': 'Retry identity/restart tests and ignored-payload-digest control are not dispatched.',
    'AC-018': 'Protected profile identity tests and mutable-reopen control are not dispatched.',
    'AC-019': 'Fresh public-only reproduction and missing-export-fixture control are not dispatched.',
    'AC-020': 'All six isolated native pass/fail/pass campaigns and test-weakening control remain separate.',
    'AC-021': 'Full benchmark protocol, raw failure populations and omitted-sample control remain separate.',
    'AC-022': 'Fresh release audit, dependency/licenses and forbidden-private-path control remain separate.',
    'AC-023': 'Browser keyboard/focus observation and the unescaped-HTML control are not dispatched.',
    'AC-024': 'Independent findings-before-repair review and omission control remain separate.',
}


def make_plan(paths: dict, python: str) -> list[dict]:
    definitions = (
        ('admission', 'AC-002', 'FR-002', 'tests/integration/scheduler.py', ['--case', 'admission']),
        ('cancel', 'AC-010', 'REL-002', 'tests/integration/scheduler.py', ['--case', 'cancel']),
        ('demo', 'AC-023', 'UX-001', 'tests/e2e/demo.py', ['--check-report']),
    )
    result = []
    for name, criterion, requirement, script, switches in definitions:
        work = str(Path(paths['work']) / name)
        command = [python, '-B', script, *switches]
        for flag in ('bin_dir', 'doctor', 'fixture', 'cgroup_root'):
            command.extend(['--' + flag.replace('_', '-'), paths[flag]])
        command.extend(['--work', work])
        result.append(dict(id=name, criterion=criterion, requirement=requirement,
                           command=command, work=work))
    return result


def _json_pairs(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key in captured completion output')
        result[key] = value
    return result


def _events(raw: bytes) -> list[dict]:
    def reject_constant(value: str):
        raise ValueError('Nonfinite captured JSON number: ' + value)
    rows = [json.loads(line, object_pairs_hook=_json_pairs, parse_constant=reject_constant)
            for line in raw.decode('utf-8').splitlines() if line.strip()]
    if not rows or len(rows) > 128 or any(not isinstance(row, dict) for row in rows):
        raise ValueError('Missing or oversized structured completion output')
    return rows


def assess(case: dict, record: dict, stdout: bytes, stderr: bytes, source: str) -> dict:
    """Assess this captured invocation only; never complete a locked criterion."""
    code = record.get('exit_code')
    altered_exit = (record.get('timed_out') is not False or bool(record.get('log_errors'))
                    or any(log.get('eof_observed') is not True
                           for log in record.get('logs', {}).values()))
    result = {'id': case['id'], 'criterion': case['criterion'],
              'status': 'FAIL', 'capture_run_id': record.get('run_id'),
              'capture_exit_code': code, 'child_exit_code': None if altered_exit or record.get('error') else code,
              'teardown': {'status': 'UNKNOWN'}, 'capture': record}
    problems = []
    if (record.get('command') != case['command']
            or record.get('category') != 'acceptance-scoped'
            or record.get('requirements') != [case['criterion'], case['requirement']]
            or record.get('working_directory') != '.'):
        problems.append('Captured invocation does not match this planned check')
    if (not re.fullmatch('[0-9a-f]{64}', source)
            or record.get('source_sha256_before') != source
            or record.get('source_sha256_after') != source):
        problems.append('Source changed during this run or between scoped checks')
    if altered_exit:
        problems.append('Capture timed out, lost a pipe or reported a persistence error; exact child exit is unavailable')
    for label, raw in (('stdout', stdout), ('stderr', stderr)):
        log = record.get('logs', {}).get(label, {})
        if (log.get('truncated') is not False or log.get('eof_observed') is not True
                or log.get('retained_bytes') != len(raw) or log.get('total_bytes') != len(raw)
                or log.get('sha256') != hashlib.sha256(raw).hexdigest()):
            problems.append(label + ' is incomplete or does not match the durable capture')
    expected_status = 'PASS' if code == 0 else 'BLOCKED' if code == 78 else 'FAIL'
    if record.get('status') != expected_status or type(code) is not int:
        problems.append('Capture status and exit code disagree')
    # No completion or cleanup claim may be derived from invalid provenance.
    # In particular, the later successful-output parser must not overwrite UNKNOWN.
    if problems:
        result['reason'] = '; '.join(problems)
        return result
    rows = []
    try:
        if stdout:
            rows = _events(stdout)
        # Preserve a real final teardown observation even if the check failed.
        # Incomplete/tampered capture cannot establish teardown.
        if not problems and case['id'] in ('admission', 'cancel'):
            teardown = [row for row in rows if row.get('case') == 'scheduler_teardown']
            if len(teardown) == 1:
                observed = teardown[0]
                if (observed.get('status') == 'PASS' and observed.get('owned_children_reaped') is True
                        and type(observed.get('owned_cgroups_remaining')) is int
                        and observed['owned_cgroups_remaining'] == 0):
                    result['teardown'] = observed
                elif observed.get('status') == 'FAIL':
                    result['teardown'] = observed
    except (ValueError, UnicodeError, RecursionError, TypeError) as error:
        problems.append(str(error))
    if code != 0:
        result['status'] = 'BLOCKED' if code == 78 and not problems else 'FAIL'
        result['reason'] = '; '.join(problems) or record.get('error') or 'Scoped child returned a nonzero exit; inspect its exact captured diagnostics'
        return result
    try:
        rows = _events(stdout)
        if any(row.get('status') != 'PASS' for row in rows):
            raise ValueError('Captured output contains a failed, blocked or unknown observation')
        names = [row.get('case') for row in rows]
        if case['id'] in ('admission', 'cancel'):
            expected = ['preflight', 'doctor_and_socket']
            expected += (['four_running_sixteen_waiting_fifo'] if case['id'] == 'admission'
                         else ['whole_group_owner_cancel', 'whole_group_wall_expiry'])
            expected += ['scheduler_teardown', 'scheduler_integration']
            if names != expected or rows[-1].get('selected_case') != case['id']:
                raise ValueError('Expected scheduler observations/completion are missing or out of order')
            teardown = rows[-2]
            if (teardown.get('owned_children_reaped') is not True
                    or type(teardown.get('owned_cgroups_remaining')) is not int
                    or teardown['owned_cgroups_remaining'] != 0):
                raise ValueError('Exact scheduler teardown evidence is missing')
            result['teardown'] = teardown
        elif case['id'] == 'demo':
            if names != ['preflight', 'demo_report', 'demo_report_integrity']:
                raise ValueError('Expected report-aware demo completion is missing')
            check = rows[-1]
            if (check.get('worker_status') != 'PASS' or check.get('report_status') != 'PASS'
                    or check.get('file_links_checked') != 6 or check.get('section_targets_checked') != 5):
                raise ValueError('Saved report integrity did not verify its worker and cleanup records')
            result['teardown'] = {'status': 'PASS', 'source': 'demo_report_integrity',
                                  'scope': 'separate worker and wrapper cleanup verified by existing saved-report checker',
                                  'wrapper_record': str(Path(case['work']) / 'wrapper-cleanup.json'),
                                  'worker_record': str(Path(case['work']) / 'run/demo-observations.json')}
        else:
            raise ValueError('No assessor for this planned check')
    except (ValueError, UnicodeError, RecursionError, TypeError, KeyError) as error:
        problems.append(str(error))
    result['status'] = 'FAIL' if problems else 'PASS'
    result['reason'] = '; '.join(problems) if problems else 'Existing scoped native assertions and teardown passed; locked criterion remains incomplete'
    return result


def drive(plan: list[dict], run_case, results: list[dict] | None = None) -> list[dict]:
    """Stop after uncertainty: a child failure must not start another native run."""
    if results is None:
        results = []
    stopped = False
    for case in plan:
        if stopped:
            result = {'id': case['id'], 'criterion': case['criterion'], 'status': 'NOT RUN',
                      'reason': 'A preceding scoped check failed or was blocked; no further native dispatch'}
        else:
            try:
                result = run_case(case)
            except KeyboardInterrupt:
                # The callback was entered, so this criterion was attempted.
                # Its child may or may not have started; infer neither an exit
                # nor cleanup from an interruption or the outer runner cleanup.
                result = {'id': case['id'], 'criterion': case['criterion'], 'status': 'FAIL',
                          'interrupted': True, 'command': case.get('command'), 'work': case.get('work'),
                          'capture_exit_code': None, 'child_exit_code': None,
                          'teardown': {'status': 'UNKNOWN'},
                          'reason': 'Interrupted during the active scoped check; child start/exit and teardown are UNKNOWN. Inspect retained work before another run.'}
            stopped = result['status'] != 'PASS'
        results.append(result)
    return results


def summarize(contract: dict, results: list[dict], blocker: str | None = None) -> dict:
    by_id = {row['criterion']: row for row in results}
    failed = any(row['status'] == 'FAIL' for row in results)
    blocked = bool(blocker) or any(row['status'] == 'BLOCKED' for row in results)
    status = 'FAIL' if failed else 'BLOCKED' if blocked else 'INCOMPLETE'
    rows = []
    for criterion in contract['criteria']:
        cid = criterion['id']
        positive = by_id.get(cid, {'status': 'NOT RUN',
            'reason': 'No scoped dispatcher result from this invocation; historical evidence is not imported'})
        rows.append({'id': cid, 'parent_requirement': criterion['parent_requirement'],
                     'locked_test_path': criterion['test_path'], 'status': 'INCOMPLETE',
                     'scoped_positive': positive,
                     'negative_control': {'status': 'NOT RUN', 'locked_control': criterion['negative_control'],
                                          'reason': 'Negative controls are not dispatched by this runner'},
                     'remaining_coverage': GAPS.get(cid, 'No coverage assessor for this locked criterion')})
    return {'schema_version': 1, 'status': status, 'exit_code': 78 if blocked and not failed else 1,
            'scope': 'Existing scoped native positives only; full locked acceptance remains incomplete',
            'completed_criteria': 0, 'required_criteria': len(rows), 'blocker': blocker,
            'criteria': rows,
            'runner_failures': [row for row in results if row['criterion'] not in {c['id'] for c in contract['criteria']}]}


def validate_bounds(filesystem: str, options: set[str], byte_count: int, inodes: int) -> None:
    if (filesystem != 'tmpfs' or 'noswap' not in options
            or not 0 < byte_count <= 12_000_000_000 or not 0 < inodes <= 200_000):
        raise ValueError('Required bounded noswap tmpfs (<=12000000000 bytes and <=200000 inodes) is unavailable')


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError('Cannot load existing verification helper: ' + str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def fingerprints(paths: list[Path]) -> list[dict]:
    result = []
    for path in paths:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError('Operator binary path is not absolute, canonical and symlink-free')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BINARY:
                raise ValueError('Operator binary is not a bounded regular file')
            digest = hashlib.sha256()
            count = 0
            while chunk := os.read(fd, 65536):
                count += len(chunk)
                if count > MAX_BINARY:
                    raise ValueError('Operator binary grew beyond its provenance read bound')
                digest.update(chunk)
            after = os.fstat(fd)
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode')
            if count != info.st_size or any(getattr(info, k) != getattr(after, k) for k in fields):
                raise ValueError('Operator binary changed while hashing')
            result.append({'path': str(path), 'device': info.st_dev, 'inode': info.st_ino,
                           'size': count, 'sha256': digest.hexdigest(), 'mode': info.st_mode,
                           'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns})
        finally:
            os.close(fd)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    bindings = {'bin_dir': 'HEARTHRUN_BIN_DIR', 'doctor': 'HEARTHRUN_DOCTOR',
                'fixture': 'HEARTHRUN_FIXTURE', 'cgroup_root': 'HEARTHRUN_JOBS',
                'work': 'HEARTHRUN_ACCEPTANCE_WORK', 'tmp_root': 'TMPDIR'}
    for key, variable in bindings.items():
        parser.add_argument('--' + key.replace('_', '-'), default=os.environ.get(variable),
                            help='Existing absolute operator path; environment default: ' + variable)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        locked = load('hearthrun_acceptance_lock', root / 'scripts/check_acceptance.py').validate(root)
        contract = json.loads((root / 'spec/acceptance.json').read_bytes())
    except (OSError, ValueError, KeyError) as error:
        print(json.dumps({'status': 'FAIL', 'exit_code': 1, 'reason': 'Locked contract validation failed: ' + str(error)}))
        return 1
    results = []
    blocker = None
    prepared = None
    capture = None
    native = None
    binaries = []
    provenance = []
    runner_teardown = {'status': 'NOT RUN'}
    def terminate(signum, _frame):
        signal.signal(signum, signal.SIG_DFL)
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, terminate)
    try:
        missing = [variable for key, variable in bindings.items() if not getattr(args, key)]
        if missing:
            raise ValueError('Set explicit operator paths: ' + ', '.join(missing))
        if sys.platform != 'linux' or platform.machine() != 'x86_64':
            raise ValueError('Native acceptance requires Linux x86-64; this host is unsupported')
        if os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgroups():
            raise ValueError('Run as the scoped non-root project UID with no supplementary groups')
        native = load('hearthrun_acceptance_native', root / 'tests/e2e/native.py')
        capture = load('hearthrun_acceptance_capture', root / 'scripts/capture.py')
        for key in bindings:
            path = native.absolute(getattr(args, key))
            setattr(args, key, str(path))
        work = Path(args.work)
        if root == work or root in work.parents or work in root.parents:
            raise ValueError('Acceptance work/evidence must be outside product source')
        temporary = Path(args.tmp_root)
        native.require(temporary.resolve(strict=True) == temporary, 'TMPDIR contains a symlink')
        native.private_directory(temporary)
        for directory in (work.parent, temporary):
            filesystem, options = native.mount_for(directory)
            fs = os.statvfs(directory)
            validate_bounds(filesystem, options, fs.f_blocks * fs.f_frsize, fs.f_files)
        native.require(work.parent.stat().st_dev == temporary.stat().st_dev,
                       'Work, capture and TMPDIR must share the bounded filesystem')
        os.environ['TMPDIR'] = str(temporary)
        os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
        prepared = native.Harness(args)
        prepared.preflight()  # Existing no-guest preflight also owns the retained jobs-root FD.
        binaries = [Path(args.bin_dir) / name for name in ('hearthrun', 'hearthrun-supervisor', 'hearthrun-launcher')]
        binaries += [Path(args.doctor), Path(args.fixture)]
        provenance = fingerprints(binaries)
        source = capture.source_digest(root)
        plan = make_plan({key: getattr(args, key) for key in bindings}, sys.executable)

        def run_case(case: dict) -> dict:
            record = None
            try:
                if fingerprints(binaries) != provenance:
                    raise ValueError('Operator binary identities changed before scoped dispatch')
                record = capture.capture(case['command'], root, work / 'evidence', 'acceptance-scoped',
                                         [case['criterion'], case['requirement']], timeout=CASE_TIMEOUT)
                raw = []
                for label in ('stdout', 'stderr'):
                    relative = Path(record['logs'][label]['path'])
                    native.require(not relative.is_absolute() and '..' not in relative.parts,
                                   'Capture returned an unsafe log path')
                    raw.append(native.read_file(work / 'evidence' / relative, capture.LOG_LIMIT,
                                                owner=True, mode=0o600))
                result = assess(case, record, *raw, source)
                if fingerprints(binaries) != provenance:
                    result.update(status='FAIL', reason='Operator binary identities changed during scoped check')
                return result
            except Exception as error:
                return {'id': case['id'], 'criterion': case['criterion'], 'status': 'FAIL',
                        'reason': 'Scoped dispatch/evidence verification failed: ' + type(error).__name__ + ': ' + str(error),
                        'teardown': {'status': 'UNKNOWN'}, 'work': case['work'], 'capture': record}
        drive(plan, run_case, results)
    except (OSError, ValueError, RuntimeError) as error:
        blocker = str(error)
    except KeyboardInterrupt:
        results.append({'id': 'interrupted', 'criterion': 'RUNNER', 'status': 'FAIL',
                        'reason': 'Runner interrupted; current child exit and teardown may be unknown. Inspect retained exact work paths before another run.'})
    finally:
        if prepared is not None:
            try:
                errors = prepared.cleanup()  # No borrowed/native job IDs are granted cleanup authority here.
            except (OSError, RuntimeError) as error:
                errors = ['Runner ownership cleanup could not be established: ' + str(error)]
            runner_teardown = {'status': 'FAIL' if errors else 'PASS', 'errors': errors,
                               'scope': 'runner preflight ownership; each native child records its own teardown'}
            if errors:
                results.append({'id': 'runner_teardown', 'criterion': 'RUNNER', 'status': 'FAIL',
                                'reason': '; '.join(errors)})
    report = summarize(contract, results, blocker)
    report.update(locked_contract=locked, operator_binaries=provenance, runner_teardown=runner_teardown,
                  operator_paths={key: getattr(args, key) for key in bindings},
                  dispatcher={'path': str(Path(__file__).resolve()),
                              'sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    if prepared is not None and prepared.created_work and capture is not None:
        try:
            data = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
            if len(data) > MAX_SUMMARY:
                raise ValueError('Acceptance report exceeds its fixed byte bound')
            directory = capture._directory(Path(args.work))
            try:
                fd = capture._evidence_file(directory, 'acceptance-summary.json')
                try:
                    capture._write_all(fd, data)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(directory)
            finally:
                os.close(directory)
        except (OSError, ValueError) as error:
            report.update(status='FAIL', exit_code=74, persistence_error=str(error))
    print(json.dumps(report, sort_keys=True, indent=2))
    return report['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
