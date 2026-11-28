"""Pure dispatcher/assessment tests. These do not execute native guests."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('acceptance_runner', ROOT / 'scripts/acceptance.py')
runner = None
if (ROOT / 'scripts/acceptance.py').exists():
    runner = importlib.util.module_from_spec(SPEC)
    sys.modules[SPEC.name] = runner
    SPEC.loader.exec_module(runner)


def contract():
    return {'criteria': [{'id': f'AC-{n:03}', 'parent_requirement': f'R-{n}',
                          'test_path': f'locked/{n}', 'negative_control': f'control {n}'}
                         for n in range(1, 25)]}


def sample_case():
    return {'id': 'admission', 'criterion': 'AC-002', 'requirement': 'FR-002',
            'command': ['/python', '-B', 'tests/integration/scheduler.py', '--case', 'admission'],
            'work': '/bounded/admission'}


def captured(stdout, code=0):
    return {'schema_version': 1, 'run_id': '20261127T000000-0123456789ab',
            'command': sample_case()['command'], 'category': 'acceptance-scoped',
            'requirements': ['AC-002', 'FR-002'], 'working_directory': '.',
            'status': 'PASS' if code == 0 else 'BLOCKED' if code == 78 else 'FAIL',
            'exit_code': code, 'timed_out': False, 'log_errors': [],
            'source_sha256_before': 'a' * 64, 'source_sha256_after': 'a' * 64,
            'git_commit': None, 'git_dirty': False,
            'logs': {'stdout': {'path': 'raw/test.stdout', 'sha256': hashlib.sha256(stdout).hexdigest(),
                                'total_bytes': len(stdout), 'retained_bytes': len(stdout),
                                'truncated': False, 'eof_observed': True},
                     'stderr': {'path': 'raw/test.stderr', 'sha256': hashlib.sha256(b'').hexdigest(),
                                'total_bytes': 0, 'retained_bytes': 0,
                                'truncated': False, 'eof_observed': True}}}


def events(*rows):
    return b''.join(json.dumps(row).encode() + b'\n' for row in rows)


def success_output():
    return events({'case': 'preflight', 'status': 'PASS'},
                  {'case': 'doctor_and_socket', 'status': 'PASS'},
                  {'case': 'four_running_sixteen_waiting_fifo', 'status': 'PASS'},
                  {'case': 'scheduler_teardown', 'status': 'PASS',
                   'owned_children_reaped': True, 'owned_cgroups_remaining': 0},
                  {'case': 'scheduler_integration', 'status': 'PASS', 'selected_case': 'admission'})


class AcceptanceRunnerTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(runner, 'the fail-closed acceptance dispatcher is not implemented')

    def test_dispatch_uses_existing_script_exact_case_and_explicit_operator_paths(self):
        paths = {key: f'/operator/{key}' for key in ('bin_dir', 'doctor', 'fixture', 'cgroup_root', 'work')}
        plan = runner.make_plan(paths, '/python')
        self.assertEqual([row['criterion'] for row in plan], ['AC-002', 'AC-010', 'AC-023'])
        self.assertEqual(plan[0]['command'], ['/python', '-B', 'tests/integration/scheduler.py',
            '--case', 'admission', '--bin-dir', '/operator/bin_dir', '--doctor', '/operator/doctor',
            '--fixture', '/operator/fixture', '--cgroup-root', '/operator/cgroup_root',
            '--work', str(Path('/operator/work') / 'admission')])
        self.assertIn('--check-report', plan[2]['command'])
        self.assertEqual(len({row['work'] for row in plan}), 3)

    def test_scoped_positive_retains_exit_and_teardown_without_completing_criterion(self):
        raw = success_output()
        result = runner.assess(sample_case(), captured(raw), raw, b'', 'a' * 64)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['child_exit_code'], 0)
        self.assertEqual(result['teardown']['status'], 'PASS')
        report = runner.summarize(contract(), [result])
        self.assertEqual(report['status'], 'INCOMPLETE')
        self.assertNotEqual(report['exit_code'], 0)
        self.assertEqual(len(report['criteria']), 24)
        self.assertEqual(report['criteria'][1]['scoped_positive']['status'], 'PASS')
        self.assertTrue(all(row['status'] == 'INCOMPLETE' for row in report['criteria']))
        self.assertTrue(all(row['negative_control']['status'] == 'NOT RUN' for row in report['criteria']))

    def test_cancel_and_demo_use_their_own_completion_and_teardown_contracts(self):
        cases = [
            ({'id': 'cancel', 'criterion': 'AC-010', 'requirement': 'REL-002', 'command': ['/cancel'], 'work': '/work/cancel'},
             events({'case': 'preflight', 'status': 'PASS'},
                    {'case': 'doctor_and_socket', 'status': 'PASS'},
                    {'case': 'whole_group_owner_cancel', 'status': 'PASS'},
                    {'case': 'whole_group_wall_expiry', 'status': 'PASS'},
                    {'case': 'scheduler_teardown', 'status': 'PASS', 'owned_children_reaped': True,
                     'owned_cgroups_remaining': 0},
                    {'case': 'scheduler_integration', 'status': 'PASS', 'selected_case': 'cancel'})),
            ({'id': 'demo', 'criterion': 'AC-023', 'requirement': 'UX-001', 'command': ['/demo'], 'work': '/work/demo'},
             events({'case': 'preflight', 'status': 'PASS'},
                    {'case': 'demo_report', 'status': 'PASS'},
                    {'case': 'demo_report_integrity', 'status': 'PASS', 'worker_status': 'PASS',
                     'report_status': 'PASS', 'file_links_checked': 6, 'section_targets_checked': 5})),
        ]
        for case, raw in cases:
            with self.subTest(case=case['id']):
                record = captured(raw)
                record.update(command=case['command'], requirements=[case['criterion'], case['requirement']])
                result = runner.assess(case, record, raw, b'', 'a' * 64)
                self.assertEqual(result['status'], 'PASS', result['reason'])
                self.assertEqual(result['teardown']['status'], 'PASS')

    def test_all_dispatched_positives_still_cannot_pass_full_gate(self):
        results = [{'criterion': key, 'id': key, 'status': 'PASS'}
                   for key in ('AC-002', 'AC-010', 'AC-023')]
        report = runner.summarize(contract(), results)
        self.assertEqual(report['exit_code'], 1)
        self.assertEqual(report['completed_criteria'], 0)
        self.assertEqual(report['criteria'][5]['scoped_positive']['status'], 'NOT RUN')

    def test_zero_exit_without_exact_teardown_or_completion_is_failed(self):
        for rows in (
            [{'case': 'scheduler_integration', 'status': 'PASS', 'selected_case': 'admission'}],
            [{'case': 'scheduler_teardown', 'status': 'PASS', 'owned_children_reaped': True,
              'owned_cgroups_remaining': 1}],
            [{'case': 'scheduler_teardown', 'status': 'PASS', 'owned_children_reaped': 1,
              'owned_cgroups_remaining': 0}],
        ):
            with self.subTest(rows=rows):
                raw = events(*rows)
                result = runner.assess(sample_case(), captured(raw), raw, b'', 'a' * 64)
                self.assertEqual(result['status'], 'FAIL')

    def test_bad_capture_cannot_be_a_positive(self):
        raw = success_output()
        changes = [({'source_sha256_after': 'b' * 64}, None),
                   ({'source_sha256_before': 'b' * 64, 'source_sha256_after': 'b' * 64}, None),
                   ({'command': ['/wrong']}, None), ({'log_errors': ['write error']}, None),
                   ({'timed_out': True}, None), ({'status': 'FAIL'}, None),
                   ({}, {'truncated': True}), ({}, {'eof_observed': False}),
                   ({}, {'sha256': '0' * 64})]
        for top, log in changes:
            with self.subTest(top=top, log=log):
                record = captured(raw)
                record.update(top)
                if log:
                    record['logs']['stdout'].update(log)
                result = runner.assess(sample_case(), record, raw, b'', 'a' * 64)
                self.assertEqual(result['status'], 'FAIL')
                self.assertEqual(result['teardown']['status'], 'UNKNOWN')

    def test_real_nonzero_and_signal_exits_are_preserved(self):
        for code, status in ((7, 'FAIL'), (-9, 'FAIL'), (78, 'BLOCKED')):
            result = runner.assess(sample_case(), captured(b'', code), b'', b'', 'a' * 64)
            self.assertEqual((result['child_exit_code'], result['status']), (code, status))

    def test_timeout_does_not_invent_an_exact_child_exit(self):
        record = captured(b'', 124)
        record['timed_out'] = True
        result = runner.assess(sample_case(), record, b'', b'', 'a' * 64)
        self.assertIsNone(result['child_exit_code'])
        self.assertEqual(result['capture_exit_code'], 124)

    def test_launch_failure_is_not_misreported_as_a_child_exit(self):
        record = captured(b'', 78)
        record['error'] = 'Executable unavailable: /python'
        result = runner.assess(sample_case(), record, b'', b'', 'a' * 64)
        self.assertIsNone(result['child_exit_code'])
        self.assertEqual((result['capture_exit_code'], result['status']), (78, 'BLOCKED'))

    def test_nonzero_native_check_retains_observed_successful_teardown(self):
        raw = events({'case': 'scheduler_integration', 'status': 'FAIL', 'reason': 'assertion failed'},
                     {'case': 'scheduler_teardown', 'status': 'PASS',
                      'owned_children_reaped': True, 'owned_cgroups_remaining': 0})
        result = runner.assess(sample_case(), captured(raw, 1), raw, b'', 'a' * 64)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['teardown']['status'], 'PASS')

    def test_driver_records_active_interruption_and_never_dispatches_later_cases(self):
        result = []
        called = []
        def one(case):
            called.append(case['id'])
            if case['id'] == 'cancel':
                raise KeyboardInterrupt()
            return {'id': case['id'], 'criterion': case['criterion'], 'status': 'PASS'}
        active = {'id': 'cancel', 'criterion': 'AC-010', 'command': ['/python', '-B', 'cancel.py'],
                  'work': '/bounded/cancel'}
        try:
            runner.drive([sample_case(), active, {'id': 'demo', 'criterion': 'AC-023'}], one, result)
        except KeyboardInterrupt:
            self.fail('Active interrupted dispatch escaped without its criterion result')
        self.assertEqual(called, ['admission', 'cancel'])
        self.assertEqual([row['status'] for row in result], ['PASS', 'FAIL', 'NOT RUN'])
        self.assertEqual(result[1]['criterion'], 'AC-010')
        self.assertTrue(result[1]['interrupted'])
        self.assertEqual(result[1]['command'], ['/python', '-B', 'cancel.py'])
        self.assertEqual(result[1]['work'], '/bounded/cancel')
        self.assertIsNone(result[1]['child_exit_code'])
        self.assertIsNone(result[1]['capture_exit_code'])
        self.assertEqual(result[1]['teardown']['status'], 'UNKNOWN')
        report = runner.summarize(contract(), result)
        self.assertEqual((report['status'], report['exit_code']), ('FAIL', 1))
        self.assertEqual(report['criteria'][9]['scoped_positive']['status'], 'FAIL')
        self.assertEqual(report['criteria'][22]['scoped_positive']['status'], 'NOT RUN')
        self.assertIn('preceding', report['criteria'][22]['scoped_positive']['reason'])
        self.assertEqual(report['completed_criteria'], 0)

    def test_invalid_capture_never_establishes_demo_teardown(self):
        case = {'id': 'demo', 'criterion': 'AC-023', 'requirement': 'UX-001',
                'command': ['/demo'], 'work': '/bounded/demo'}
        raw = events({'case': 'preflight', 'status': 'PASS'},
                     {'case': 'demo_report', 'status': 'PASS'},
                     {'case': 'demo_report_integrity', 'status': 'PASS', 'worker_status': 'PASS',
                      'report_status': 'PASS', 'file_links_checked': 6, 'section_targets_checked': 5})
        record = captured(raw)
        record.update(command=['/demo'], requirements=['AC-023', 'UX-001'])
        record['logs']['stdout']['sha256'] = '0' * 64
        result = runner.assess(case, record, raw, b'', 'a' * 64)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['teardown']['status'], 'UNKNOWN')
        self.assertIn('durable capture', result['reason'])

    def test_duplicate_json_and_extra_failure_marker_refuse_positive(self):
        for raw in (success_output() + b'{"case":"x","status":"PASS","status":"FAIL"}\n',
                    success_output() + b'{"case":"late","status":"FAIL"}\n'):
            result = runner.assess(sample_case(), captured(raw), raw, b'', 'a' * 64)
            self.assertEqual(result['status'], 'FAIL')

    def test_stops_dispatch_after_failed_or_blocked_child_preserving_denominator(self):
        for status in ('FAIL', 'BLOCKED'):
            called = []
            def one(case):
                called.append(case['id'])
                return {'id': case['id'], 'criterion': case['criterion'], 'status': status}
            result = runner.drive([sample_case(), {'id': 'cancel', 'criterion': 'AC-010'}], one)
            self.assertEqual(called, ['admission'])
            self.assertEqual([row['status'] for row in result], [status, 'NOT RUN'])
            self.assertIn('preceding', result[1]['reason'])

    def test_required_bounds_refuse_unbounded_or_swappable_paths(self):
        for filesystem, options, byte_count, inodes in (
            ('ext4', {'noswap'}, 6_000_000_000, 200_000),
            ('tmpfs', set(), 6_000_000_000, 200_000),
            ('tmpfs', {'noswap'}, 12_000_000_001, 200_000),
            ('tmpfs', {'noswap'}, 6_000_000_000, 0),
            ('tmpfs', {'noswap'}, 6_000_000_000, 200_001),
        ):
            with self.subTest(filesystem=filesystem, options=options, bytes=byte_count, inodes=inodes):
                with self.assertRaises(ValueError):
                    runner.validate_bounds(filesystem, options, byte_count, inodes)
        self.assertIsNone(runner.validate_bounds('tmpfs', {'noswap'}, 6_000_000_000, 200_000))

    def test_missing_inputs_report_all_criteria_blocked_and_not_run(self):
        report = runner.summarize(contract(), [], blocker='set explicit operator paths')
        self.assertEqual((report['status'], report['exit_code']), ('BLOCKED', 78))
        self.assertEqual(len(report['criteria']), 24)
        self.assertTrue(all(row['scoped_positive']['status'] == 'NOT RUN' for row in report['criteria']))

    def test_cli_missing_inputs_returns78_full_locked_denominator_without_native_imports(self):
        env = dict(os.environ)
        for name in ('HEARTHRUN_BIN_DIR', 'HEARTHRUN_DOCTOR', 'HEARTHRUN_FIXTURE',
                     'HEARTHRUN_JOBS', 'HEARTHRUN_ACCEPTANCE_WORK', 'TMPDIR'):
            env.pop(name, None)
        child = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/acceptance.py')],
                               cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(child.returncode, 78, child.stderr)
        report = json.loads(child.stdout)
        self.assertEqual(report['required_criteria'], 24)
        self.assertEqual(report['completed_criteria'], 0)
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertEqual(report['runner_teardown']['status'], 'NOT RUN')
        self.assertTrue(all(row['scoped_positive']['status'] == 'NOT RUN' for row in report['criteria']))


if __name__ == '__main__':
    unittest.main()
