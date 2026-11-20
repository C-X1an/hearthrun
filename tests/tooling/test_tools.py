import contextlib
import io
import json
import math
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import benchmark_summary
import capture
import check_acceptance
import report


class ContractTests(unittest.TestCase):
    def test_locked_acceptance(self):
        self.assertEqual(check_acceptance.validate(ROOT)['criteria'], 24)

    def test_tamper_detected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); (p / 'spec').mkdir()
            (p / 'spec/acceptance.json').write_bytes((ROOT / 'spec/acceptance.json').read_bytes() + b' ')
            (p / 'spec/acceptance.sha256').write_bytes((ROOT / 'spec/acceptance.sha256').read_bytes())
            with self.assertRaises(ValueError): check_acceptance.validate(p)

    def test_real_report_requires_evidence(self):
        with self.assertRaises(ValueError): report.render({'status': 'PASS'})

    def test_report_escapes_untrusted_html(self):
        text = report.render({'x': '<script>alert(1)</script>'}, True)
        self.assertNotIn('<script>', text)
        self.assertIn('&lt;script&gt;', text)
        self.assertIn('NOT A LIVE EXECUTION', text)

    def test_real_report_label(self):
        text = report.render({'evidence_run_id': 'real-test-id', 'status': 'FAIL'})
        self.assertIn('RECORDED EXECUTION', text)
        self.assertNotIn('NOT A LIVE EXECUTION', text)


class BenchmarkTests(unittest.TestCase):
    def rows(self):
        return [{'run_id': str(i), 'environment_id': 'test-fixture', 'policy_digest': 'test-policy',
                 'duration_ms': float(i), 'status': 'PASS'} for i in range(1, 101)]
    def test_nearest_rank(self):
        r = benchmark_summary.summarize(self.rows())
        self.assertEqual((r['p50_ms'], r['p95_ms'], r['p99_ms']), (50, 95, 99))
    def test_failures_counted(self):
        r = self.rows(); r[-1]['status'] = 'FAIL'
        x = benchmark_summary.summarize(r)
        self.assertEqual(x['samples_failed_or_blocked'], 1)
        self.assertEqual(x['samples_total'], 100)
        self.assertEqual(x['samples_success'], 99)
    def test_all_failed_has_no_latency(self):
        r = self.rows()
        for x in r: x['status'] = 'BLOCKED'
        self.assertIsNone(benchmark_summary.summarize(r)['p95_ms'])
    def test_mixed_environment_rejected(self):
        r = self.rows(); r[0]['environment_id'] = 'other'
        with self.assertRaises(ValueError): benchmark_summary.summarize(r)
    def test_duplicate_rejected(self):
        r = self.rows(); r.append(r[0])
        with self.assertRaises(ValueError): benchmark_summary.summarize(r)
    def test_nonfinite_rejected(self):
        for v in [float('nan'), float('inf'), -1, True]:
            r = self.rows(); r[0]['duration_ms'] = v
            with self.assertRaises(ValueError): benchmark_summary.summarize(r)
    def test_empty_rejected(self):
        with self.assertRaises(ValueError): benchmark_summary.summarize([])
    def test_unknown_status_rejected(self):
        r = self.rows(); r[0]['status'] = 'SKIPPED_AS_PASS'
        with self.assertRaises(ValueError): benchmark_summary.summarize(r)
    def test_missing_fields_rejected(self):
        with self.assertRaises(ValueError): benchmark_summary.summarize([{'run_id': '1'}])


class CaptureTests(unittest.TestCase):
    def run_command(self, command, timeout=3):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root / 'source').mkdir()
            r = capture.capture(command, root / 'source', root / 'evidence', 'tooling-test', [], timeout)
            manifest = (root / 'evidence/run_manifest.jsonl').read_text()
            self.assertEqual(json.loads(manifest)['run_id'], r['run_id'])
            for log in r['logs'].values():
                self.assertTrue((root / 'evidence' / log['path']).is_file())
            return r
    def test_success_real_exit(self):
        r = self.run_command([sys.executable, '-c', 'print("ok")'])
        self.assertEqual((r['status'], r['exit_code']), ('PASS', 0))
        self.assertEqual(r['logs']['stdout']['total_bytes'], 3)
    def test_failure_real_exit(self):
        r = self.run_command([sys.executable, '-c', 'raise SystemExit(7)'])
        self.assertEqual((r['status'], r['exit_code']), ('FAIL', 7))
    def test_missing_executable_blocked(self):
        r = self.run_command(['/nonexistent/hearthrun-tool'])
        self.assertEqual((r['status'], r['exit_code']), ('BLOCKED', 78))
    def test_timeout_failure(self):
        r = self.run_command([sys.executable, '-c', 'import time; time.sleep(3)'], .05)
        self.assertEqual((r['status'], r['exit_code']), ('FAIL', 124))
        self.assertTrue(r['timed_out'])
    def test_bounded_log_drain(self):
        r = self.run_command([sys.executable, '-c', 'import sys; sys.stdout.write("a" * 3000000)'])
        self.assertTrue(r['logs']['stdout']['truncated'])
        self.assertEqual(r['logs']['stdout']['retained_bytes'], capture.LOG_LIMIT)
        self.assertEqual(r['logs']['stdout']['total_bytes'], 3_000_000)
    def test_no_shell_expansion(self):
        r = self.run_command([sys.executable, '-c', 'import sys; print(sys.argv[1])', '$(echo injected)'])
        self.assertEqual(r['logs']['stdout']['total_bytes'], len('$(echo injected)\n'))
    def test_invalid_timeout(self):
        with self.assertRaises(ValueError): self.run_command(['echo', 'x'], 0)


if __name__ == '__main__':
    unittest.main()
