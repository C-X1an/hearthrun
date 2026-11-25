"""Focused B-06 regression for the durable exec-release window."""
import unittest
from types import SimpleNamespace

from retention import make_harness


class RunningWitnessTests(unittest.TestCase):
    def test_exec_released_before_running_has_no_live_witness(self):
        native = SimpleNamespace(Harness=object, TERMINAL={'SUCCEEDED', 'CANCELLED'})
        harness = make_harness(native)
        witness = harness.__new__(harness)
        witness.record = lambda _job: {'state': 'STARTING', 'launch_stage': 'EXEC_RELEASED',
                                       'started_monotonic_ns': None}
        witness.bound_record = lambda *_: None

        def check_before_commit(_job):
            self.fail('cgroup observation started before the RUNNING record was durable')

        witness.open_group = check_before_commit
        self.assertIsNone(witness.observe_live({'job_id': 'fixture'}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
