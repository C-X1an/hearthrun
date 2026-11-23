#!/usr/bin/env python3
"""Submit a fixed approved action while an operational host check refuses."""
from __future__ import annotations

import argparse
from pathlib import Path
import secrets
import signal
import sys
import time

from resources import native

FEATURES = (
    (272, 'namespaces_minimal_root'),
    (444, 'landlock_application_denial'),
    (317, 'seccomp_arch_x32_default_deny'),
    (434, 'pidfd_signal_reap'),
    (436, 'close_range'),
    (437, 'openat2_resolution'),
)


class HostSuite(native.Harness):
    def start_refusing(self, name: str, doctor: Path, jobs: str, failed_feature: str) -> None:
        self.server = native.Process(self, name, [str(self.bin_dir / 'hearthrun-supervisor'), 'serve',
                                                   str(self.state), jobs, str(self.bin_dir / 'hearthrun-launcher'), str(doctor)])
        self.children.append(self.server)
        deadline = time.monotonic() + 30
        while not (self.state / 'control.sock').is_socket():
            native.require(self.server.poll() is None and time.monotonic() < deadline,
                           'restricted supervisor failed before providing its operational report')
            time.sleep(0.01)
        code, stdout, _ = self.command([str(self.bin_dir / 'hearthrun'), '--state', str(self.state), 'doctor'])
        report = native.strict_json(stdout)
        native.require(code == 78 and report.get('ok') is True, 'restricted doctor lacked its unsupported-host exit')
        result = report['result']
        feature = result['features'][failed_feature]
        native.require(result.get('compatible') is False and result.get('status') == 'BLOCKED'
                       and feature['passed'] is False and feature['errno'] != 0 and feature['detail'],
                       'restricted host did not name the missing capability')

    def refusal(self, name: str, doctor: Path, jobs: str, feature: str) -> None:
        self.start_refusing(name, doctor, jobs, feature)
        staged = self.cli('stage', f'data.ndjson={self.work / "data.ndjson"}')['stage_id']
        error = self.cli('submit', secrets.token_hex(16), 'example', staged, '10000', '--', 'summary',
                         ok=False, error='UNSUPPORTED_HOST')
        metrics = self.cli('metrics')
        native.require(metrics['active'] == 0 and metrics['queued'] == 0 and metrics['admission_open'] is False
                       and not self.inventory() and not self.group_names()
                       and not any((self.state / 'results').iterdir()),
                       'unsupported host changed the journal, result store or cgroup inventory')
        assert self.server is not None
        self.server.proc.terminate()
        native.require(self.server.wait(16) == 0, 'restricted supervisor did not shut down cleanly')
        native.emit(name, 'PASS', error_code=error['code'], failed_feature=feature, admitted_jobs=0, committed_results=0)

    def exercise(self) -> None:
        code, stdout, _ = self.command([str(self.bin_dir / 'hearthrun-supervisor'), 'install-profile',
                                       str(self.state), 'example', str(self.fixture)])
        native.require(code == 0 and native.strict_json(stdout).get('profile_id') == 'example',
                       'approved fixture installation failed')
        native.write_synthetic(self.work / 'data.ndjson', b'{"value":17}\n')
        self.start()
        active = self.cli('metrics')
        native.require(active.get('admission_open') is True, 'compatible control did not open admission')
        assert self.server is not None
        self.server.proc.terminate()
        native.require(self.server.wait(16) == 0, 'compatible control did not shut down cleanly')
        self.refusal('no_delegation', self.doctor, '-', 'delegated_cgroup_operations')

        helper = Path(__file__).resolve().parents[2] / 'tools' / 'test_doctor.py'
        interpreter = Path(sys.executable).resolve(strict=True)
        for number, feature in FEATURES:
            wrapper = self.work / f'doctor-{number}'
            adapter = (f'#!{interpreter}\nimport os\nimport sys\n'
                       f'os.execv(sys.executable, [sys.executable, {str(helper)!r}, "--deny-syscall",'
                       f' {str(number)!r}, {str(self.doctor)!r}, *sys.argv[1:]])\n')
            native.write_synthetic(wrapper, adapter.encode())
            wrapper.chmod(0o700)
            self.refusal(f'denied_{number}', wrapper, str(self.cgroup_root), feature)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bin-dir', 'doctor', 'fixture', 'cgroup-root', 'work'):
        parser.add_argument(f'--{name}', required=True)
    args = parser.parse_args()

    def terminate(signum, _frame):
        signal.signal(signum, signal.SIG_DFL)
        raise native.Failure('termination requested during scoped host verification')

    signal.signal(signal.SIGTERM, terminate)
    suite = HostSuite(args)
    status = 1
    try:
        suite.preflight()
        suite.exercise()
        status = 0
    except native.Blocked as error:
        native.emit('host_refusal', 'BLOCKED', reason=str(error)[:1024])
        status = 78
    except Exception as error:
        native.emit('host_refusal', 'FAIL', reason=f'{type(error).__name__}: {error}'[:1024])
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
