#!/usr/bin/env python3
"""Real Linux doctor regression checks; needs an operator-delegated jobs parent.

No mock cgroups or guest executables. Fault cases add a disposable seccomp
policy to a fresh wrapper process, then exec the exact same doctor binary.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager


class Filter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]


class Program(ctypes.Structure):
    _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]


def deny_syscall(number: int, executable: str, arguments: list[str]) -> None:
    # This filter adds one explicit ENOSYS to this process and its descendants.
    # It never changes host-wide policy. x86_64 syscall numbers are intentional.
    instructions = (Filter * 4)(Filter(0x20, 0, 0, 0),
                                Filter(0x15, 0, 1, number),
                                Filter(0x06, 0, 0, 0x50000 | errno.ENOSYS),
                                Filter(0x06, 0, 0, 0x7fff0000))
    program = Program(4, instructions)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError(ctypes.get_errno(), 'fault policy installation failed')
    os.execv(executable, [executable, *arguments])

@contextmanager
def owned_suite(parent: Path):
    """Keep even an interrupted doctor and all its workers under one owned subtree."""
    suite = Path(tempfile.mkdtemp(prefix='hearthrun-doctor-suite-', dir=parent))
    host = suite / 'host'
    jobs = suite / 'jobs'
    try:
        (suite / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        host.mkdir()
        jobs.mkdir()
        (jobs / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        yield host, jobs
    finally:
        (suite / 'cgroup.kill').write_text('1')
        deadline = time.monotonic() + 6
        while 'populated 0' not in (suite / 'cgroup.events').read_text().splitlines():
            if time.monotonic() >= deadline:
                raise RuntimeError(f'Owned doctor suite still populated: {suite.name}')
            time.sleep(0.01)
        for leaf in jobs.iterdir() if jobs.is_dir() else ():
            if leaf.is_dir():
                leaf.rmdir()
        if jobs.is_dir():
            jobs.rmdir()
        if host.is_dir():
            host.rmdir()
        suite.rmdir()


def stop_doctor(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.communicate(timeout=18)
    except subprocess.TimeoutExpired:
        # The enclosing test-only cgroup is the authority for descendant
        # cleanup. Here we only signal and reap our direct child.
        process.kill()
        process.wait(timeout=6)


def main() -> int:
    if len(sys.argv) >= 5 and sys.argv[1] == '--join-owned-host' and sys.argv[3] == '--':
        (Path(sys.argv[2]) / 'cgroup.procs').write_text(str(os.getpid()))
        os.execv(sys.argv[4], sys.argv[4:])
        raise AssertionError('exec returned')
    if len(sys.argv) >= 4 and sys.argv[1] == '--deny-syscall':
        deny_syscall(int(sys.argv[2]), sys.argv[3], sys.argv[4:])
        raise AssertionError('exec returned')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--doctor', required=True, type=Path)
    parser.add_argument('--cgroup-root', required=True, type=Path)
    args = parser.parse_args()
    doctor = str(args.doctor.resolve(strict=True))
    parent = args.cgroup_root.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='doctor-suite-', dir=os.environ['TMPDIR']) as scratch:
        with owned_suite(parent) as (host, root):
            return run_suite(doctor, host, root, Path(scratch))


def run_suite(doctor: str, host: Path, root: Path, tmp: Path) -> int:
    base_env = dict(os.environ, TMPDIR=str(tmp))
    before_groups = {p.name for p in root.iterdir() if p.is_dir()}
    before_scratch = {p.name for p in tmp.glob('hearthrun-doctor-*')}
    cases = 0
    entry = [sys.executable, str(Path(__file__).resolve()), '--join-owned-host', str(host), '--']

    def assert_clean() -> None:
        assert {p.name for p in root.iterdir() if p.is_dir()} == before_groups, 'disposable cgroup leaked'
        assert {p.name for p in tmp.glob('hearthrun-doctor-*')} == before_scratch, 'scratch leaked'

    def run(name: str, command: list[str], expected: int,
            failed_feature: str | None = None, env: dict | None = None) -> dict:
        nonlocal cases
        with subprocess.Popen(entry + command, env=base_env if env is None else env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True) as process:
            try:
                stdout, stderr = process.communicate(timeout=35)
            finally:
                stop_doctor(process)
        assert process.returncode == expected, (name, process.returncode, stdout, stderr)
        report = json.loads(stdout)
        assert report['schema_version'] == 2
        assert report['full_launch_policy_exercised'] is False
        assert report['compatible'] is (expected == 0), (name, report)
        assert report['status'] == ('PASS' if expected == 0 else 'BLOCKED')
        assert all(set(v) == {'passed', 'errno', 'detail'} for v in report['features'].values())
        if expected == 0:
            assert all(v['passed'] and v['errno'] == 0 for v in report['features'].values())
        if failed_feature:
            assert not report['features'][failed_feature]['passed'], (name, report)
            assert report['features'][failed_feature]['errno'] != 0
        assert report['features']['disposable_cleanup']['passed'], (name, report)
        assert_clean()
        cases += 1
        print(json.dumps({'case': name, 'exit_code': process.returncode,
                          'compatible': report['compatible'], 'failed_feature': failed_feature}))
        return report

    full = [doctor, '--cgroup-root', str(root)]
    run('operational_capabilities', full, 0)
    clean_env = base_env.copy()
    clean_env.pop('HEARTHRUN_CGROUP_ROOT', None)
    run('missing_delegation', [doctor], 78, 'delegated_cgroup_operations', clean_env)
    run('relative_delegation', [doctor, '--cgroup-root', 'relative'], 78, 'delegated_cgroup_operations')
    run('non_cgroup_directory', [doctor, '--cgroup-root', str(tmp)], 78, 'delegated_cgroup_operations')
    run('nonexistent_delegation', [doctor, '--cgroup-root', str(tmp / 'does-not-exist')], 78, 'delegated_cgroup_operations')
    run('unknown_argument', [doctor, '--unknown'], 78, 'operator_configuration')
    missing_tmp = base_env.copy()
    missing_tmp.pop('TMPDIR', None)
    run('missing_scratch_configuration', full, 78, 'disposable_scratch', missing_tmp)
    env_root = dict(base_env, HEARTHRUN_CGROUP_ROOT=str(root))
    run('operator_environment_delegation', [doctor], 0, env=env_root)
    for syscall, feature in [(272, 'namespaces_minimal_root'), (444, 'landlock_application_denial'),
                             (317, 'seccomp_arch_x32_default_deny'), (434, 'pidfd_signal_reap'),
                             (436, 'close_range'), (437, 'openat2_resolution')]:
        run('denied_syscall_' + str(syscall),
            [sys.executable, str(Path(__file__).resolve()), '--deny-syscall', str(syscall), *full],
            78, feature)
    # Wait until a real disposable cgroup exists, then interrupt the doctor.
    # Its outer process must kill its own leaf, reap adopted children and return
    # a structured refusal. It must not alter the parent or unrelated leaves.
    process = subprocess.Popen(entry + full, env=base_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if any(p.name not in before_groups and p.is_dir() for p in root.iterdir()):
                process.send_signal(signal.SIGTERM)
                break
            assert process.poll() is None, 'doctor finished before interruption condition'
            time.sleep(0.001)
        else:
            raise AssertionError('no disposable cgroup observed')
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 78, (process.returncode, stdout, stderr)
        report = json.loads(stdout)
        assert report['compatible'] is False
        assert report['features']['disposable_cleanup']['passed'], report
        assert_clean()
        cases += 1
        print(json.dumps({'case': 'interrupted_cgroup_probe', 'exit_code': 78, 'compatible': False}))
    finally:
        stop_doctor(process)
        process.stdout.close()
        process.stderr.close()
    print(json.dumps({'status': 'PASS', 'cases': cases,
                      'scope': 'operational doctor and fail-closed fault checks; not launch acceptance'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
