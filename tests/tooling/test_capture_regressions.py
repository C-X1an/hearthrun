import errno
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import capture


class CaptureRegressions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.out = self.root / 'evidence'
        self.command = [sys.executable, '-c', 'print("captured")']

    def run_capture(self, command=None, timeout=3):
        return capture.capture(command or self.command, self.source, self.out,
                               'capture-regression', [], timeout)

    def refuse_without_launch(self):
        with mock.patch.object(capture.subprocess, 'Popen') as launch:
            with self.assertRaises((OSError, ValueError)):
                self.run_capture()
            launch.assert_not_called()

    def private_out(self):
        self.out.mkdir(mode=0o700)

    def assert_reaped(self, process):
        self.assertIsNotNone(process.returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
        with self.assertRaises(ProcessLookupError):
            os.kill(process.pid, 0)

    def test_nonfinite_timeout_refuses_before_spawn(self):
        for timeout in [float('nan'), float('inf'), float('-inf'), 0, -1]:
            with self.subTest(timeout=timeout):
                with mock.patch.object(capture.subprocess, 'Popen') as launch:
                    with self.assertRaises(ValueError):
                        self.run_capture(timeout=timeout)
                    launch.assert_not_called()

    def test_insecure_existing_out_refuses_before_spawn(self):
        self.private_out()
        self.out.chmod(0o755)
        self.refuse_without_launch()
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o755)

    def test_insecure_existing_raw_refuses_before_spawn(self):
        self.private_out()
        raw = self.out / 'raw'
        raw.mkdir(mode=0o700)
        # The caller may run the whole check suite under umask 077.
        raw.chmod(0o755)
        self.assertEqual(stat.S_IMODE(raw.stat().st_mode), 0o755)
        self.refuse_without_launch()

    def test_symlink_out_refuses_before_spawn(self):
        target = self.root / 'other'
        target.mkdir(mode=0o700)
        self.out.symlink_to(target, target_is_directory=True)
        self.refuse_without_launch()
        self.assertEqual(list(target.iterdir()), [])

    def test_symlink_ancestor_refuses_before_spawn(self):
        target = self.root / 'other'
        target.mkdir(mode=0o700)
        alias = self.root / 'alias'
        alias.symlink_to(target, target_is_directory=True)
        self.out = alias / 'evidence'
        self.refuse_without_launch()
        self.assertFalse((target / 'evidence').exists())

    def test_symlink_raw_refuses_before_spawn(self):
        self.private_out()
        target = self.root / 'other'
        target.mkdir(mode=0o700)
        (self.out / 'raw').symlink_to(target, target_is_directory=True)
        self.refuse_without_launch()

    def test_existing_manifest_requires_private_regular_single_link(self):
        self.private_out()
        manifest = self.out / 'run_manifest.jsonl'
        for kind in ('permissive', 'hardlink', 'symlink', 'directory', 'fifo'):
            with self.subTest(kind=kind):
                target = self.root / ('target-' + kind)
                if kind == 'directory':
                    manifest.mkdir(mode=0o700)
                elif kind == 'fifo':
                    os.mkfifo(manifest, mode=0o600)
                elif kind in ('symlink', 'hardlink'):
                    target.write_text('unchanged')
                    target.chmod(0o600)
                    if kind == 'symlink':
                        manifest.symlink_to(target)
                    else:
                        os.link(target, manifest)
                else:
                    manifest.write_text('unchanged')
                    manifest.chmod(0o644)
                self.refuse_without_launch()
                if kind == 'directory':
                    manifest.rmdir()
                else:
                    manifest.unlink()
                if target.exists():
                    self.assertEqual(target.read_text(), 'unchanged')

    def test_wrong_directory_or_manifest_owner_refuses(self):
        # Inject ownership metadata only; actual child execution is always denied.
        original_fstat = capture.os.fstat
        for resource in ('directory', 'manifest'):
            with self.subTest(resource=resource):
                def wrong_owner(fd):
                    info = original_fstat(fd)
                    selected = stat.S_ISDIR(info.st_mode) if resource == 'directory' else stat.S_ISREG(info.st_mode)
                    if not selected:
                        return info
                    values = list(info)
                    values[4] = os.geteuid() + 1
                    return os.stat_result(values)
                with mock.patch.object(capture.os, 'fstat', side_effect=wrong_owner):
                    self.refuse_without_launch()

    def test_log_open_failure_never_launches_or_mislabels_executable(self):
        original_open = capture.os.open
        def fail_stderr(path, flags, *args, **kwargs):
            if str(path).endswith('.stderr'):
                raise FileNotFoundError(errno.ENOENT, 'injected log destination failure', str(path))
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(capture.os, 'open', side_effect=fail_stderr):
            with mock.patch.object(capture.subprocess, 'Popen') as launch:
                with self.assertRaisesRegex(FileNotFoundError, 'log destination'):
                    self.run_capture()
                launch.assert_not_called()

    def test_all_resources_validated_and_open_before_launch(self):
        original_popen = capture.subprocess.Popen
        def inspect_then_launch(*args, **kwargs):
            files = [self.out / 'run_manifest.jsonl', *self.out.glob('*.json'), *self.out.glob('raw/*')]
            self.assertEqual(len(files), 4)
            for path in files:
                info = path.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                self.assertEqual(info.st_nlink, 1)
                self.assertEqual(info.st_uid, os.geteuid())
            for path in (self.out, self.out / 'raw'):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            return original_popen(*args, **kwargs)
        # Avoid intercepting git's independent provenance subprocesses.
        with mock.patch.object(capture, 'git_value', return_value=None):
            with mock.patch.object(capture.subprocess, 'Popen', side_effect=inspect_then_launch):
                self.assertEqual(self.run_capture()['status'], 'PASS')

    def test_existing_private_manifest_appends_preserving_records(self):
        first = self.run_capture()
        second = self.run_capture()
        rows = [json.loads(line) for line in (self.out / 'run_manifest.jsonl').read_text().splitlines()]
        self.assertEqual([row['run_id'] for row in rows], [first['run_id'], second['run_id']])

    def test_log_write_error_kills_and_reaps_running_child(self):
        original_popen = capture.subprocess.Popen
        original_write = capture.os.write
        processes = []
        log_fds = set()
        original_file = capture._evidence_file
        def remember_file(directory, name, **kwargs):
            fd = original_file(directory, name, **kwargs)
            if name.endswith('.stdout'):
                log_fds.add(fd)
            return fd
        def launch(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process
        def fail_log(fd, data):
            if fd in log_fds:
                raise FileNotFoundError(errno.ENOENT, 'injected log write failure')
            return original_write(fd, data)
        command = [sys.executable, '-c', 'import time; print("ready", flush=True); time.sleep(60)']
        with mock.patch.object(capture, 'git_value', return_value=None), \
                mock.patch.object(capture, '_evidence_file', side_effect=remember_file), \
                mock.patch.object(capture.subprocess, 'Popen', side_effect=launch), \
                mock.patch.object(capture.os, 'write', side_effect=fail_log):
            record = self.run_capture(command)
        self.assertEqual((record['status'], record['exit_code']), ('FAIL', 74))
        self.assertNotIn('Executable unavailable', record.get('error', ''))
        self.assertIn('Output capture failed', record['log_errors'][0])
        self.assertEqual(len(processes), 1)
        self.assertEqual(processes[0].returncode, -signal.SIGKILL)
        self.assert_reaped(processes[0])
        self.assertFalse(record['logs']['stdout']['eof_observed'])
        self.assertIsNone(record['logs']['stdout']['full_stream_sha256'])

    def test_unexpected_exception_still_kills_and_reaps_child(self):
        original_popen = capture.subprocess.Popen
        processes = []
        def launch(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process
        with mock.patch.object(capture, 'git_value', return_value=None), \
                mock.patch.object(capture.subprocess, 'Popen', side_effect=launch), \
                mock.patch.object(capture.os, 'set_blocking', side_effect=RuntimeError('injected setup failure')):
            with self.assertRaisesRegex(RuntimeError, 'setup failure'):
                self.run_capture([sys.executable, '-c', 'import time; time.sleep(60)'])
        self.assertEqual(len(processes), 1)
        self.assert_reaped(processes[0])

    def test_partial_log_write_error_hashes_only_retained_bytes(self):
        original_write = capture.os.write
        original_file = capture._evidence_file
        log_fds = set()
        writes = 0
        def remember_file(directory, name, **kwargs):
            fd = original_file(directory, name, **kwargs)
            if name.endswith('.stdout'):
                log_fds.add(fd)
            return fd
        def partial_then_fail(fd, data):
            nonlocal writes
            if fd in log_fds:
                writes += 1
                if writes == 1:
                    return original_write(fd, data[:2])
                raise OSError(errno.ENOSPC, 'injected partial write failure')
            return original_write(fd, data)
        with mock.patch.object(capture, '_evidence_file', side_effect=remember_file), \
                mock.patch.object(capture.os, 'write', side_effect=partial_then_fail):
            record = self.run_capture()
        self.assertEqual((record['status'], record['exit_code']), ('FAIL', 74))
        log = record['logs']['stdout']
        data = (self.out / log['path']).read_bytes()
        self.assertEqual(data, b'ca')
        self.assertEqual(log['retained_bytes'], 2)
        self.assertEqual(log['sha256'], hashlib.sha256(data).hexdigest())

    def test_log_fsync_failure_records_failure_after_reaping(self):
        original_fsync = capture.os.fsync
        original_popen = capture.subprocess.Popen
        original_file = capture._evidence_file
        log_fds = set()
        processes = []
        def remember_file(directory, name, **kwargs):
            fd = original_file(directory, name, **kwargs)
            if name.endswith('.stderr'):
                log_fds.add(fd)
            return fd
        def launch(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process
        def fail_sync(fd):
            if fd in log_fds:
                self.assert_reaped(processes[0])
                raise OSError(errno.ENOSPC, 'injected log durability failure')
            return original_fsync(fd)
        with mock.patch.object(capture, 'git_value', return_value=None), \
                mock.patch.object(capture, '_evidence_file', side_effect=remember_file), \
                mock.patch.object(capture.subprocess, 'Popen', side_effect=launch), \
                mock.patch.object(capture.os, 'fsync', side_effect=fail_sync):
            record = self.run_capture()
        self.assertEqual((record['status'], record['exit_code']), ('FAIL', 74))
        self.assertIn('stderr log durability failed', record['log_errors'][0])
        self.assert_reaped(processes[0])

    def test_record_persistence_error_is_explicit_after_child_reaped(self):
        original_write = capture.os.write
        original_popen = capture.subprocess.Popen
        processes = []
        def launch(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process
        def fail_record(fd, data):
            if data.startswith(b'{\n'):
                self.assert_reaped(processes[0])
                raise OSError(errno.ENOSPC, 'injected record persistence failure')
            return original_write(fd, data)
        with mock.patch.object(capture, 'git_value', return_value=None), \
                mock.patch.object(capture.subprocess, 'Popen', side_effect=launch), \
                mock.patch.object(capture.os, 'write', side_effect=fail_record):
            with self.assertRaisesRegex(OSError, 'record persistence'):
                self.run_capture()
        self.assert_reaped(processes[0])

    def test_log_hashes_match_actual_bytes(self):
        record = self.run_capture()
        for log in record['logs'].values():
            data = (self.out / log['path']).read_bytes()
            self.assertEqual(log['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(log['retained_bytes'], len(data))
            self.assertTrue(log['eof_observed'])


class ReapedLeaderRegressions(unittest.TestCase):
    def test_reaped_leader_group_is_never_signalled(self):
        process = subprocess.Popen([sys.executable, '-c', 'pass'], start_new_session=True)
        process.wait(timeout=5)
        with mock.patch.object(capture.os, 'killpg') as kill_group:
            capture._stop_and_reap(process, kill_group=True)
        kill_group.assert_not_called()


class SourceFingerprintRegressions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()

    def digest(self):
        return capture.source_digest(self.source)

    def test_executable_mode_changes_digest(self):
        path = self.source / 'tool'
        path.write_text('same contents')
        path.chmod(0o600)
        before = self.digest()
        path.chmod(0o700)
        self.assertNotEqual(before, self.digest())

    def test_symlink_creation_target_change_and_removal_change_digest(self):
        before = self.digest()
        link = self.source / 'link'
        link.symlink_to('missing-a')
        linked = self.digest()
        self.assertNotEqual(before, linked)
        link.unlink()
        link.symlink_to('missing-b')
        self.assertNotEqual(linked, self.digest())
        link.unlink()
        self.assertEqual(before, self.digest())

    def test_symlink_target_contents_are_not_followed(self):
        external = self.root / 'external'
        external.mkdir()
        (external / 'data').write_text('before')
        (self.source / 'link').symlink_to(external, target_is_directory=True)
        before = self.digest()
        (external / 'data').write_text('changed contents')
        self.assertEqual(before, self.digest())
        (self.source / 'loop').symlink_to(self.source, target_is_directory=True)
        self.assertNotEqual(before, self.digest())

    def test_file_and_symlink_with_same_contents_have_different_digest(self):
        external = self.root / 'external'
        external.write_text('same')
        path = self.source / 'data'
        path.write_text('same')
        before = self.digest()
        path.unlink()
        path.symlink_to(external)
        self.assertNotEqual(before, self.digest())

    def test_empty_directory_and_directory_mode_are_fingerprinted(self):
        before = self.digest()
        directory = self.source / 'empty'
        directory.mkdir(mode=0o700)
        created = self.digest()
        self.assertNotEqual(before, created)
        directory.chmod(0o755)
        self.assertNotEqual(created, self.digest())

    def test_special_entry_refuses_instead_of_ignoring_or_blocking(self):
        os.mkfifo(self.source / 'fifo', mode=0o600)
        with self.assertRaisesRegex(ValueError, 'Unsupported source entry type'):
            self.digest()


if __name__ == '__main__':
    unittest.main()
