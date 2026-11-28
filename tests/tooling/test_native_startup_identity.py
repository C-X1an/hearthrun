"""Owned local inert Unix sockets plus synthetic child/clock scheduling; no native guest."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PRODUCT = Path(__file__).resolve().parents[2]


class StartupIdentity(unittest.TestCase):
    def setUp(self):
        source = PRODUCT / "tests/e2e/native.py"
        spec = importlib.util.spec_from_file_location("startup_native", source)
        self.n = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.n)
        self.context = tempfile.TemporaryDirectory(prefix="native-startup-identity-")
        self.addCleanup(self.context.cleanup)
        self.root = Path(self.context.name)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.directory = os.open(self.state, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.directory)
        self.anchor = f"/proc/self/fd/{self.directory}/control.sock"
        self.sockets = []
        self.addCleanup(self.close_sockets)
        self.actions = []
        self.doctor_identities = []
        self.on_doctor = lambda: None
        self.time = 100.0
        harness = object.__new__(self.n.Harness)
        harness.state, harness.bin_dir = self.state, Path("/synthetic-bin")
        harness.cgroup_root, harness.doctor = Path("/unused-cgroup"), Path("/unused-doctor")
        harness.deadline = self.time + 0.5
        harness.children, harness.server = [], None
        harness.command = self.doctor
        harness.read_instance = lambda: "synthetic-instance"
        self.h = harness
        self.child = SimpleNamespace(name="server-01", proc=SimpleNamespace(returncode=None))
        self.child.proc.poll = lambda child=self.child: child.proc.returncode
        self.child.poll = self.child.proc.poll
        self.child.pump = lambda: None

    def close_sockets(self):
        for item in self.sockets:
            item.close()

    def bind(self, *, mode=0o600, listen=True):
        item = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sockets.append(item)
        item.bind(self.anchor)
        os.chmod("control.sock", mode, dir_fd=self.directory)
        if listen:
            item.listen(8)
        self.current = item
        info = os.stat("control.sock", dir_fd=self.directory, follow_symlinks=False)
        return info.st_dev, info.st_ino

    def unlink(self):
        os.unlink("control.sock", dir_fd=self.directory)

    def replace(self, **kwargs):
        self.unlink()
        return self.bind(**kwargs)

    def sleep(self, duration):
        self.time += duration
        if self.actions:
            self.actions.pop(0)()

    def doctor(self, argv, timeout=25):
        info = os.stat("control.sock", dir_fd=self.directory, follow_symlinks=False)
        self.doctor_identities.append((info.st_dev, info.st_ino))
        self.on_doctor()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            try:
                client.connect(self.anchor)
            except ConnectionRefusedError:
                return 2, json.dumps({"v": 1, "ok": False, "error": {
                    "code": "IO_UNCERTAIN", "retryable": False,
                    "message": "cannot connect to owner-only supervisor: Connection refused (os error 111)"}}).encode(), b""
        accepted, _ = self.current.accept()
        accepted.close()
        return 0, b'{"v":1,"ok":true,"result":{"compatible":true}}', b""

    def start(self, on_spawn=lambda: None):
        def spawn(*args, **kwargs):
            on_spawn()
            return self.child
        with patch.object(self.n, "Process", spawn), \
             patch.object(self.n.time, "monotonic", lambda: self.time), \
             patch.object(self.n.time, "sleep", self.sleep):
            return self.h.start()

    def test_restart_never_probes_stale_generation_before_distinct_socket(self):
        stale = self.bind(listen=False)
        fresh = []
        self.actions = [lambda: fresh.append(self.replace())]
        self.start()
        self.assertNotEqual(fresh[0], stale)
        self.assertEqual(self.doctor_identities, [fresh[0]])

    def test_bind_chmod_listen_stages_use_one_fresh_generation(self):
        fresh = []
        self.actions = [lambda: fresh.append(self.bind(mode=0o700, listen=False)),
                        lambda: os.chmod("control.sock", 0o600, dir_fd=self.directory),
                        lambda: self.current.listen(8)]
        self.start()
        self.assertEqual(self.doctor_identities, [fresh[0], fresh[0]])

    def test_first_fresh_disappearance_is_fatal(self):
        self.actions = [lambda: self.bind(mode=0o700, listen=False), self.unlink]
        with self.assertRaisesRegex(self.n.Failure, "socket.*(disappeared|identity)"):
            self.start()
        self.assertEqual(self.doctor_identities, [])

    def test_first_fresh_replacement_is_fatal_even_before_chmod(self):
        self.actions = [lambda: self.bind(mode=0o700, listen=False), self.replace]
        with self.assertRaisesRegex(self.n.Failure, "socket.*identity"):
            self.start()
        self.assertEqual(self.doctor_identities, [])

    def test_replacement_during_doctor_is_fatal(self):
        self.actions = [self.bind]
        self.on_doctor = self.replace
        with self.assertRaisesRegex(self.n.Failure, "socket.*identity"):
            self.start()

    def test_directory_replacement_during_doctor_is_fatal(self):
        self.actions = [self.bind]
        def replace_directory():
            self.state.rename(self.root / "old-state")
            self.state.mkdir(mode=0o700)
        self.on_doctor = replace_directory
        with self.assertRaisesRegex(self.n.Failure, "directory.*identity"):
            self.start()

    def test_directory_symlink_during_readiness_is_fatal(self):
        def replace_directory():
            self.state.rename(self.root / "old-state")
            self.state.symlink_to(self.root / "old-state", target_is_directory=True)
        self.actions = [replace_directory]
        with self.assertRaises((self.n.Failure, OSError)):
            self.start()

    def test_stale_socket_must_be_owner0600_and_nofollow(self):
        self.bind(mode=0o700, listen=False)
        with self.assertRaisesRegex(self.n.Failure, "socket"):
            self.start()
        self.assertIsNone(self.h.server)

    def test_symlink_socket_is_not_treated_as_missing(self):
        (self.state / "control.sock").symlink_to("missing")
        with self.assertRaisesRegex(self.n.Failure, "socket"):
            self.start()
        self.assertIsNone(self.h.server)

    def test_actual_unauthorized_is_fatal_without_retry(self):
        self.actions = [self.bind]
        self.h.command = lambda *args, **kwargs: (2, b'{"v":1,"ok":false,"error":{"code":"UNAUTHORIZED","retryable":false,"message":"control socket name changed during connection"}}', b"")
        with self.assertRaises(self.n.Failure):
            self.start()

    def test_other_io_uncertainty_is_not_retried(self):
        self.actions = [self.bind]
        calls = []
        def other_io(*args, **kwargs):
            calls.append(1)
            return 2, b'{"v":1,"ok":false,"error":{"code":"IO_UNCERTAIN","retryable":false,"message":"cannot read response"}}', b""
        self.h.command = other_io
        with self.assertRaises(self.n.Failure):
            self.start()
        self.assertEqual(len(calls), 1)

    def test_same_owned_process_must_remain_live_after_doctor(self):
        self.actions = [self.bind]
        self.on_doctor = lambda: setattr(self.child.proc, "returncode", 1)
        with self.assertRaisesRegex(self.n.Failure, "supervisor"):
            self.start()

    def test_stale_generation_is_held_open_until_distinct_generation_ready(self):
        self.bind(listen=False)
        retained = []
        def replace_stale():
            old = os.stat("control.sock", dir_fd=self.directory, follow_symlinks=False)
            self.replace()
            for fd in Path("/proc/self/fd").iterdir():
                try:
                    info = os.fstat(int(fd.name))
                except OSError:
                    continue
                if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == (old.st_dev, old.st_ino):
                    retained.append(info.st_nlink)
        self.actions = [replace_stale]
        self.start()
        self.assertIn(0, retained)

    def test_stale_socket_without_replacement_expires_without_doctor(self):
        self.bind(listen=False)
        with self.assertRaisesRegex(self.n.Failure, "deadline"):
            self.start()
        self.assertEqual(self.doctor_identities, [])

    def test_readiness_cannot_return_after_existing_deadline(self):
        self.actions = [self.bind]
        self.h.read_instance = lambda: setattr(self, "time", self.time + 1)
        with self.assertRaisesRegex(self.n.Failure, "deadline"):
            self.start()

    def test_secured_socket_permission_regression_is_fatal(self):
        self.actions = [self.bind]
        self.on_doctor = lambda: os.chmod("control.sock", 0o700, dir_fd=self.directory)
        with self.assertRaisesRegex(self.n.Failure, "socket"):
            self.start()

    def test_directory_and_socket_descriptors_close_after_success_and_failure(self):
        def open_descriptors():
            result = set()
            for entry in Path("/proc/self/fd").iterdir():
                try:
                    info = os.fstat(int(entry.name))
                except OSError:
                    continue
                result.add((int(entry.name), info.st_dev, info.st_ino))
            return result
        self.bind(listen=False)
        self.actions = [self.replace]
        before = open_descriptors()
        self.start()
        # The synthetic server opened one new listening socket; only that
        # deliberately retained resource may have been added by the test.
        expected = self.current.fileno()
        after = open_descriptors()
        self.assertEqual({row for row in after - before if row[0] != expected}, set())
        self.child.proc.returncode = 0
        self.h.server = self.child
        self.child = SimpleNamespace(name="server-02", proc=SimpleNamespace(returncode=None))
        self.child.proc.poll = lambda child=self.child: child.proc.returncode
        self.child.poll = self.child.proc.poll
        self.actions = []
        before = open_descriptors()
        with self.assertRaisesRegex(self.n.Failure, "deadline"):
            self.start()
        self.assertEqual(open_descriptors(), before)

    def test_known_stale_unlinked_after_open_before_fstat_is_not_ready(self):
        self.bind(listen=False)
        guard = self.n._StartupSocket(self.state)
        self.addCleanup(guard.close)
        stale = os.fstat(guard.stale)
        real_fstat = os.fstat
        def retired_metadata(descriptor):
            info = real_fstat(descriptor)
            if (info.st_dev, info.st_ino) == (stale.st_dev, stale.st_ino):
                values = list(info)
                values[3] = 0  # stat_result.st_nlink: the opened stale A retired.
                return os.stat_result(values)
            return info
        checks = []
        check_directory = guard._check_directory
        def checked_directory():
            checks.append(1)
            check_directory()
        with patch.object(self.n.os, "fstat", retired_metadata), \
             patch.object(guard, "_check_directory", checked_directory):
            try:
                ready = guard.ready()
            except self.n.Failure as error:
                self.fail(f"known stale retirement incorrectly became fatal: {error}")
            self.assertFalse(ready)
        self.assertGreaterEqual(len(checks), 2)
        self.assertIsNone(guard.fresh)
        self.assertEqual(self.doctor_identities, [])

    def test_known_stale_metadata_before_new_named_generation_is_not_ready(self):
        self.bind(listen=False)
        guard = self.n._StartupSocket(self.state)
        self.addCleanup(guard.close)
        stale = os.fstat(guard.stale)
        values = list(stale)
        values[1] += 1  # A's sampled metadata, but B is now the named socket.
        named_b = os.stat_result(values)
        real_stat = os.stat
        def replaced_name(path, *args, **kwargs):
            if path == "control.sock" and kwargs.get("dir_fd") == guard.directory:
                return named_b
            return real_stat(path, *args, **kwargs)
        checks = []
        check_directory = guard._check_directory
        def checked_directory():
            checks.append(1)
            check_directory()
        with patch.object(self.n.os, "stat", replaced_name), \
             patch.object(guard, "_check_directory", checked_directory):
            try:
                ready = guard.ready()
            except self.n.Failure as error:
                self.fail(f"known stale replacement incorrectly became fatal: {error}")
            self.assertFalse(ready)
        self.assertGreaterEqual(len(checks), 2)
        self.assertIsNone(guard.fresh)
        self.assertEqual(self.doctor_identities, [])


if __name__ == "__main__":
    unittest.main()
