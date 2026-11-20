#!/usr/bin/env python3
"""Capture trusted verification commands. Not an untrusted-code sandbox.

No shell evaluation. Secrets must not be put in argv, environment output or test
fixtures. Logs are owner-only; publication requires a separate content audit.
Process-group cleanup is best effort, not native descendant containment.
"""
from __future__ import annotations
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
import platform
import selectors
import signal
import stat
import subprocess
import time
import uuid
from pathlib import Path

LOG_LIMIT = 2 * 1024 * 1024
EXCLUDED = {'.git', '.work', 'target', 'verification', '__pycache__'}


def git_value(root: Path, args: list[str]) -> str | None:
    try:
        result = subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                                text=True, timeout=5, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def source_digest(root: Path) -> str:
    """Fingerprint names, entry types, permission bits and contents without following links."""
    digest = hashlib.sha256(b'hearthrun-source-v2\x00')

    def field(value: bytes) -> None:
        digest.update(len(value).to_bytes(8, 'big'))
        digest.update(value)

    def visit(directory: int, prefix: bytes) -> None:
        with os.scandir(directory) as entries:
            names = sorted(entry.name for entry in entries if entry.name not in EXCLUDED)
        for name in names:
            rel = prefix + os.fsencode(name)
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            field(rel)
            field(str(stat.S_IMODE(info.st_mode)).encode())
            if stat.S_ISLNK(info.st_mode):
                field(b'symlink')
                field(os.fsencode(os.readlink(name, dir_fd=directory)))
            elif stat.S_ISDIR(info.st_mode):
                field(b'directory')
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=directory)
                try:
                    opened = os.fstat(fd)
                    if (opened.st_dev, opened.st_ino, opened.st_mode) != (info.st_dev, info.st_ino, info.st_mode):
                        raise ValueError(f'Source entry changed during fingerprint: {rel!r}')
                    visit(fd, rel + b'/')
                finally:
                    os.close(fd)
            elif stat.S_ISREG(info.st_mode):
                field(b'file')
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
                try:
                    opened = os.fstat(fd)
                    if (not stat.S_ISREG(opened.st_mode)
                            or (opened.st_dev, opened.st_ino, opened.st_mode) != (info.st_dev, info.st_ino, info.st_mode)):
                        raise ValueError(f'Source entry changed during fingerprint: {rel!r}')
                    content = hashlib.sha256()
                    while chunk := os.read(fd, 65536):
                        content.update(chunk)
                    field(content.digest())
                finally:
                    os.close(fd)
            else:
                raise ValueError(f'Unsupported source entry type: {rel!r}')

    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        visit(fd, b'')
    finally:
        os.close(fd)
    return digest.hexdigest()


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _private_metadata(fd: int, directory: bool) -> None:
    info = os.fstat(fd)
    correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not correct_type or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or (not directory and info.st_nlink != 1)):
        raise ValueError('Evidence resources must be owned, owner-only directories or single-link regular files')


def _directory(path: Path) -> int:
    """Walk with directory descriptors so no evidence-path component follows a symlink."""
    absolute = Path(os.path.abspath(path))
    fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in absolute.parts[1:]:
            try:
                os.mkdir(name, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        _private_metadata(fd, directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _evidence_file(directory: int, name: str, *, append: bool = False) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= os.O_APPEND if append else os.O_EXCL
    fd = os.open(name, flags, 0o600, dir_fd=directory)
    try:
        _private_metadata(fd, directory=False)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write_all(fd: int, data: bytes) -> None:
    while data:
        written = os.write(fd, data)
        if written <= 0:
            raise OSError('Evidence write made no progress')
        data = data[written:]


def _stop_and_reap(proc: subprocess.Popen, kill_group: bool) -> None:
    try:
        # poll() returning None leaves the leader unreaped; even an intervening
        # exit pins its PID until wait(). Never signal a numeric process group
        # after reaping: an escaped descendant may hold a pipe while that old
        # group no longer exists and its numeric ID can be reused.
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    finally:
        # Even a cleanup error must not leave the direct child running or unreaped.
        if proc.poll() is None:
            proc.kill()
        proc.wait()


def capture(command: list[str], cwd: Path, out: Path, category: str,
            requirements: list[str], timeout: float = 120) -> dict:
    if not command or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Command and finite positive timeout required')
    cwd = cwd.resolve(strict=True)
    run_id = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:12]
    # All persistence destinations are opened and validated before a trusted command runs.
    # Held descriptors prevent later pathname substitution from redirecting our writes.
    with contextlib.ExitStack() as resources:
        out_fd = _directory(out)
        resources.callback(os.close, out_fd)
        try:
            os.mkdir('raw', mode=0o700, dir_fd=out_fd)
        except FileExistsError:
            pass
        raw_fd = os.open('raw', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=out_fd)
        resources.callback(os.close, raw_fd)
        _private_metadata(raw_fd, directory=True)
        manifest_fd = _evidence_file(out_fd, 'run_manifest.jsonl', append=True)
        resources.callback(os.close, manifest_fd)
        record_fd = _evidence_file(out_fd, f'{run_id}.json')
        resources.callback(os.close, record_fd)
        streams = {}
        for label in ('stdout', 'stderr'):
            name = f'{run_id}.{label}'
            fd = _evidence_file(raw_fd, name)
            resources.callback(os.close, fd)
            streams[label] = {'fd': fd, 'full': hashlib.sha256(), 'kept': hashlib.sha256(),
                              'total': 0, 'written': 0, 'path': f'raw/{name}', 'eof': False}
        before = source_digest(cwd)
        record = {'schema_version': 1, 'run_id': run_id, 'command': command,
                  'working_directory': '.', 'git_commit': git_value(cwd, ['rev-parse', 'HEAD']),
                  'git_dirty': bool(git_value(cwd, ['status', '--porcelain'])),
                  'source_sha256_before': before, 'start_utc': utc(), 'category': category,
                  'requirements': requirements, 'environment': {'system': platform.system(),
                  'machine': platform.machine(), 'kernel': platform.release(),
                  'python': platform.python_version()}, 'logs': {}}
        start = time.monotonic()
        log_errors: list[str] = []
        timed_out = False
        retained_pipe = False
        proc = None
        finished = False
        code = 74
        try:
            try:
                proc = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=True)
            except FileNotFoundError as error:
                code = 78
                record['error'] = f'Executable unavailable: {error.filename}'
            except OSError as error:
                record['error'] = f'Command launch failed: {error}'
            if proc is not None:
                with selectors.DefaultSelector() as selector:
                    for label, pipe in [('stdout', proc.stdout), ('stderr', proc.stderr)]:
                        os.set_blocking(pipe.fileno(), False)
                        selector.register(pipe, selectors.EVENT_READ, label)
                    exited_at = None
                    while selector.get_map() or proc.poll() is None:
                        now = time.monotonic()
                        if now - start >= timeout and proc.poll() is None and not timed_out:
                            timed_out = True
                            try:
                                os.killpg(proc.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        if proc.poll() is not None:
                            if exited_at is None:
                                exited_at = now
                            elif now - exited_at > 1 and selector.get_map():
                                retained_pipe = True
                                log_errors.append('Detached child retained output pipe; descendant cleanup is UNKNOWN')
                                break
                        for key, _ in selector.select(timeout=.05):
                            stream = streams[key.data]
                            try:
                                chunk = os.read(key.fileobj.fileno(), 65536)
                            except BlockingIOError:
                                continue
                            if not chunk:
                                stream['eof'] = True
                                selector.unregister(key.fileobj)
                                continue
                            stream['total'] += len(chunk)
                            stream['full'].update(chunk)
                            piece = chunk[:max(0, LOG_LIMIT - stream['written'])]
                            while piece:
                                written = os.write(stream['fd'], piece)
                                if written <= 0:
                                    raise OSError('Log write made no progress')
                                stream['kept'].update(piece[:written])
                                stream['written'] += written
                                piece = piece[written:]
                    code = proc.wait()
                    if timed_out:
                        code = 124
                    if retained_pipe:
                        code = 74
            finished = True
        except OSError as error:
            code = 74
            log_errors.append(f'Output capture failed: {error}')
        finally:
            if proc is not None:
                try:
                    _stop_and_reap(proc, kill_group=not finished or retained_pipe)
                finally:
                    try:
                        if proc.stdout is not None:
                            proc.stdout.close()
                    finally:
                        if proc.stderr is not None:
                            proc.stderr.close()
        for label, stream in streams.items():
            try:
                os.fsync(stream['fd'])
            except OSError as error:
                log_errors.append(f'{label} log durability failed: {error}')
            record['logs'][label] = {'path': stream['path'], 'sha256': stream['kept'].hexdigest(),
                'full_stream_sha256': stream['full'].hexdigest() if stream['eof'] else None,
                'total_bytes': stream['total'], 'retained_bytes': stream['written'],
                'truncated': stream['total'] > stream['written'], 'eof_observed': stream['eof']}
        if log_errors:
            code = 74
        record.update(end_utc=utc(), duration_seconds=time.monotonic() - start,
                      exit_code=code, timed_out=timed_out,
                      status='PASS' if code == 0 else 'BLOCKED' if code == 78 else 'FAIL',
                      source_sha256_after=source_digest(cwd), log_errors=log_errors)
        _write_all(record_fd, (json.dumps(record, indent=2) + '\n').encode())
        os.fsync(record_fd)
        fcntl.flock(manifest_fd, fcntl.LOCK_EX)
        try:
            _private_metadata(manifest_fd, directory=False)
            _write_all(manifest_fd, (json.dumps(record, sort_keys=True) + '\n').encode())
            os.fsync(manifest_fd)
        finally:
            fcntl.flock(manifest_fd, fcntl.LOCK_UN)
        os.fsync(raw_fd)
        os.fsync(out_fd)
        return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cwd', type=Path, default=Path.cwd())
    parser.add_argument('--out', type=Path, default=Path('verification'))
    parser.add_argument('--category', required=True)
    parser.add_argument('--requirement', action='append', default=[])
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    a = parser.parse_args()
    cmd = a.command[1:] if a.command[:1] == ['--'] else a.command
    record = capture(cmd, a.cwd, a.out, a.category, a.requirement, a.timeout)
    print(json.dumps(record, indent=2))
    return max(0, record['exit_code']) if record['exit_code'] >= 0 else 128 - record['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
