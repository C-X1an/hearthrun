#!/usr/bin/env python3
"""Exercise real ENOSPC during daemon publication and recovery of the owned state."""
from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import sys
import time

from resources import ResourceSuite, native

RESERVE_BYTES = 128 * 1024


class PublicationSuite(ResourceSuite):
    def check_mount(self) -> None:
        parent = self.work.parent
        info = parent.lstat()
        rows = [row.split() for row in native.read_file(Path('/proc/self/mountinfo'), 1024 * 1024,
                                                       virtual=True).decode().splitlines()]
        mounts = [row for row in rows if re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), row[4]) == str(parent)]
        filesystem, options = native.mount_for(parent)
        capacity = os.statvfs(parent)
        if (parent.resolve(strict=True) != parent or not parent.is_mount() or info.st_uid != os.geteuid()
                or os.geteuid() == 0 or stat.S_IMODE(info.st_mode) != 0o700
                or len(mounts) != 1 or mounts[0][3] != '/' or sum(row[2] == mounts[0][2] for row in rows) != 1
                or filesystem != 'tmpfs' or not {'noswap', 'nodev', 'noexec'} <= options
                or not 8 * 1024 * 1024 <= capacity.f_blocks * capacity.f_frsize <= 128 * 1024 * 1024):
            raise native.Blocked('publication pressure requires a dedicated 8–128 MiB owner-only noswap nodev noexec tmpfs')
        native.require(not any(parent.iterdir()), 'publication pressure mount must be empty before the run')

    def exercise(self) -> None:
        code, stdout, _ = self.command([str(self.bin_dir / 'hearthrun-supervisor'), 'install-profile',
                                       str(self.state), 'example', str(self.fixture)])
        native.require(code == 0 and native.strict_json(stdout).get('profile_id') == 'example',
                       'approved synthetic resource profile installation failed')
        self.start()
        data = self.work / 'data.ndjson'
        native.write_synthetic(data, b'{"value":1}\n')
        self.stage = self.cli('stage', f'data.ndjson={data}')['stage_id']
        prior = self.submit_mode('standard')
        self.terminal(prior, 'SUCCEEDED')
        baseline = self.verify_result(prior, 'SUCCEEDED')
        self.cli('result', prior)

        request = secrets.token_hex(16)
        job = self.submit(request, self.stage, 'streams')
        group, members, launchers, _ = self.live_group(job)
        server = self.server
        filler = self.work / 'pressure.bin'
        fd = None
        try:
            native.require(server is not None, 'owned supervisor identity missing')
            fd = os.open(filler, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            space = os.fstatvfs(fd)
            remaining = space.f_bavail * space.f_frsize
            native.require(remaining > 4 * RESERVE_BYTES, 'not enough space to stage the controlled allocation')
            os.posix_fallocate(fd, 0, remaining - RESERVE_BYTES)
            space = os.fstatvfs(fd)
            free = space.f_bavail * space.f_frsize
            native.require(0 < free <= RESERVE_BYTES, 'real pressure allocation did not take effect')
            native.require(b'populated 1\n' in self.control_read(group, 'cgroup.events'),
                           'fixture exited before controlled pressure was established')
            response = self.raw_request(json.dumps({'v': 1, 'op': 'result', 'job_id': job}).encode())
            native.require(response.get('ok') is False and response.get('error', {}).get('code') == 'NOT_READY',
                           'result was visible while the real fixture was still running')

            deadline = time.monotonic() + 12
            while server.poll() is None:
                native.require(time.monotonic() < deadline, 'supervisor did not report bounded publication failure')
                time.sleep(0.01)
            server.pump()
            failure = bytes(server.buffers['stderr'])
            native.require(server.proc.returncode == 1 and b'cannot write retained stream' in failure
                           and f'os error {errno.ENOSPC}'.encode() in failure,
                           'failure did not come from the real result stream write')
            record = self.record(job)
            native.require(record.get('state') == 'EXPORTING' and record.get('result_digest') is None
                           and record.get('cleanup_confirmed') is True, 'failed publication acquired a terminal receipt')
            result_root = self.state / 'results'
            native.require(not (result_root / job).exists(), 'partial result appeared at its final name')
            stages = list(result_root.glob(f'.tmp-{job}-*'))
            native.require(len(stages) == 1 and (stages[0] / 'stdout.bin').is_file(), 'failed write did not retain its private stage')
            native.require(not self.group_names(), 'storage failure retained a job cgroup')
        finally:
            os.close(group)
            if fd is not None:
                os.close(fd)
                filler.unlink()

        native.require(server.wait(2) == 1, 'failed supervisor was not reaped')
        self.start()
        self.terminal(job, 'INTERRUPTED')
        self.cleanup_observed(job, members, launchers)
        metadata, stdout, stderr = self.verify_result(job, 'INTERRUPTED')
        native.require(metadata['artifacts'] == [] and not stdout and not stderr,
                       'restart exposed partial failed-publication bytes')
        native.require(not list((self.state / 'results').glob(f'.tmp-{job}-*')), 'restart retained the private stage')
        native.require(self.verify_result(prior, 'SUCCEEDED') == baseline, 'restart changed the prior committed bundle')
        replay = self.cli('submit', request, 'example', self.stage, '60000', '--', 'streams')
        native.require(replay.get('job_id') == job and replay.get('state') == 'INTERRUPTED' and not self.group_names(),
                       'retry replayed the uncertain fixture')
        native.emit('publication_pressure', 'PASS', free_bytes=free, errno=errno.ENOSPC, failed_state='EXPORTING',
                    recovered_state='INTERRUPTED', prior_result_readable=True, partial_result_visible=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bin-dir', 'doctor', 'fixture', 'cgroup-root', 'work'):
        parser.add_argument(f'--{name}', required=True)
    args = parser.parse_args()

    def terminate(signum, _frame):
        signal.signal(signum, signal.SIG_DFL)
        raise native.Failure('termination requested during owned pressure check')

    signal.signal(signal.SIGTERM, terminate)
    suite = PublicationSuite(args)
    status = 1
    try:
        suite.check_mount()
        suite.preflight()
        suite.exercise()
        status = 0
    except native.Blocked as error:
        native.emit('publication_pressure', 'BLOCKED', reason=str(error)[:1024])
        status = 78
    except Exception as error:
        native.emit('publication_pressure', 'FAIL', reason=f'{type(error).__name__}: {error}'[:1024])
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
