#!/usr/bin/env python3
"""Lose a real local submission reply and verify one durable request identity."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import socket
import stat
import struct
import sys
import time

from resources import native


class RetrySuite(native.Harness):
    def submit_without_reading_reply(self, header: bytes) -> None:
        name = self.state / 'control.sock'
        info = name.lstat()
        native.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid()
                       and stat.S_IMODE(info.st_mode) == 0o600, 'submission socket was not the owned endpoint')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2)
            connection.connect(str(name))
            _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            native.require(uid == os.geteuid(), 'submission peer did not match the operator UID')
            connection.sendall(struct.pack('!I', len(header)) + header)
            connection.shutdown(socket.SHUT_WR)
            # Close the client without reading any reply bytes.

    def wait_for_visible_record(self, request: str, previous: set[str]) -> str:
        deadline = min(self.deadline, time.monotonic() + 8)
        while time.monotonic() < deadline:
            self.pump_server()
            paths = [path for path in (self.state / 'records').iterdir()
                     if path.suffix == '.json' and native.ID.fullmatch(path.stem) and path.stem not in previous]
            native.require(len(paths) <= 1, 'one submit generated multiple record names')
            if paths:
                job = paths[0].stem
                self.jobs.add(job)
                if self.record(job).get('request_id') == request:
                    return job
                raise native.Failure('the durable record did not belong to the lost reply')
            time.sleep(0.01)
        raise native.Failure('the supervisor did not persist the complete lost-reply request')

    def lose_submit(self, request: str, stage: str, mode: str, wall_ms: int, previous: set[str]) -> str:
        frame = json.dumps({'v': 1, 'op': 'submit', 'request_id': request, 'profile_id': 'example',
                            'stage_id': stage, 'wall_ms': wall_ms, 'argv': [mode]}).encode()
        self.submit_without_reading_reply(frame)
        return self.wait_for_visible_record(request, previous)

    def exercise(self) -> None:
        code, stdout, _ = self.command([str(self.bin_dir / 'hearthrun-supervisor'), 'install-profile',
                                       str(self.state), 'example', str(self.fixture)])
        native.require(code == 0 and native.strict_json(stdout)['profile_id'] == 'example',
                       'approved synthetic fixture could not install')
        self.start()
        input_path = self.work / 'data.ndjson'
        native.write_synthetic(input_path, b'{"value":-2}\n{"value":11}\n')
        stage = self.cli('stage', f'data.ndjson={input_path}')['stage_id']
        request = secrets.token_hex(16)
        job = self.lose_submit(request, stage, 'summary', 10000, set())
        self.terminal(job, 'SUCCEEDED')
        verified = self.verify_result(job, 'SUCCEEDED')
        expected = native.strict_json(native.read_file(self.state / 'results' / job / 'artifacts' / 'summary.json',
                                                       1024, owner=True, mode=0o600))
        native.require(expected == {'count': 2, 'sum': 9}, 'the single approved job did not execute the expected transform')
        before = self.record(job)

        def validate_retries() -> None:
            retry = self.cli('submit', request, 'example', stage, '10000', '--', 'summary')
            native.require(retry['job_id'] == job and retry['state'] == 'SUCCEEDED', 'retry changed the durable job identity')
            try:
                self.cli('submit', request, 'example', stage, '10000', '--', 'empty', ok=False, error='CONFLICT')
            except native.Failure as error:
                raise native.Failure(f'changed argument for retained request did not conflict: {error}') from error
            self.cli('submit', request, 'example', stage, '11000', '--', 'summary', ok=False, error='CONFLICT')
            metrics = self.cli('metrics')
            native.require(metrics['active'] == 0 and metrics['queued'] == 0 and self.inventory() == {job}
                           and not self.group_names() and self.record(job) == before,
                           'retry changed the journal, scheduler or cgroup state')
            native.require(self.verify_result(job, 'SUCCEEDED') == verified, 'retry changed the verified result')

        validate_retries()
        assert self.server is not None
        self.server.proc.terminate()
        native.require(self.server.wait(16) == 0, 'supervisor did not shut down cleanly before restart')
        self.start()
        validate_retries()

        active_request = secrets.token_hex(16)
        active_job = self.lose_submit(active_request, stage, 'hold', 60000, {job})
        self.detached_ready(active_job)
        running = self.cli('submit', active_request, 'example', stage, '60000', '--', 'hold')
        native.require(running['job_id'] == active_job and running['state'] == 'RUNNING'
                       and self.inventory() == {job, active_job}, 'early retry admitted different running work')
        recovery = self.restart_interrupted(active_job, active_request, stage)
        native.require(recovery['state'] == 'INTERRUPTED' and self.inventory() == {job, active_job}
                       and self.record(job) == before and self.verify_result(job, 'SUCCEEDED') == verified,
                       'uncertain-work recovery changed the prior result or admitted a second job')
        native.emit('lost_reply_idempotency', 'PASS', lost_replies=2, admitted_jobs=2,
                    exact_retries=4, conflicted_retries=5, graceful_restart=True, crash_restart=True,
                    recovered_state=recovery['state'], prior_result_unchanged=True)

    def cleanup(self) -> list[str]:
        errors = []
        if self.created_work and (self.state / 'records' / 'catalog.json').exists():
            try:
                self.jobs.update(self.inventory())
            except Exception as error:
                errors.append(f'could not reconcile the owned request catalog: {error}')
        return errors + super().cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bin-dir', 'doctor', 'fixture', 'cgroup-root', 'work'):
        parser.add_argument(f'--{name}', required=True)
    args = parser.parse_args()

    def terminate(signum, _frame):
        signal.signal(signum, signal.SIG_DFL)
        raise native.Failure('termination requested during owned retry verification')

    signal.signal(signal.SIGTERM, terminate)
    suite = RetrySuite(args)
    status = 1
    try:
        suite.preflight()
        suite.exercise()
        status = 0
    except native.Blocked as error:
        native.emit('lost_reply_idempotency', 'BLOCKED', reason=str(error)[:1024])
        status = 78
    except Exception as error:
        native.emit('lost_reply_idempotency', 'FAIL', reason=f'{type(error).__name__}: {error}'[:1024])
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
