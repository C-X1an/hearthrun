#!/usr/bin/env python3
"""Audit the tracked contents and history of a public-only candidate."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

MAX_BLOB = 2 * 1024 * 1024
MAX_BLOBS = 4096
MAX_HISTORY = 256
COMPONENT = re.compile(r'[A-Za-z0-9._-]{1,128}')
FORBIDDEN = {
    'private', '.git', '.env', '.codex', '.work', 'target', '__pycache__',
    'execution_manifest.yaml', 'model_router.yaml', 'project_status.yaml', 'start_codex_prompt.txt',
}
REQUIRED = {
    'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'LICENSE', 'README.md', 'Makefile',
    'spec/acceptance.json', 'spec/acceptance.sha256', 'fixtures/native/task.c',
    'tests/e2e/native.py', 'tests/e2e/demo.py', 'tools/doctor.c', 'scripts/capture.py',
}
SENSITIVE = [
    re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}'),
    re.compile(rb'github_pat_[A-Za-z0-9_]{30,}'),
    re.compile(rb'sk-[A-Za-z0-9_-]{30,}'),
    re.compile(rb'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----'),
    re.compile(rb'[A-Za-z]:\\Users\\[^\\\r\n ]+', re.I),
    re.compile(rb'/mnt/[a-z]/Users/[^/\r\n ]+', re.I),
]


class AuditError(ValueError):
    pass


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, timeout=20)
    if result.returncode:
        raise AuditError(f'git {args[0]} failed in candidate')
    return result.stdout


def logical(name):
    path = PurePosixPath(name)
    if (not path.parts or path.is_absolute() or name != path.as_posix() or
            any(not COMPONENT.fullmatch(part) or part in ('.', '..') or
                part.casefold() in FORBIDDEN or part.endswith('.') for part in path.parts) or
            path.suffix.lower() in ('.pem', '.token', '.key', '.vhdx', '.pyc')):
        raise AuditError('forbidden tracked publication path')
    return path


def inspect_contents(name, content):
    if len(content) > MAX_BLOB or any(pattern.search(content) for pattern in SENSITIVE):
        raise AuditError('oversized or potentially sensitive tracked file')
    if name.startswith('.github/workflows/'):
        text = content.decode('utf-8', errors='strict')
        if re.search(r'pull_request_target:|self-hosted|contents:\s*write|persist-credentials:\s*true', text):
            raise AuditError('privileged GitHub workflow configuration')
        for action in re.findall(r'uses:\s*([^\s#]+)', text):
            if not re.fullmatch(r'[\w.-]+/[\w./-]+@[0-9a-f]{40}', action):
                raise AuditError('unpinned GitHub action')


def index(root):
    result = {}
    casefolded = set()
    for row in git(root, 'ls-files', '--stage', '-z').split(b'\0'):
        if not row:
            continue
        metadata, name = row.decode('utf-8', errors='strict').split('\t', 1)
        mode, oid, stage = metadata.split()
        logical(name)
        if mode not in ('100644', '100755') or stage != '0' or name.casefold() in casefolded:
            raise AuditError('nonregular, ambiguous, or unresolved tracked entry')
        casefolded.add(name.casefold())
        result[name] = oid
    if not REQUIRED <= set(result):
        raise AuditError('required public product or reproduction source missing')
    return result


def audit(root):
    if Path(git(root, 'rev-parse', '--show-toplevel').decode().strip()).resolve() != root:
        raise AuditError('run audit from the root of the public-only Git checkout')
    if git(root, 'ls-files', '--others', '--exclude-standard', '-z'):
        raise AuditError('public checkout contains unreviewed untracked files')
    checked = set()

    def inspect_blob(name, oid):
        key = (name, oid)
        if key in checked:
            return
        if len(checked) >= MAX_BLOBS or int(git(root, 'cat-file', '-s', oid)) > MAX_BLOB:
            raise AuditError('history exceeds audit bounds')
        inspect_contents(name, git(root, 'cat-file', 'blob', oid))
        checked.add(key)

    tracked = index(root)
    for name, oid in tracked.items():
        path = root.joinpath(*logical(name).parts)
        props = path.lstat()
        if (not stat.S_ISREG(props.st_mode) or props.st_nlink != 1 or props.st_size > MAX_BLOB
                or path.resolve(strict=True) != path):
            raise AuditError('working tree contains a redirected or oversized tracked resource')
        inspect_contents(name, path.read_bytes())
        inspect_blob(name, oid)
    history = git(root, 'rev-list', '--all', f'--max-count={MAX_HISTORY + 1}').splitlines()
    if len(history) > MAX_HISTORY:
        raise AuditError('history exceeds full-audit commit bound')
    for commit in history:
        for item in git(root, 'ls-tree', '-rz', commit.decode()).split(b'\0'):
            if not item:
                continue
            metadata, name = item.decode('utf-8', errors='strict').split('\t', 1)
            mode, kind, oid = metadata.split()
            logical(name)
            if mode not in ('100644', '100755') or kind != 'blob':
                raise AuditError('nonregular tracked resource in history')
            inspect_blob(name, oid)
    return {'status': 'PASS', 'tracked_paths': len(tracked), 'audited_commits': len(history),
            'inspected_path_blob_pairs': len(checked),
            'scope': 'tracked paths, known secret patterns and workflow permissions'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path, default=Path.cwd(), nargs='?')
    args = parser.parse_args()
    try:
        print(json.dumps(audit(args.root.resolve(strict=True)), sort_keys=True))
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'status': 'FAIL', 'error': type(error).__name__,
                          'detail': str(error) if isinstance(error, AuditError) else 'candidate could not be verified'}))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
