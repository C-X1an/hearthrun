#!/usr/bin/env python3
"""Reproduce the implemented native source profile in a fresh public-only checkout."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys

PUBLIC = Path(__file__).resolve().parents[2]


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def bounded_parent(work):
    parent = work.parent.resolve(strict=True)
    require(work.is_absolute() and work.parent == parent and not work.exists() and not work.is_symlink(),
            'work must name a new directory in an existing bounded parent')
    info = parent.lstat()
    require(info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o022,
            'work parent must be protected and owned by the non-root operator')
    matches = []
    for row in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = row.split(' - ', maxsplit=1)
        mount = Path(left.split()[4])
        if parent.is_relative_to(mount):
            filesystem, _, options = right.split()[:3]
            matches.append((len(mount.parts), filesystem, options.split(',')))
    _, filesystem, options = max(matches, key=lambda row: row[0])
    space = os.statvfs(parent)
    require(filesystem == 'tmpfs' and 'noswap' in options and 0 < space.f_blocks * space.f_frsize <= 12_000_000_000,
            'clean native reproduction requires a capped no-swap tmpfs')


def checked(*argv, cwd):
    return subprocess.run(argv, cwd=cwd, check=True, capture_output=True, timeout=30, text=True).stdout.strip()


def checked_tool(path):
    resolved = path.resolve(strict=True)
    require(resolved.is_file() and os.access(resolved, os.X_OK), f'{path.name} must be an executable file')
    return resolved


def capture_from(root):
    script = root / 'scripts' / 'capture.py'
    require(script.resolve(strict=True) == script and script.is_file(), 'capture must come from the exact public tree')
    spec = importlib.util.spec_from_file_location('hearthrun_repro_capture', script)
    require(spec is not None and spec.loader is not None, 'could not load the source capture implementation')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.capture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=PUBLIC)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--jobs', required=True, type=Path)
    parser.add_argument('--toolchain-bin', required=True, type=Path, help='preinstalled pinned rustc and cargo directory')
    parser.add_argument('--host-cc', default='cc')
    parser.add_argument('--native-cc', default='musl-gcc')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.geteuid() == 0 or os.getgroups():
        print(json.dumps({'status': 'BLOCKED', 'reason': 'Linux x86-64 non-root operator without supplementary groups required'}))
        return 78
    source = args.source.resolve(strict=True)
    require(source == PUBLIC, 'run this reproducer from the selected audited public source checkout')
    work = args.work
    bounded_parent(work)
    longest_socket = work / 'native' / 'integration-scheduler-20000101T000000-9999999' / 'run' / 'state' / 'control.sock'
    require(len(os.fsencode(longest_socket)) <= 107, 'work path is too long for the native Unix socket')
    jobs = args.jobs.resolve(strict=True)
    require(jobs == args.jobs and jobs.is_dir() and not any(path.is_dir() for path in jobs.iterdir()),
            'operator jobs directory must be an exact empty delegation')
    toolchain = args.toolchain_bin.resolve(strict=True)
    rustc = checked_tool(toolchain / 'rustc')
    cargo = checked_tool(toolchain / 'cargo')
    require(rustc.parent == cargo.parent == toolchain, 'use the installed compiler and cargo, without rustup shims')
    make_name = shutil.which('make')
    require(make_name is not None, 'GNU Make must be on the operator PATH')
    make = checked_tool(Path(make_name))
    work.mkdir(mode=0o700)
    for name in ('home', 'cargo', 'target', 'tmp', 'native', 'cache', 'config', 'data', 'state', 'rustup',
                 'zig-cache', 'git-template'):
        (work / name).mkdir(mode=0o700)
    os.environ.clear()
    os.environ.update(PATH=os.pathsep.join((str(toolchain), str(make.parent), '/usr/bin', '/bin')),
                      HOME=str(work / 'home'), TMPDIR=str(work / 'tmp'), TMP=str(work / 'tmp'),
                      TEMP=str(work / 'tmp'), CARGO_HOME=str(work / 'cargo'), CARGO_TARGET_DIR=str(work / 'target'),
                      XDG_CACHE_HOME=str(work / 'cache'), XDG_CONFIG_HOME=str(work / 'config'),
                      XDG_DATA_HOME=str(work / 'data'), XDG_STATE_HOME=str(work / 'state'),
                      ZIG_GLOBAL_CACHE_DIR=str(work / 'zig-cache'), ZIG_LOCAL_CACHE_DIR=str(work / 'zig-cache'),
                      GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TEMPLATE_DIR=str(work / 'git-template'),
                      GIT_TERMINAL_PROMPT='0', RUSTUP_HOME=str(work / 'rustup'), RUSTUP_AUTO_INSTALL='0', RUSTC=str(rustc),
                      HEARTHRUN_DEV_ROOT=str(work / 'native'), HEARTHRUN_JOBS=str(jobs),
                      CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1', CARGO_NET_RETRY='1', PYTHONDONTWRITEBYTECODE='1',
                      LANG='C.UTF-8', TZ='UTC')
    sys.dont_write_bytecode = True
    require(Path(checked('git', 'rev-parse', '--show-toplevel', cwd=source)) == source,
            'source must be the root of an audited public-only checkout')
    require(not checked('git', 'status', '--porcelain', cwd=source), 'source has uncommitted changes')
    commit = checked('git', 'rev-parse', 'HEAD', cwd=source)
    clone = work / 'source'
    evidence = work / 'evidence'
    staged = capture_from(source)(['git', 'clone', '--no-local', '--no-recurse-submodules', '--no-tags',
                                   '--single-branch', '--depth', '1', source.as_uri(), str(clone)],
                                  source, evidence, 'clean-local-clone', ['AC-019'], 30)
    require(staged['status'] == 'PASS' and checked('git', 'rev-parse', 'HEAD', cwd=clone) == commit,
            'fresh clone did not have the audited source commit')
    require(not (clone / 'private').exists(), 'package-private contents are forbidden')
    capture = capture_from(clone)
    rust_version = checked(str(rustc), '-vV', cwd=clone)
    cargo_version = checked(str(cargo), '--version', cwd=clone)
    require(rust_version.startswith('rustc 1.99.1 ') and cargo_version.startswith('cargo 1.99.1 '),
            'pinned compiler and Cargo required')
    print(json.dumps({'commit': commit, 'clone_capture': staged['run_id'], 'rustc': rust_version,
                      'cargo': cargo_version, 'make': checked(str(make), '--version', cwd=clone).splitlines()[0]}),
          flush=True)
    commands = [
        ('clean-audit', [str(make), 'public-audit']),
        ('clean-bootstrap', [str(make), 'bootstrap']),
        ('clean-fetch', [str(cargo), 'fetch', '--locked']),
        ('clean-sources', [str(make), 'build', 'fmt', 'lint', 'typecheck', 'unit', 'tooling-test', 'property', 'fuzz']),
        ('clean-native-prerequisites', [str(make), '.work/hearthrun-probe', 'native-prerequisites', 'policy-fixture',
                                        'resource-fixture', f'CC={args.host_cc}', f'NATIVE_CC={args.native_cc}']),
        ('clean-e2e', [str(make), 'integration-run', 'security-smoke', 'resource-run', 'demo-run']),
    ]
    outcomes = [staged['run_id']]
    try:
        for name, argv in commands:
            outcome = capture(argv, clone, evidence, name, ['AC-019'], 240)
            outcomes.append(outcome['run_id'])
            print(json.dumps({'case': name, 'status': outcome['status'], 'run_id': outcome['run_id']}), flush=True)
            require(outcome['status'] == 'PASS', f'{name} did not pass')
            if name == 'clean-fetch':
                os.environ['CARGO_NET_OFFLINE'] = 'true'
    finally:
        teardown = capture([str(make), 'teardown'], clone, evidence, 'clean-teardown', ['AC-019'], 30)
        require(teardown['status'] == 'PASS' and not any(path.is_dir() for path in jobs.iterdir()),
                'clean teardown did not prove an empty delegation')
        outcomes.append(teardown['run_id'])
    print(json.dumps({'status': 'PASS', 'commit': commit, 'captures': outcomes,
                      'scope': 'fresh local clone, fresh Cargo cache, implemented native profile'}))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'FAIL', 'reason': str(error)[:512]}), file=sys.stderr)
        sys.exit(1)
