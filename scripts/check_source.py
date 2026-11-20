#!/usr/bin/env python3
"""Portable syntax/contract hygiene. Not a compiler, security audit or native test."""
import ast
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def main():
    count = 0
    for directory in ('scripts', 'tests', 'benchmarks'):
        for p in (ROOT / directory).rglob('*.py'):
            ast.parse(p.read_text(), filename=str(p.relative_to(ROOT)))
            count += 1
    for p in (ROOT / 'schemas').glob('*.json'):
        json.loads(p.read_text())
    for p in [ROOT/'Cargo.toml', ROOT/'Cargo.lock', ROOT/'rust-toolchain.toml', ROOT/'.cargo/config.toml',
              *(ROOT/'crates').glob('*/Cargo.toml')]:
        tomllib.loads(p.read_text())
    for p in (ROOT / '.github/workflows').glob('*.yml'):
        for use in re.findall(r'uses:\s*([^\s#]+)', p.read_text()):
            if not re.fullmatch(r'[\w.-]+/[\w./-]+@[0-9a-f]{40}', use):
                raise ValueError(f'Action is not full-SHA pinned: {use}')
        if 'pull_request_target:' in p.read_text():
            raise ValueError('Review privileged trigger policy before using pull_request_target')
    print(json.dumps({'status':'PASS','python_files':count,'scope':'syntax, manifest parse and workflow pin hygiene'}))
    return 0

if __name__ == '__main__': raise SystemExit(main())
