#!/usr/bin/env python3
"""Run an available tool; missing capability is BLOCKED rather than success."""
import shutil
import subprocess
import sys
if len(sys.argv) < 2:
    raise SystemExit('usage: require_tool.py PROGRAM [ARG ...]')
if shutil.which(sys.argv[1]) is None:
    print('BLOCKED: required executable unavailable: ' + sys.argv[1], file=sys.stderr)
    raise SystemExit(78)
raise SystemExit(subprocess.call(sys.argv[1:]))
