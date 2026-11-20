#!/usr/bin/env python3
import sys
print('BLOCKED: native product target not implemented: ' + ' '.join(sys.argv[1:]), file=sys.stderr)
raise SystemExit(78)
