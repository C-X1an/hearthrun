"""Bounded parsing tests for retained raw trace files."""
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "benchmarks"))
from cancel_timing import parse_trace

class TraceFile(unittest.TestCase):
    def test_preserves_integer_nanoseconds_without_float_conversion(self):
        self.assertEqual(parse_trace(b'{"receipt_ns":12345678901234567}\n'),[{"receipt_ns":12345678901234567}])
    def test_duplicate_json_keys_and_partial_records_fail(self):
        for raw in (b'{"kind":"header","kind":"footer"}\n',b'{}',b'\n',b'{"n":NaN}\n',b'{}\n'*131,
                    b'{"field":"'+b'a'*2048+b'"}\n',b'{}\n'*100000):
            with self.subTest(length=len(raw)),self.assertRaises(ValueError):
                parse_trace(raw)

if __name__=="__main__":unittest.main()
