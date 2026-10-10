#!/usr/bin/env python3
"""Standalone test runner (no pytest needed).

Usage:  python tests/test_all.py
"""
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_all as T

def main():
    tests = [(n, f) for n, f in sorted(vars(T).items())
             if n.startswith("test_") and callable(f)]
    passed, failed = 0, 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
            passed += 1
        except Exception:
            print(f"  FAIL  {name}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed, {len(tests)} total")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
