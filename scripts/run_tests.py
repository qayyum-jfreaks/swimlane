#!/usr/bin/env python3
"""Portable test runner for the WhoisFreaks Swimlane connector.

The test files are written as plain ``test_*`` functions with ``assert``
statements, so they run under ``pytest`` when available and under this
dependency-free runner when it is not. It wires ``connector/src`` and ``tests``
onto ``sys.path`` and executes every ``test_*`` function it finds.

Usage:
    python3 scripts/run_tests.py
"""
import glob
import importlib.util
import os
import sys
import traceback
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.join(ROOT, "connector", "src"))


def main() -> int:
    passed = failed = 0
    failures = []
    for path in sorted(glob.glob(os.path.join(ROOT, "tests", "test_*.py"))):
        modname = os.path.splitext(os.path.basename(path))[0]
        spec = importlib.util.spec_from_file_location(modname, path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # import-time failure
            failed += 1
            failures.append((f"{modname} (import)", traceback.format_exc()))
            print(f"FAIL import {modname}: {exc}")
            continue
        for name in sorted(dir(module)):
            if not name.startswith("test_"):
                continue
            fn = getattr(module, name)
            if not isinstance(fn, types.FunctionType):
                continue
            try:
                fn()
                passed += 1
                print(f"PASS {modname}.{name}")
            except Exception as exc:
                failed += 1
                failures.append((f"{modname}.{name}", traceback.format_exc()))
                print(f"FAIL {modname}.{name}: {exc}")

    print(f"\n=== {passed} passed, {failed} failed ===")
    for name, tb in failures:
        print(f"\n--- {name} ---\n{tb}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
