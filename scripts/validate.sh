#!/usr/bin/env bash
set -euo pipefail

# WhoisFreaks Swimlane connector local validation gate.
# Portable: no machine-specific paths. tsdk/Docker gates are attempted when the
# tooling is present and reported as SKIPPED (not PASSED) when it is not.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

RESULT=0
have() { command -v "$1" >/dev/null 2>&1; }

echo "=================================================================="
echo " [GATE 1/5] Turbine connector schema validation (tsdk)"
echo "=================================================================="
if have tsdk; then
  tsdk connector validate || RESULT=1
else
  echo "SKIPPED: tsdk not found. Install the Swimlane Turbine SDK to run this gate."
fi

echo ""
echo "=================================================================="
echo " [GATE 2/5] Static linting & formatting"
echo "=================================================================="
if have tsdk; then
  tsdk connector lint || RESULT=1
elif have flake8 || python3 -c "import flake8" 2>/dev/null; then
  echo "tsdk not found; running flake8 directly (max-line-length=120)."
  python3 -m flake8 --max-line-length=120 connector/src/ tests/ scripts/run_tests.py || RESULT=1
else
  echo "SKIPPED: neither tsdk nor flake8 available."
fi

echo ""
echo "=================================================================="
echo " [GATE 3/5] Unit test suite"
echo "=================================================================="
if have pytest || python3 -c "import pytest" 2>/dev/null; then
  python3 -m pytest -q tests/ || RESULT=1
else
  echo "pytest not found; running the dependency-free test runner."
  python3 scripts/run_tests.py || RESULT=1
fi

echo ""
echo "=================================================================="
echo " [GATE 4/5] Secret scan"
echo "=================================================================="
# Fail on anything that looks like a real API key / token in source & config.
# Scans the filesystem directly (works outside a git checkout). Docs and tests
# are allowed to contain illustrative placeholders only.
SUSPECT='(ghp_[0-9A-Za-z]{36}|[0-9a-fA-F]{40}|AKIA[0-9A-Z]{16})'
if grep -REIn --include='*.py' --include='*.yaml' --include='*.yml' \
     "${SUSPECT}" connector/ 2>/dev/null; then
  echo "ERROR: possible hardcoded secret detected in connector sources."
  RESULT=1
else
  echo "Secret scan passed: no live-looking secrets in connector sources."
fi

echo ""
echo "=================================================================="
echo " [GATE 5/5] Container image packaging build (tsdk)"
echo "=================================================================="
if have tsdk && have docker; then
  tsdk connector build || RESULT=1
else
  echo "SKIPPED: tsdk and/or docker not found. Build the image in an environment"
  echo "         with the Turbine SDK and a running Docker daemon before publishing."
fi

echo ""
echo "=================================================================="
if [[ "${RESULT}" -eq 0 ]]; then
  echo " Local gates passed (see any SKIPPED gates above before publishing)."
else
  echo " One or more gates FAILED. See output above."
fi
echo "=================================================================="
exit "${RESULT}"
