#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's unit suite (check framework), built by build.sh as mayhem/out/sslsplit.test with the
# normal flags. It must run from the source root: the tests read extra/pki/* and other tree files.
T="$SRC/mayhem/out/sslsplit.test"
if [ ! -x "$T" ]; then
  echo "test.sh: $T missing — mayhem/build.sh must build it" >&2
  emit_ctrf "check" 0 1 0; exit 1
fi
log="$(mktemp)"
CK_FORK=yes "$T" >"$log" 2>&1; rc=$?
cat "$log"
# check prints: "<pct>%: Checks: N, Failures: F, Errors: E"
line="$(grep -E '^[0-9]+%: Checks: [0-9]+, Failures: [0-9]+, Errors: [0-9]+' "$log" | tail -1)"
if [ -z "$line" ]; then
  rm -f "$log"
  echo "test.sh: no check summary in the suite output (rc=$rc)" >&2
  emit_ctrf "check" 0 1 0; exit 1
fi
checks=$(sed -E 's/.*Checks: ([0-9]+).*/\1/' <<<"$line")
fails=$(sed -E 's/.*Failures: ([0-9]+).*/\1/' <<<"$line")
errs=$(sed -E 's/.*Errors: ([0-9]+).*/\1/' <<<"$line")
failed=$(( fails + errs ))
passed=$(( checks - failed ))
skipped=0
# proxyspec_parse resolves numeric addresses through getaddrinfo(AI_ADDRCONFIG) (sys.c), which
# glibc refuses when the host has no non-loopback address (e.g. `docker run --network none`, the
# air-gapped re-run). Only there, count that test case's errors as skipped, not failed.
if ! getent ahostsv4 127.0.0.1 >/dev/null 2>&1; then
  skipped=$(grep -cE '^opts\.t\.c:[0-9]+:E:proxyspec_parse:' "$log" || true)
  failed=$(( failed - skipped ))
  echo "test.sh: no non-loopback address — $skipped proxyspec_parse checks skipped (AI_ADDRCONFIG)"
fi
rm -f "$log"
[ "$rc" -eq 0 ] || [ "$failed" -gt 0 ] || [ "$skipped" -gt 0 ] || failed=1
emit_ctrf "check" "$passed" "$failed" "$skipped"
