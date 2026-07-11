#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the functional oracles mayhem/build.sh already built (never compiles here):
#   1. file_olefile_test / file_oleheader_test — snort3's OWN cpputest suite for the exact code
#      file_olefile_fuzz fuzzes (src/decompress/test/file_olefile_test.cc): real CHECK()/CHECK_TRUE()
#      assertions on COMPUTED values (e.g. OleFile::find_bytes_to_copy(70,50,60,64) must equal 10;
#      a malformed mini-FAT header must yield get_mini_fat_offset() == -1).
#   2. zip_kat_test — a standalone known-answer test for file_decomp_zip.cc (upstream ships no unit
#      test for this one): builds a real ZIP local-header body around a real DEFLATE stream of a
#      KNOWN plaintext, runs it through the unmodified production decompressor, and asserts the
#      reconstructed output matches an exactly-computed expected byte sequence (see
#      mayhem/harnesses/zip_kat_test.cc for the derivation) for TWO distinct payloads — proving real
#      decompression happened, not a hardcoded echo.
#
# All three programs only print their "did this specific check pass" markers if they actually RUN —
# an exit(0) neuter (this repo's sabotage/anti-reward-hack check) produces NO output at all, so this
# script fails as soon as it can't find the expected marker lines (not just "did it exit 0").
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

TEST_BUILD="$SRC/mayhem-build-test"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

overall_fail=0
total_passed=0
total_failed=0

# --- 1+2) cpputest suites: run, then require BOTH exit 0 AND a genuine "OK (N tests, N ran, ...)"
#     summary line with N>0 — a sabotaged (exit(0)-neutered) binary prints nothing, so the grep fails
#     and the count stays at 0, which we treat as a hard failure regardless of exit code. ----------
run_cpputest() {
  local bin="$1" label="$2"
  if [ ! -x "$bin" ]; then
    echo "MISSING $label: $bin (mayhem/build.sh should have built it)" >&2
    echo 0
    return 1
  fi
  local out rc line ran
  out="$("$bin" 2>&1)"; rc=$?
  echo "=== $label ===" >&2
  echo "$out" >&2
  line="$(printf '%s\n' "$out" | grep -E '^OK \([0-9]+ tests, [0-9]+ ran' | tail -1 || true)"
  if [ -n "$line" ]; then
    ran="$(printf '%s' "$line" | sed -E 's/^OK \([0-9]+ tests, ([0-9]+) ran.*/\1/')"
  else
    ran=0
  fi
  if [ "$rc" -eq 0 ] && [ "${ran:-0}" -gt 0 ]; then
    echo "$ran"
    return 0
  fi
  echo 0
  return 1
}

ole_ran=$(run_cpputest "$TEST_BUILD/src/decompress/test/file_olefile_test" "file_olefile_test") \
  && ole_ok=1 || ole_ok=0
total_passed=$(( total_passed + (ole_ok ? ole_ran : 0) ))
total_failed=$(( total_failed + (ole_ok ? 0 : (ole_ran > 0 ? ole_ran : 1)) ))
[ "$ole_ok" -eq 1 ] || overall_fail=1

oleheader_ran=$(run_cpputest "$TEST_BUILD/src/decompress/test/file_oleheader_test" "file_oleheader_test") \
  && oleheader_ok=1 || oleheader_ok=0
total_passed=$(( total_passed + (oleheader_ok ? oleheader_ran : 0) ))
total_failed=$(( total_failed + (oleheader_ok ? 0 : (oleheader_ran > 0 ? oleheader_ran : 1)) ))
[ "$oleheader_ok" -eq 1 ] || overall_fail=1

# --- 3) zip_kat_test: two KAT cases, each printing "ZIP_KAT case=... match=1" and a final
#     "ZIP_KAT SUMMARY failures=N" line. Require the binary to exit 0 AND the summary line to read
#     failures=0 AND both individual match=1 markers to be present. -------------------------------
ZIP_KAT_BIN="$TEST_BUILD/zip_kat_test"
if [ -x "$ZIP_KAT_BIN" ]; then
  zk_out="$("$ZIP_KAT_BIN" 2>&1)"; zk_rc=$?
  echo "=== zip_kat_test ===" >&2
  echo "$zk_out" >&2
  zk_summary="$(printf '%s\n' "$zk_out" | grep -E '^ZIP_KAT SUMMARY failures=' | tail -1 || true)"
  zk_case1="$(printf '%s\n' "$zk_out" | grep -c '^ZIP_KAT case=roundtrip .*match=1$' || true)"
  zk_case2="$(printf '%s\n' "$zk_out" | grep -c '^ZIP_KAT case=distinct-payload .*match=1$' || true)"
  if [ "$zk_rc" -eq 0 ] && [ "$zk_summary" = "ZIP_KAT SUMMARY failures=0" ] \
     && [ "${zk_case1:-0}" -eq 1 ] && [ "${zk_case2:-0}" -eq 1 ]; then
    total_passed=$(( total_passed + 2 ))
  else
    echo "zip_kat_test did not produce the expected passing markers (rc=$zk_rc)" >&2
    total_failed=$(( total_failed + 2 ))
    overall_fail=1
  fi
else
  echo "MISSING zip_kat_test: $ZIP_KAT_BIN (mayhem/build.sh should have built it)" >&2
  total_failed=$(( total_failed + 2 ))
  overall_fail=1
fi

emit_ctrf "snort3-decompress-kat" "$total_passed" "$total_failed"
exit $(( overall_fail ))
