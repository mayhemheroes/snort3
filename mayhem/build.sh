#!/usr/bin/env bash
#
# mayhem/build.sh — build snort3's TWO upstream fuzz harnesses.
#
# snort3 ships its own libFuzzer harnesses under src/decompress/fuzz/ (wired into its real cmake
# build via `add_fuzzer()` in cmake/macros.cmake, gated by -DENABLE_FUZZERS=ON):
#   file_decomp_zip_fuzz  — src/decompress/file_decomp_zip.cc:  ZIP local-file-header + DEFLATE
#                            decompression state machine (used to pull vbaMacros / VBA content out
#                            of Office documents embedded in a scanned ZIP stream).
#   file_olefile_fuzz     — src/decompress/file_olefile.cc + file_oleheader.cc: legacy OLE2/CFBF
#                            compound-file parser (FAT/MiniFAT walk + RLE decompression) used to
#                            pull VBA macros out of old-format (.doc/.xls) Office documents.
# Both operate on attacker-controlled file bytes reconstructed from network traffic — exactly the
# kind of file-format parsing OSS-Fuzz/Mayhem exists to fuzz.
#
# DEPENDENCY NOTE: snort3's own cmake ALWAYS requires DAQ/DNET/HWLOC/LuaJIT/OpenSSL/PCAP/PCRE2/ZLIB
# to configure (cmake/include_libraries.cmake), even though these two fuzz targets don't use them —
# they're pulled in as a project-wide link_libraries(). DAQ (snort3's OWN libdaq v3, NOT Debian's
# ancient libdaq-dev v2 package) has no Debian package and is built from source + `make install`ed
# as a normal system lib in mayhem/Dockerfile (network at IMAGE BUILD time only); everything else is
# a pinned apt -dev package. This script only builds the fuzz/test targets — it never touches the
# network, so it re-runs cleanly under `docker run --network none` (air-gapped, §6.2 item 9).
#
# Build contract (base image ENV) — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF < 4; Mayhem's triage can't read DWARF >= 4)
#   SRC                 /mayhem
#   STANDALONE_FUZZ_MAIN  /opt/mayhem/StandaloneFuzzTargetMain.c
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

FUZZ_TARGETS=(file_decomp_zip_fuzz file_olefile_fuzz)

# ── 1) SANITIZED fuzz build: snort3's OWN cmake fuzz targets, built with $SANITIZER_FLAGS and
#      $DEBUG_FLAGS via the project's native ENABLE_FUZZ_SANITIZER path (add_fuzzer() in
#      cmake/macros.cmake wires -fsanitize=fuzzer per-target through FUZZER_CXX_FLAGS/LINKER_FLAGS).
#      This configures the WHOLE project (cmake requires DAQ/DNET/etc. unconditionally) but building
#      only these two named targets compiles just their handful of decompress/*.cc + helpers/*.cc
#      sources (see src/decompress/fuzz/CMakeLists.txt) — not the rest of snort3. ─────────────────
#      ENABLE_GDB=OFF + CMAKE_BUILD_TYPE= (empty) so nothing else re-appends a plain `-g` AFTER our
#      explicit $DEBUG_FLAGS on the compiler command line (a later bare -g would reset to DWARF-5).
FUZZ_BUILD="$SRC/mayhem-build-fuzz"
rm -rf "$FUZZ_BUILD"
cmake -S "$SRC" -B "$FUZZ_BUILD" -G Ninja \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DENABLE_FUZZERS=ON -DENABLE_FUZZ_SANITIZER=ON -DENABLE_GDB=OFF \
  -DCMAKE_BUILD_TYPE= \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS"
cmake --build "$FUZZ_BUILD" -j"$MAYHEM_JOBS" --target "${FUZZ_TARGETS[@]}"

# Standalone driver object (no libFuzzer runtime; StandaloneFuzzTargetMain.c is C, so it's compiled
# once here and re-linked into each C++ harness below — clang++ would otherwise mangle its
# LLVMFuzzerTestOneInput reference).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_BUILD/standalone_main.o"

for t in "${FUZZ_TARGETS[@]}"; do
  cp "$FUZZ_BUILD/fuzz/$t" "/mayhem/$t"

  # Standalone reproducer: re-link the SAME compiled objects (ninja's own recorded link command for
  # this target) against the standalone driver instead of $LIB_FUZZING_ENGINE (-fsanitize=fuzzer).
  link_cmd="$(ninja -C "$FUZZ_BUILD" -t commands "$t" | tail -1)"
  standalone_cmd="$(printf '%s' "$link_cmd" | sed \
    -e "s#$LIB_FUZZING_ENGINE#$FUZZ_BUILD/standalone_main.o#" \
    -e "s#-o fuzz/$t#-o /mayhem/$t-standalone#")"
  ( cd "$FUZZ_BUILD" && eval "$standalone_cmd" )
  echo "built $t (+ standalone)"
done

# ── 2) Project's OWN cpputest suite for the olefile/oleheader parsers (src/decompress/test/), with
#      NORMAL (unsanitized) flags — a separate, clean tree so mayhem/test.sh only RUNS it. Uses the
#      "Unix Makefiles" generator (NOT Ninja): with -DENABLE_UNIT_TESTS=ON snort3's cmake also wires
#      the unrelated src/js_norm lexer/parser subdirectory, whose generated-source rule triggers a
#      Ninja "multiple rules generate ..." generator bug that Make does not hit; only the two named
#      test targets are actually built either way. ────────────────────────────────────────────────
TEST_BUILD="$SRC/mayhem-build-test"
rm -rf "$TEST_BUILD"
cmake -S "$SRC" -B "$TEST_BUILD" -G "Unix Makefiles" \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DENABLE_UNIT_TESTS=ON
cmake --build "$TEST_BUILD" -j"$MAYHEM_JOBS" --target file_olefile_test file_oleheader_test

# ── 3) Standalone KAT for file_decomp_zip (upstream ships no unit test for it — unlike olefile).
#      Compiled directly against the REAL production sources (unmodified), normal flags, no cmake
#      target needed. Reuses $FUZZ_BUILD's generated config.h (ENABLE_UNIT_TESTS is OFF there, so
#      file_decomp.cc's #ifdef UNIT_TEST Catch2 TEST_CASE blocks are compiled out — the TEST_BUILD's
#      config.h has UNIT_TEST defined and would need linking Catch2, which this KAT does not use).
$CXX -DHAVE_CONFIG_H -Dinline=inline -Drestrict=__restrict -std=c++17 \
  -I"$SRC/src/network_inspectors" -I"$SRC/src" -I"$FUZZ_BUILD" -I"$SRC" \
  "$SRC/mayhem/harnesses/zip_kat_test.cc" \
  "$SRC/src/decompress/file_decomp_zip.cc" "$SRC/src/decompress/file_decomp_pdf.cc" \
  "$SRC/src/decompress/file_decomp_swf.cc" "$SRC/src/decompress/file_decomp.cc" \
  "$SRC/src/helpers/boyer_moore_search.cc" \
  -lz -llzma -o "$TEST_BUILD/zip_kat_test"

echo "build.sh complete:"
ls -la /mayhem/file_decomp_zip_fuzz /mayhem/file_olefile_fuzz \
       /mayhem/file_decomp_zip_fuzz-standalone /mayhem/file_olefile_fuzz-standalone \
       "$TEST_BUILD/src/decompress/test/file_olefile_test" \
       "$TEST_BUILD/src/decompress/test/file_oleheader_test" \
       "$TEST_BUILD/zip_kat_test" 2>&1 || true

# mayhem-dict-fix: place the dictionaries the Mayhemfiles reference (build.sh never did -> libFuzzer exited 1 on missing -dict -> 0 edges)
find "$SRC/mayhem" -name "*.dict" -exec cp {} /mayhem/ \; 2>/dev/null || true
