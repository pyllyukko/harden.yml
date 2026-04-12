#!/bin/bash
#
# Test a pre-built pwqfilter cuckoo filter (/opt/passwdqc/rockyou.pwq)
# created from /usr/share/dict/rockyou.txt.bz2 with --create=14700000.
# Verifies the filter's integrity, capacity, and lookup correctness.

set -euo pipefail

PWQFILTER_BIN="${PWQFILTER_BIN:-pwqfilter}"
FILTER="${FILTER:-/opt/passwdqc/rockyou.pwq}"
ROCKYOU_BZ2="${ROCKYOU_BZ2:-/usr/share/dict/rockyou.txt.bz2}"
EXPECTED_CAPACITY=14637132

if ! command -v "${PWQFILTER_BIN}" >/dev/null 2>&1; then
  echo "[-] pwqfilter not found" >&2
  exit 1
fi

if [ ! -f "${FILTER}" ]; then
  echo "[-] filter not found at ${FILTER}" >&2
  echo "    Create it with:" >&2
  echo "    bzcat ${ROCKYOU_BZ2} | ${PWQFILTER_BIN} --create=${EXPECTED_CAPACITY} --output=${FILTER}" >&2
  exit 1
fi

if [ -t 1 ]; then
  GREEN=$'\033[0;32m'
  RED=$'\033[0;31m'
  NC=$'\033[0m'
else
  GREEN=""
  RED=""
  NC=""
fi

pass=0
fail=0

assert() {
  local description="$1"
  local expected_exit="$2"
  shift 2

  printf "%-55s" "${description}"
  if "$@" >/dev/null 2>&1; then
    actual_exit=0
  else
    actual_exit=$?
  fi

  if [ "${actual_exit}" -eq "${expected_exit}" ]; then
    printf "%sPASS%s\n" "${GREEN}" "${NC}"
    ((pass++)) || true
  else
    printf "%sFAIL%s (expected exit %d, got %d)\n" "${RED}" "${NC}" "${expected_exit}" "${actual_exit}"
    ((fail++)) || true
  fi
}

assert_output() {
  local description="$1"
  local expected_output="$2"
  shift 2

  printf "%-55s" "${description}"
  actual_output=$("$@" 2>/dev/null) || true

  if [ "${actual_output}" = "${expected_output}" ]; then
    printf "%sPASS%s\n" "${GREEN}" "${NC}"
    ((pass++)) || true
  else
    printf "%sFAIL%s\n" "${RED}" "${NC}"
    printf "  expected: %s\n" "${expected_output}"
    printf "  got:      %s\n" "${actual_output}"
    ((fail++)) || true
  fi
}

tmp_dir=$(mktemp -d) || exit
trap 'rm -rf "${tmp_dir}"' EXIT

printf "=== pwqfilter rockyou.pwq tests ===\n"
printf "Filter:    %s\n" "${FILTER}"
printf "Capacity:  %d (expected)\n\n" "${EXPECTED_CAPACITY}"

# ---------------------------------------------------------------------------
# 1. Filter file basics
# ---------------------------------------------------------------------------
printf "[filter file]\n"
assert "Filter file exists" 0 test -f "${FILTER}"

# Expected file size: 64-byte header + 14700000 * 4 = 58800064
expected_size=$(( 64 + EXPECTED_CAPACITY * 4 ))
file_size=$(stat -c%s "${FILTER}" 2>/dev/null || stat -f%z "${FILTER}")
assert "Filter file size is ${expected_size} bytes" 0 test "${file_size}" -eq "${expected_size}"

# ---------------------------------------------------------------------------
# 2. Status
# ---------------------------------------------------------------------------
printf "\n[status]\n"
assert "Status reports success" 0 \
  "${PWQFILTER_BIN}" --status --filter="${FILTER}"

status_output=$("${PWQFILTER_BIN}" --status --filter="${FILTER}" 2>&1)

# Verify capacity matches
reported_capacity=$(echo "${status_output}" | grep -oP 'Capacity \K[0-9]+')
assert "Capacity is ${EXPECTED_CAPACITY}" 0 \
  test "${reported_capacity}" -eq "${EXPECTED_CAPACITY}"

# Verify load is in the expected range (14344391 / 14700000 ≈ 97.6%)
load_pct=$(echo "${status_output}" | grep -oP 'load \K[0-9]+(?=\.\d+%)')
assert "Load is above 95%" 0 test "${load_pct}" -ge 95

# ---------------------------------------------------------------------------
# 3. Lookup — well-known rockyou passwords (positive)
# ---------------------------------------------------------------------------
printf "\n[lookup positive]\n"
for word in "123456" "password" "iloveyou" "princess" "rockyou" "abc123" "nicole" "jessica" "monkey" "ashley"; do
  assert_output "Lookup '${word}' found" "${word}" \
    sh -c "echo '${word}' | ${PWQFILTER_BIN} --filter='${FILTER}' --lookup"
done

# Entries from deeper in the list
for word in "jimmyisno1" "arisha55" "05448708072"; do
  assert_output "Lookup '${word}' found (deep)" "${word}" \
    sh -c "echo '${word}' | ${PWQFILTER_BIN} --filter='${FILTER}' --lookup"
done

# ---------------------------------------------------------------------------
# 4. Lookup — strings that should NOT be in rockyou (negative)
# ---------------------------------------------------------------------------
printf "\n[lookup negative]\n"
for word in \
  "ThisPasswordIsDefinitelyNotInRockyou_2026!" \
  "kd82!Zmq@4xR#pLw9Yv" \
  "correct horse battery staple xkcd" \
  "fjölnir-íslandskt-lykilorð-42"; do
  assert_output "Lookup not in list" "" \
    sh -c "echo '${word}' | ${PWQFILTER_BIN} --filter='${FILTER}' --lookup"
done

# ---------------------------------------------------------------------------
# 5. Batch lookup — sample from the wordlist if available
# ---------------------------------------------------------------------------
printf "\n[lookup count]\n"
if [ -f "${ROCKYOU_BZ2}" ] && command -v bzcat >/dev/null 2>&1; then
  # Pick 100 random lines from the wordlist
  bzcat "${ROCKYOU_BZ2}" | shuf -n 100 > "${tmp_dir}/sample_positive.txt"
  sample_count=$(wc -l < "${tmp_dir}/sample_positive.txt")

  assert_output "Count matches from ${sample_count} random lines" "${sample_count}" \
    sh -c "cat '${tmp_dir}/sample_positive.txt' | ${PWQFILTER_BIN} --filter='${FILTER}' --count"
else
  printf "%-55s%s\n" "Batch sample (skipped, no wordlist)" "SKIP"
fi

assert_output "Count 0 for strings not in list" "0" \
  sh -c "printf 'xyzzy_not_here_1\nxyzzy_not_here_2\n' | ${PWQFILTER_BIN} --filter='${FILTER}' --count"

# ---------------------------------------------------------------------------
# 6. Inverted lookup
# ---------------------------------------------------------------------------
printf "\n[lookup invert-match]\n"
assert_output "Inverted: known word produces no output" "" \
  sh -c "echo 'password' | ${PWQFILTER_BIN} -v --filter='${FILTER}'"

assert_output "Inverted: unknown word is returned" "xyzzy_not_here" \
  sh -c "echo 'xyzzy_not_here' | ${PWQFILTER_BIN} -v --filter='${FILTER}'"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== Results: %d passed, %d failed ===\n" "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
