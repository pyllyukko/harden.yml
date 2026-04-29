#!/bin/bash
#
# Regression canary for YARA features that ClamAV does *not* support
# (and that strip_unsupported_yara_rules.py therefore strips).  For
# each category we feed clamscan one tiny rule exercising just that
# feature and assert ClamAV refuses to load it.  If a rule starts
# loading successfully, ClamAV has gained support for that feature
# and we should relax the corresponding stripper check so more
# YARA-Forge rules can be kept.
#
# Exit codes:
#   0  all unsupported features still rejected (expected)
#   1  one or more features are now supported (review the stripper)
#   2  environment problem (clamscan missing, etc.)

set -u

if ! command -v clamscan >/dev/null 2>&1
then
  echo "[-] clamscan not installed" 1>&2
  exit 2
fi

if ! command -v yara >/dev/null 2>&1
then
  echo "[-] yara not installed" 1>&2
  exit 2
fi

clamscan --version
yara --version

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

# Payload to scan; content is irrelevant -- we only care about loading.
printf 'harmless\n' > "${tmp}/payload.bin"

# Reusable big literal for the lex_buf-overflow fixture.
big_string="$(printf 'A%.0s' {1..1100})"

# ---------------------------------------------------------------------------
# Build the fixtures: one .yar per category in ${tmp}/fixtures/.
# Each rule has at least one supported string in its strings: section,
# so the *only* reason clamscan should reject the rule is the feature
# the fixture is testing.
#
# Categories ClamAV 1.5.x already accepts (and that the stripper
# therefore *does not* reject) are intentionally NOT included here:
#
#   - ``private`` rule modifier
#   - ``global``  rule modifier
#   - bare ``import "X"`` with no use of ``X.something``
#   - empty ``""`` literal in ``meta:`` (only ``""`` in ``strings:`` is fatal)
#   - ``\h`` and other illegal escapes (lexer warns, rule still loads)
#
# If ClamAV ever starts rejecting any of those again we will notice
# via the ansible-playbook workflow loading fewer YARA Forge rules
# than expected.
# ---------------------------------------------------------------------------

mkdir -p "${tmp}/fixtures"

# An ``import`` is silently accepted by ClamAV when the module is
# never referenced; the rule has to actually USE the module symbol
# for the load to fail.
cat > "${tmp}/fixtures/01_undefined_module_pe.yar" <<'YAR'
import "pe"
rule canary_import_pe
{
  strings:
    $a = "harmless"
  condition:
    pe.entry_point > 0 and $a
}
YAR

cat > "${tmp}/fixtures/02_undefined_module_math.yar" <<'YAR'
rule canary_math_module
{
  strings:
    $a = "harmless"
  condition:
    math.entropy(0, filesize) > 7.0 and $a
}
YAR

cat > "${tmp}/fixtures/03_undefined_module_hash.yar" <<'YAR'
rule canary_hash_module
{
  strings:
    $a = "harmless"
  condition:
    hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e" and $a
}
YAR

cat > "${tmp}/fixtures/04_undefined_module_console.yar" <<'YAR'
rule canary_console_module
{
  strings:
    $a = "harmless"
  condition:
    console.log("hi") and $a
}
YAR

cat > "${tmp}/fixtures/05_undefined_func_uint32be.yar" <<'YAR'
rule canary_uint32be_func
{
  strings:
    $a = "harmless"
  condition:
    uint32be(0) == 0x7B5C7274 and $a
}
YAR

# Empty string literal must be in the strings: section to fail loading.
cat > "${tmp}/fixtures/06_empty_string_in_strings.yar" <<'YAR'
rule canary_empty_string_in_strings
{
  strings:
    $a = ""
    $b = "harmless"
  condition:
    $b
}
YAR

# clamav cap: max 64 subsigs per rule.  65 strings should make load fail.
{
  echo 'rule canary_too_many_subsigs'
  echo '{'
  echo '  strings:'
  for i in $(seq 1 65); do
    # shellcheck disable=SC2016  # $s%02d is a printf format, not a variable
    printf '    $s%02d = "marker_%02d"\n' "${i}" "${i}"
  done
  echo '  condition:'
  echo '    any of them'
  echo '}'
} > "${tmp}/fixtures/07_too_many_subsigs.yar"

cat > "${tmp}/fixtures/08_no_strings_section.yar" <<'YAR'
rule canary_no_strings
{
  condition:
    filesize > 0
}
YAR

cat > "${tmp}/fixtures/09_hex_with_slash_comment.yar" <<'YAR'
rule canary_hex_with_slash
{
  strings:
    $a = { 4D 5A // looks like an MZ
           90 00 }
  condition:
    $a
}
YAR

cat > "${tmp}/fixtures/10_regex_wide_modifier.yar" <<'YAR'
rule canary_regex_wide
{
  strings:
    $r = /harm[a-z]+/ wide
  condition:
    $r
}
YAR

cat > "${tmp}/fixtures/11_string_modifier_xor.yar" <<'YAR'
rule canary_string_modifier_xor
{
  strings:
    $a = "harmless" xor
  condition:
    $a
}
YAR

cat > "${tmp}/fixtures/12_string_modifier_base64.yar" <<'YAR'
rule canary_string_modifier_base64
{
  strings:
    $a = "harmless" base64
  condition:
    $a
}
YAR

cat > "${tmp}/fixtures/13_string_modifier_private.yar" <<'YAR'
rule canary_string_modifier_private
{
  strings:
    $a = "harmless" private
  condition:
    $a
}
YAR

cat > "${tmp}/fixtures/14_string_too_long.yar" <<YAR
rule canary_string_too_long
{
  strings:
    \$a = "${big_string}"
  condition:
    \$a
}
YAR

cat > "${tmp}/fixtures/15_hex_alt_no_filter.yar" <<'YAR'
rule canary_hex_alt_no_filter
{
  strings:
    $h = { 68 (01|02) 00 00 80 }
  condition:
    $h
}
YAR

# Sanity fixture: a trivial rule that *must* load successfully.  If
# this one breaks, the test environment is wrong, not the stripper.
cat > "${tmp}/fixtures/00_sanity_loadable.yar" <<'YAR'
rule canary_sanity_loadable
{
  strings:
    $a = "harmless"
  condition:
    $a
}
YAR

# ---------------------------------------------------------------------------
# Two-stage check for each fixture:
#   1. ``yara``      MUST accept the fixture (otherwise the fixture
#                    itself is buggy -- it should exercise a feature
#                    that real YARA supports but ClamAV does not).
#   2. ``clamscan``  MUST reject the fixture (otherwise ClamAV has
#                    gained support for the feature and the matching
#                    check in the stripper can be relaxed).
# ---------------------------------------------------------------------------

regressions=()
yara_broken=()
fixtures=("${tmp}"/fixtures/*.yar)
total=${#fixtures[@]}
ok=0

for fx in "${fixtures[@]}"
do
  name="$(basename "${fx}" .yar)"

  # Step 1: verify the fixture is a *valid* YARA rule with the
  # reference compiler.  If yara itself can't compile/load the rule
  # then the fixture is buggy and the clamscan result below would be
  # meaningless.
  yara_out="$(yara "${fx}" "${tmp}/payload.bin" 2>&1)"
  yara_rc=$?
  # yara exits 0 on match, 1 on no-match; anything else (compile
  # error, fatal) means the rule is not a valid yara rule.
  if [ "${yara_rc}" -ne 0 ] && [ "${yara_rc}" -ne 1 ]
  then
    printf '[-] %-38s fixture rejected by yara 4.x (exit %d): %s\n' \
      "${name}" "${yara_rc}" "${yara_out}" 1>&2
    yara_broken+=("${name}")
    continue
  fi

  # Step 2: feed the same fixture to clamscan and check the rule
  # is *not* loaded.  clamscan exit codes do not distinguish "rule
  # failed to load" from "no match", so we parse the
  # ``Known viruses: N`` line:
  #   N == 0  --> rule was rejected (expected for unsupported features)
  #   N >= 1  --> ClamAV now supports this feature (regression canary fires)
  out="$(clamscan --database="${fx}" "${tmp}/payload.bin" 2>&1 || true)"
  loaded="$(printf '%s\n' "${out}" | sed -n 's/^Known viruses: \([0-9]\+\)$/\1/p' | head -n1)"

  if [ "${name}" = "00_sanity_loadable" ]
  then
    if [ "${loaded:-0}" -ge 1 ]
    then
      printf '[+] %-38s sanity rule loaded (Known viruses: %s)\n' "${name}" "${loaded}"
      ok=$((ok + 1))
    else
      echo "[-] sanity rule failed to load -- broken test environment" 1>&2
      printf '%s\n' "${out}" 1>&2
      exit 2
    fi
    continue
  fi

  if [ "${loaded:-0}" -eq 0 ]
  then
    printf '[+] %-38s correctly rejected by clamav\n' "${name}"
    ok=$((ok + 1))
  else
    printf '[!] %-38s NOW LOADS (Known viruses: %s) -- clamav added support?\n' "${name}" "${loaded}"
    regressions+=("${name}")
  fi
done

echo
echo "[*] ${ok}/${total} fixtures behaved as expected"

if [ "${#yara_broken[@]}" -gt 0 ]
then
  echo "[-] The following fixtures could not be compiled by yara:" 1>&2
  printf '    - %s\n' "${yara_broken[@]}" 1>&2
  echo 1>&2
  echo "[-] These fixtures are buggy -- fix them so they exercise" 1>&2
  echo "    a YARA feature that real yara accepts but clamscan does not." 1>&2
  exit 2
fi

if [ "${#regressions[@]}" -gt 0 ]
then
  echo "[-] The following fixtures unexpectedly loaded:" 1>&2
  printf '    - %s\n' "${regressions[@]}" 1>&2
  echo 1>&2
  echo "[-] ClamAV likely added support for one or more YARA features." 1>&2
  echo "    Re-evaluate the matching check in strip_unsupported_yara_rules.py" 1>&2
  echo "    so that more YARA-Forge rules can be kept." 1>&2
  exit 1
fi

exit 0
