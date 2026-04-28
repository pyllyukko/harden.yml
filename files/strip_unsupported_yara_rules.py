#!/usr/bin/env python3
"""Strip YARA rules that ClamAV cannot load.

By default this performs *static* analysis on each rule and removes
rules that ClamAV's YARA subset will reject at compile time.  The
detection rules are derived from ``libclamav/readdb.c``,
``libclamav/yara_compiler.c`` and ``libclamav/yara_lexer.l`` in the
ClamAV source tree and from the error messages observed when running
``clamscan --debug`` against yara-forge's ``yara-rules-core.yar``.

Categories detected:

  1. ``private`` / ``global`` rule modifiers
     – ClamAV warns and skips these (``readdb.c:3884``/``3888``).
  2. References to YARA modules ClamAV does not link in
     (``pe``, ``hash``, ``math``, ``elf``, ``dotnet``, ``magic``,
     ``cuckoo``, ``androguard``, ``console``, ``time``, ``dex``,
     ``macho``, ...) and the big-endian ``uintNbe``/``intNbe``
     helpers – any use raises ``undefined identifier "X"``
     (``yara_compiler.c``).
  3. ``import "..."`` statements – ClamAV ships with no YARA modules
     so any import returns ``ERROR_UNKNOWN_MODULE``.
  4. Empty string literals (``$x = ""`` / ``$x = ''``) – rejected by
     the lexer as ``empty string`` (``yara_lexer.l``).
  5. Hex strings whose first or last fixed-byte segment contains only
     a single byte adjacent to a jump – ``Single byte subpatterns
     unsupported in ClamAV`` (``readdb.c:3651``).
  6. Hex strings with a ranged jump (``[N]`` / ``[N-M]``) inside an
     alternative (``( ... | ... )``) – ``Alternative match contains
     unsupported ranged wildcard`` (``readdb.c:773``).
  7. Rules with more than 64 declared strings – ``too many subsigs``.

In addition, ``--from-log LOG`` may be passed to also remove rules
matched by parsing one or more clamscan/clamd debug logs (legacy
behaviour; useful for catching cascade failures such as rules that
reference an already-skipped private rule).

The original file is preserved as ``<file>.bak`` (unless
``--no-backup``).

Usage:
    strip_unsupported_yara_rules.py RULES.yar [--from-log LOG ...]
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from collections import Counter
from pathlib import Path

RULE_START_RE = re.compile(
    r"^\s*(?P<mods>(?:private\s+|global\s+)+)?rule\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
RULE_END_RE = re.compile(r"^\}\s*$")

# Modules / external symbols that this ClamAV build does not provide.
# These are matched only when used in module/function context
# (``module.attr`` or ``func(...)``), so meta keys named ``hash =`` or
# ``time =`` are not false positives.
FORBIDDEN_MODULES = (
    "pe", "elf", "hash", "math", "dotnet", "magic", "cuckoo",
    "androguard", "console", "time", "dex", "macho", "cape",
)
FORBIDDEN_FUNCS = (
    "uint8be", "uint16be", "uint32be",
    "int8be", "int16be", "int32be",
)
# ``module.`` access — e.g. ``pe.section_index``.
MODULE_USE_RE = re.compile(
    r"(?<![A-Za-z0-9_$])(" + "|".join(FORBIDDEN_MODULES) + r")\s*\."
)
# ``func(`` calls — e.g. ``uint16be(0)``.
FUNC_USE_RE = re.compile(
    r"(?<![A-Za-z0-9_$])(" + "|".join(FORBIDDEN_FUNCS) + r")\s*\("
)

IMPORT_RE = re.compile(r'^\s*import\s+"[^"]+"')

# Detect log error patterns (legacy --from-log mode).
YYERROR_LINE_RE = re.compile(r"yyerror\(\):\s+\S+\s+line\s+(\d+)\b")
SKIPPING_RULE_RE = re.compile(r"skipping\s+YARA\.([A-Za-z_][A-Za-z0-9_]*)")

# String modifiers ClamAV's YARA fork does not recognise; using any of
# them produces "syntax error, unexpected _IDENTIFIER_, expecting
# _CONDITION_".  Match them as a token following a string assignment.
UNSUPPORTED_STRING_MODIFIERS = ("xor", "base64", "base64wide", "private")
STRING_MOD_RE = re.compile(
    r'\$[A-Za-z0-9_]*\s*=\s*(?:"(?:\\.|[^"\\])*"|\{[^}]*\}|/(?:\\.|[^/\\\n])+/[a-z]*)'
    r'(?:\s+[A-Za-z]+)*\s+(' + "|".join(UNSUPPORTED_STRING_MODIFIERS) + r')\b',
)


# ---------------------------------------------------------------------------
# rule indexing
# ---------------------------------------------------------------------------

def index_rules(lines: list[str]) -> list[tuple[int, int, str]]:
    """Return ``[(start, end, name), ...]`` (1-based, inclusive).

    Brace depth is tracked so that a literal ``}`` at column 0 inside a
    multi-line hex string (e.g. ``$chunk_1 = {\\n...\\n}``) does not
    terminate the rule prematurely.  Quoted strings and comments are
    skipped when counting braces.
    """
    rules: list[tuple[int, int, str]] = []
    i = 0
    n = len(lines)
    while i < n:
        m = RULE_START_RE.match(lines[i])
        if not m:
            i += 1
            continue
        start = i + 1
        name = m.group("name")
        # Find the rule body's opening ``{`` — may be on same line as
        # ``rule X { ... `` or on a following line.
        depth = 0
        opened = False
        j = i
        while j < n:
            stripped = sanitize(lines[j])
            for ch in stripped:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
            if opened and depth == 0:
                break
            j += 1
        if j >= n:
            print(
                f"warning: unterminated rule {name!r} starting at line {start}",
                file=sys.stderr,
            )
            break
        rules.append((start, j + 1, name))
        i = j + 1
    return rules


# ---------------------------------------------------------------------------
# rule-body sanitisation: strip comments and string literals so the
# static checks don't trip on them.
# ---------------------------------------------------------------------------

def _blank_quoted(text: str) -> str:
    """Blank out double-quoted strings (preserving the quotes) **without**
    stripping comments.  Used as a pre-pass when we need to inspect raw
    text — e.g. searching for ``//`` inside hex strings (which our
    ``sanitize`` routine would otherwise remove)."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == "\n":
                    break
                j += 1
            if j < n and text[j] == '"':
                out.append('""')
                i = j + 1
                continue
            out.append('"')
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def sanitize(text: str, *, keep_strings: bool = False) -> str:
    """Strip ``//`` and ``/* ... */`` comments, and (optionally) blank
    out the contents of double-quoted string literals while preserving
    the surrounding quotes.

    A single pass over the input that respects string-literal boundaries
    so that ``//`` inside ``"https://..."`` is not mistaken for a
    comment, and a ``"`` inside ``// "x"`` does not start a string.

    YARA only uses double-quoted strings (single quotes are not string
    literals), and regex literals ``/.../`` are also recognised so a
    ``//`` immediately after ``=`` does not eat the rest of the line.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    # Track the last emitted non-whitespace char so we can disambiguate
    # ``/`` as the start of a regex literal vs division.
    last_sig = "\n"
    REGEX_PREV = set("=(,[|:!&\n")
    while i < n:
        c = text[i]
        # block comment
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            if end < 0:
                break
            out.append(" ")
            i = end + 2
            continue
        # line comment
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i + 2)
            if end < 0:
                break
            i = end  # keep the newline
            continue
        # regex literal: /.../[ismx]*  — only when we're in a token
        # position where a regex can legitimately start.  This blanks out
        # the body (preserving length) so any ``{``/``}``/``"`` inside
        # don't confuse brace counting or string detection downstream.
        if c == "/" and last_sig in REGEX_PREV:
            j = i + 1
            ok = False
            while j < n and text[j] != "\n":
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == "/":
                    ok = True
                    break
                j += 1
            if ok:
                # consume regex body (replace with spaces, keep delimiters)
                out.append("/")
                out.append(" " * (j - i - 1))
                out.append("/")
                k = j + 1
                while k < n and text[k].isalpha():
                    out.append(text[k])
                    k += 1
                last_sig = "/"
                i = k
                continue
        # double-quoted string
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == "\n":
                    break
                j += 1
            if j < n and text[j] == '"':
                if keep_strings:
                    out.append(text[i:j + 1])
                else:
                    out.append('""')
                i = j + 1
                last_sig = '"'
                continue
            # unterminated; emit the bare quote and advance
            out.append('"')
            i += 1
            last_sig = '"'
            continue
        out.append(c)
        if not c.isspace():
            last_sig = c
        elif c == "\n":
            last_sig = "\n"
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# hex string parsing
# ---------------------------------------------------------------------------

HEX_BYTE_RE = re.compile(r"\?\?|[0-9A-Fa-f]\?|\?[0-9A-Fa-f]|[0-9A-Fa-f]{2}")
JUMP_RE = re.compile(r"\[\s*\d+\s*(?:-\s*\d+\s*)?\]")
# A regex string assignment used with the ``wide`` modifier — clamav
# warns: "wide modifier [w] is not supported for regex subsigs".
REGEX_WIDE_RE = re.compile(
    r"\$[A-Za-z0-9_]*\s*=\s*/(?:\\.|[^/\\\n])+/[a-z]*\s+[a-z\s]*\bwide\b",
)


def _tokenise_hex(body: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    i = 0
    n = len(body)
    while i < n:
        c = body[i]
        if c.isspace():
            i += 1
            continue
        if c == "[":
            m = JUMP_RE.match(body, i)
            if m:
                tokens.append(("JUMP", m.group(0)))
                i = m.end()
                continue
            i += 1
            continue
        if c == "(":
            depth = 1
            j = i + 1
            while j < n and depth:
                if body[j] == "(":
                    depth += 1
                elif body[j] == ")":
                    depth -= 1
                j += 1
            tokens.append(("GROUP", body[i + 1:j - 1]))
            i = j
            continue
        m = HEX_BYTE_RE.match(body, i)
        if m:
            tok = m.group(0)
            kind = "FIXED" if re.fullmatch(r"[0-9A-Fa-f]{2}", tok) else "WILD"
            tokens.append((kind, tok))
            i = m.end()
            continue
        i += 1
    return tokens


def _has_two_consecutive_fixed(tokens: list[tuple[str, str]]) -> bool:
    """Return True if ``tokens`` contains two adjacent FIXED bytes
    somewhere, treating GROUP elements as opaque (each branch of a
    GROUP is checked recursively)."""
    # Linear scan: any two adjacent FIXEDs?
    for i in range(len(tokens) - 1):
        if tokens[i][0] == "FIXED" and tokens[i + 1][0] == "FIXED":
            return True
    # No direct pair — but a GROUP whose every branch has 2 adjacent
    # FIXEDs *and* the surrounding context is connected through it
    # could still pass.  Conservative: only count GROUP as good if each
    # branch independently contains 2 adjacent FIXEDs.
    for t, v in tokens:
        if t == "GROUP":
            branches = _split_group_branches(v)
            if branches and all(
                _has_two_consecutive_fixed(_tokenise_hex(b)) for b in branches
            ):
                return True
    return False


def _split_group_branches(group_body: str) -> list[str]:
    """Split ``group_body`` (inside of a ``(...)``) on top-level ``|``."""
    out: list[str] = []
    depth = 0
    last = 0
    for i, ch in enumerate(group_body):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            out.append(group_body[last:i])
            last = i + 1
    out.append(group_body[last:])
    return out


def _segments(tokens: list[tuple[str, str]]) -> list[list[tuple[str, str]]]:
    """Split ``tokens`` on JUMP boundaries."""
    segs: list[list[tuple[str, str]]] = []
    cur: list[tuple[str, str]] = []
    for t, v in tokens:
        if t == "JUMP":
            segs.append(cur)
            cur = []
        else:
            cur.append((t, v))
    segs.append(cur)
    return segs


def hex_unsupported_reasons(hex_body: str) -> list[str]:
    reasons: list[str] = []
    body = sanitize(hex_body, keep_strings=False)

    # 1. Ranged wildcard inside alternative.
    depth = 0
    group_start = -1
    for idx, ch in enumerate(body):
        if ch == "(":
            if depth == 0:
                group_start = idx
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and group_start >= 0:
                inside = body[group_start + 1:idx]
                if JUMP_RE.search(inside):
                    reasons.append("hex: ranged wildcard inside alternative")
                    break

    tokens = _tokenise_hex(body)

    # 2. Each segment between jumps must contain >=2 adjacent fixed
    #    bytes; otherwise clamav fails with "Can't find a static
    #    subpattern of length 2" / "Signature ... is too short".
    segs = _segments(tokens)
    if len(segs) > 1:
        bad = False
        for seg in segs:
            if not seg:
                # empty segment between two jumps is fine; clamav merges
                continue
            # Strict: require two adjacent FIXED bytes at the TOP level
            # of the segment.  Earlier we recursed into GROUP branches
            # but clamav still fails when a segment is a single GROUP
            # (the filter cannot derive a deterministic 2-byte prefix).
            seg_pair = any(
                seg[i][0] == "FIXED" and seg[i + 1][0] == "FIXED"
                for i in range(len(seg) - 1)
            )
            if not seg_pair:
                bad = True
                break
        if bad:
            reasons.append("hex: segment between jumps lacks 2 fixed bytes")

    # 3. Single-byte first/last fixed segment adjacent to a jump
    #    (kept distinct because parse_yara_hex_string rejects this with
    #    a different error).
    if any(t == "JUMP" for t, _ in tokens):
        leading: list[tuple[str, str]] = []
        for t, v in tokens:
            if t == "JUMP":
                break
            leading.append((t, v))
        trailing: list[tuple[str, str]] = []
        for t, v in reversed(tokens):
            if t == "JUMP":
                break
            trailing.append((t, v))
        if len(leading) == 1 and leading[0][0] in ("FIXED", "WILD"):
            if "hex: segment between jumps lacks 2 fixed bytes" not in reasons:
                reasons.append("hex: single-byte segment before first jump")
        if len(trailing) == 1 and trailing[0][0] in ("FIXED", "WILD"):
            if "hex: segment between jumps lacks 2 fixed bytes" not in reasons:
                reasons.append("hex: single-byte segment after last jump")

    # 4. Whole hex string with no two adjacent FIXED bytes at the top
    #    level (e.g. back-to-back alternations like ``33 (43|63)
    #    (3533|3733) ...``).  ClamAV's filter cannot derive a 2-byte
    #    deterministic substring even though each branch internally has
    #    fixed bytes — error: "string failed test insertion" /
    #    "Subpattern ... shorter than the minimum depth of the AC trie
    #    (1 < 2)".
    has_top_pair = any(
        tokens[i][0] == "FIXED" and tokens[i + 1][0] == "FIXED"
        for i in range(len(tokens) - 1)
    )
    if not has_top_pair and any(t == "GROUP" for t, _ in tokens):
        reasons.append("hex: no 2 adjacent fixed bytes at top level")

    return reasons


def find_hex_strings(rule_body: str) -> list[str]:
    results: list[str] = []
    # find lines like:  $name = { ... }
    # hex strings can span multiple lines, so search globally.
    i = 0
    n = len(rule_body)
    while i < n:
        # find "= {"
        eq = rule_body.find("=", i)
        if eq < 0:
            break
        # walk past whitespace
        k = eq + 1
        while k < n and rule_body[k] in " \t":
            k += 1
        if k < n and rule_body[k] == "{":
            # find matching closing brace; hex strings may contain
            # nested () but never nested {} except inside jump syntax,
            # which uses [].
            end = rule_body.find("}", k + 1)
            if end < 0:
                break
            results.append(rule_body[k + 1:end])
            i = end + 1
        else:
            i = eq + 1
    return results


# ---------------------------------------------------------------------------
# per-rule analysis
# ---------------------------------------------------------------------------

# Allowed escape sequences in clamav YARA double-quoted strings.
_ALLOWED_STR_ESCAPES = set('\\"tn')  # \\ \" \t \n
_HEX_RE = re.compile(r"x[0-9A-Fa-f]{2}")


def _iter_string_literals(text: str) -> list[str]:
    """Yield the *contents* (no surrounding quotes) of every double-quoted
    string literal in ``text``.  Comments are stripped first; the
    literal terminates at the next un-escaped ``"`` or newline."""
    cleaned = sanitize(text, keep_strings=True)
    out: list[str] = []
    i = 0
    n = len(cleaned)
    while i < n:
        c = cleaned[i]
        if c == '"':
            j = i + 1
            while j < n and cleaned[j] != '"':
                if cleaned[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if cleaned[j] == "\n":
                    break
                j += 1
            if j < n and cleaned[j] == '"':
                out.append(cleaned[i + 1:j])
                i = j + 1
                continue
        i += 1
    return out


def _bad_escape(s: str) -> str | None:
    """Return the offending escape (without leading ``\\``) if ``s``
    contains any escape sequence rejected by clamav, else ``None``."""
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            nxt = s[i + 1]
            if nxt in _ALLOWED_STR_ESCAPES:
                i += 2
                continue
            if nxt == "x" and _HEX_RE.match(s, i + 1):
                i += 4
                continue
            return nxt if nxt != "\n" else "\\n-literal"
        i += 1
    return None


def _decoded_len(s: str) -> int:
    """Approximate decoded byte length of a string-literal body for
    LEX_BUF_SIZE comparison.  Each ``\\xNN`` and other allowed escape
    counts as 1 byte; unknown escapes count as 1."""
    i = 0
    n = len(s)
    out = 0
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            if s[i + 1] == "x" and _HEX_RE.match(s, i + 1):
                i += 4
            else:
                i += 2
            out += 1
            continue
        i += 1
        out += 1
    return out


def analyse_rule(text: str, *, strict_empty_string: bool = True) -> list[str]:
    """Return list of failure reasons for this rule body
    (empty list = supported).

    ``strict_empty_string=True`` (the default) removes rules containing
    an empty ``""`` literal *anywhere* in the rule.  ClamAV >= 1.5
    actually loads such rules, but it spams ``LibClamAV Error:
    yyerror(): ... empty string`` for every occurrence.  Pass
    ``False`` to keep those rules at the cost of noisy clamscan
    output.
    """
    reasons: list[str] = []
    raw = text

    # 1. Rule modifiers.
    #    NOTE: ClamAV 1.5.x silently accepts ``private`` and ``global``
    #    rule modifiers (they have no runtime effect for clamav scans
    #    but the rules still load).  We therefore no longer reject
    #    them.  See tests/test_clamav_yara_unsupported.sh for the
    #    canary that will detect any future change in behaviour.

    # 2. import statements.
    #    A bare ``import "pe"`` is silently accepted by ClamAV; it is
    #    only the *use* of an unknown module symbol (e.g.
    #    ``pe.entry_point``) that fails to load.  That use is already
    #    detected via FORBIDDEN_MODULES in step 4 below, so we no
    #    longer reject every rule that imports something.

    # Build two views:
    #   keep_only:  comments stripped but string literal contents kept.
    #               Used for empty-string detection and to find hex
    #               strings (which contain no string literals anyway).
    #   code_only:  comments stripped AND string literal contents
    #               replaced with "" so identifier scans don't match
    #               text inside strings.
    keep_only = sanitize(raw, keep_strings=True)
    code_only = sanitize(raw, keep_strings=False)

    # 3. Empty string literal.
    #    ClamAV's YARA lexer rejects ``$x = ""`` in the strings:
    #    section outright, and prints a noisy ``yyerror(): ... empty
    #    string`` line for every ``""`` elsewhere (meta etc.) even
    #    though the rule still loads.  Scan the whole rule when
    #    strict_empty_string is set; otherwise only the strings:
    #    section.
    if strict_empty_string:
        if re.search(r'(?<!\\)""', keep_only):
            reasons.append('empty string ("")')
    else:
        in_strings = False
        for line in keep_only.splitlines():
            bare = line.strip()
            if bare.startswith("strings:"):
                in_strings = True
                continue
            if bare.startswith("condition:"):
                in_strings = False
                continue
            if in_strings and re.search(r'(?<!\\)""', line):
                reasons.append('empty string ("")')
                break

    # 4. Forbidden module / helper identifiers.
    found = set()
    for tok in MODULE_USE_RE.findall(code_only):
        found.add(tok)
    for tok in FUNC_USE_RE.findall(code_only):
        found.add(tok)
    for tok in sorted(found):
        reasons.append(f'undefined identifier "{tok}"')

    # 5. Too many strings (clamav max subsigs = 64).
    string_count = 0
    in_strings = False
    has_strings_section = False
    for line in code_only.splitlines():
        bare = line.strip()
        if bare.startswith("strings:"):
            in_strings = True
            has_strings_section = True
            continue
        if bare.startswith("condition:"):
            in_strings = False
            continue
        if in_strings and re.match(r"\s*\$[A-Za-z0-9_]*\s*=", line):
            string_count += 1
    if string_count > 64:
        reasons.append(f"too many subsigs ({string_count} > 64)")
    # ClamAV's YARA loader requires every rule to contain at least one
    # string it can match against (it uses the AC trie for everything).
    # A condition that only inspects ``uint*()``/``filesize`` with no
    # ``strings:`` section produces "yara rule contains no supported
    # strings, skipping ...".
    if not has_strings_section:
        reasons.append("no strings: section")

    # 6/7. Hex strings.
    for hx in find_hex_strings(code_only):
        for r in hex_unsupported_reasons(hx):
            reasons.append(r)
    # ClamAV's YARA lexer rule for hex strings (yara_lexer.l:552) only
    # allows hex digits, whitespace, `-`, `|`, `?`, `[]`, `()`.  A `/`
    # inside `{ ... }` (e.g. an embedded `//` line comment, which
    # standard YARA permits but clamav does not) makes the whole hex
    # string fail to lex.  Run this check on the comment-preserving
    # view.
    raw_keep = _blank_quoted(raw)
    for hx in find_hex_strings(raw_keep):
        if "/" in hx:
            reasons.append("hex: unsupported character '/' inside hex string")
            break

    # 8. ``wide`` modifier on regex string — clamav only supports
    #    ``wide`` on text/hex strings.
    if REGEX_WIDE_RE.search(code_only):
        reasons.append("regex string with `wide` modifier")

    # 9. Unsupported string modifiers (xor, base64, base64wide,
    #    private).
    for m in STRING_MOD_RE.finditer(sanitize(raw, keep_strings=True)):
        reasons.append(f"unsupported string modifier `{m.group(1)}`")
        break

    # 10. Over-long string literals.
    #     ClamAV's YARA lexer caps decoded string-literal length at
    #     LEX_BUF_SIZE = 1024 bytes; longer literals raise
    #     "out of space in lex_buf".
    #     NOTE: The lexer also accepts only the escapes
    #     ``\\ \" \t \n \xNN`` and warns on others, but the warning is
    #     non-fatal in ClamAV >= 1.5 -- the rule still loads and
    #     matches.  The illegal-escape canary in
    #     tests/test_clamav_yara_unsupported.sh will fire if that ever
    #     becomes fatal again.
    for slit in _iter_string_literals(raw):
        if _decoded_len(slit) >= 1024:
            reasons.append("string literal too long for lex_buf (>=1024)")
            break

    # de-dup while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# log parsing (legacy --from-log mode)
# ---------------------------------------------------------------------------

def parse_logs(paths: list[Path]) -> tuple[set[int], set[str]]:
    bad_lines: set[int] = set()
    bad_names: set[str] = set()
    for p in paths:
        text = p.read_bytes().decode("utf-8", errors="replace")
        text = text.replace("\r", "\n")
        for m in YYERROR_LINE_RE.finditer(text):
            bad_lines.add(int(m.group(1)))
        for m in SKIPPING_RULE_RE.finditer(text):
            bad_names.add(m.group(1))
    return bad_lines, bad_names


def find_rule_for_line(
    rules: list[tuple[int, int, str]], lineno: int
) -> tuple[int, int, str] | None:
    for start, end, name in rules:
        if start <= lineno <= end:
            return start, end, name
    return None


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("rules", type=Path, help="path to the .yar file to clean")
    ap.add_argument(
        "--from-log",
        type=Path,
        action="append",
        default=[],
        metavar="LOG",
        help="also remove rules referenced by errors in this clamscan "
             "debug log (may be passed multiple times)",
    )
    ap.add_argument(
        "--no-static",
        action="store_true",
        help="skip static analysis (only useful with --from-log)",
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="write cleaned rules here (default: overwrite input in place)",
    )
    ap.add_argument(
        "--no-backup",
        action="store_true",
        help="do not create <rules>.bak when overwriting in place",
    )
    ap.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="report what would be removed but do not write any file",
    )
    ap.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print every removed rule and reason",
    )
    ap.add_argument(
        "--allow-empty-strings",
        action="store_true",
        help="keep rules containing empty \"\" literals outside the "
             "strings: section (clamav loads them but logs a noisy "
             "yyerror() for each occurrence)",
    )
    args = ap.parse_args()

    if not args.rules.is_file():
        ap.error(f"no such file: {args.rules}")
    for log in args.from_log:
        if not log.is_file():
            ap.error(f"no such file: {log}")
    if args.no_static and not args.from_log:
        ap.error("--no-static requires at least one --from-log")

    raw = args.rules.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines(keepends=True)

    rules = index_rules(lines)
    if not rules:
        print("error: no rules found in input", file=sys.stderr)
        return 1
    print(f"indexed {len(rules)} rules in {args.rules}", file=sys.stderr)

    # name -> (start, end, name)
    by_name = {name: (s, e, name) for (s, e, name) in rules}

    # rule -> list[reason]
    removals: dict[str, list[str]] = {}

    # ---- static analysis ----
    if not args.no_static:
        for s, e, name in rules:
            body = "".join(lines[s - 1:e])
            reasons = analyse_rule(
                body,
                strict_empty_string=not args.allow_empty_strings,
            )
            if reasons:
                removals[name] = reasons
        print(
            f"static analysis: flagged {len(removals)} rules",
            file=sys.stderr,
        )

    # ---- cascade: rules referencing rules we have already removed ----
    # When a rule is removed, any other rule whose condition references
    # the removed rule by name gets `undefined identifier "<name>"` at
    # load time.  Iterate to a fixed point.
    if not args.no_static and removals:
        before_cascade = len(removals)
        while True:
            removed_names = set(removals.keys())
            name_pat = re.compile(
                r"(?<![A-Za-z0-9_$])("
                + "|".join(re.escape(n) for n in removed_names)
                + r")(?![A-Za-z0-9_])"
            )
            new_cascades: dict[str, str] = {}
            for s, e, name in rules:
                if name in removals:
                    continue
                body = "".join(lines[s - 1:e])
                code_only = sanitize(body, keep_strings=False)
                refs = set(name_pat.findall(code_only)) - {name}
                if refs:
                    new_cascades[name] = sorted(refs)[0]
            if not new_cascades:
                break
            for name, ref in new_cascades.items():
                removals[name] = [f"references removed rule '{ref}'"]
        added = len(removals) - before_cascade
        if added:
            print(
                f"cascade analysis: flagged {added} additional rules",
                file=sys.stderr,
            )

    # ---- log-driven ----
    if args.from_log:
        bad_lines, bad_names = parse_logs(args.from_log)
        print(
            f"log parse: {len(bad_lines)} yyerror line refs and "
            f"{len(bad_names)} 'skipping YARA.*' names",
            file=sys.stderr,
        )
        unmatched_lines: list[int] = []
        for ln in sorted(bad_lines):
            hit = find_rule_for_line(rules, ln)
            if hit is None:
                unmatched_lines.append(ln)
                continue
            removals.setdefault(hit[2], []).append("log: yyerror")
        unknown_names: list[str] = []
        for name in sorted(bad_names):
            if name in by_name:
                removals.setdefault(name, []).append("log: skipping YARA.*")
            else:
                unknown_names.append(name)
        if unmatched_lines:
            print(
                f"warning: {len(unmatched_lines)} log line refs did not map to "
                f"any rule (e.g. {unmatched_lines[:5]})",
                file=sys.stderr,
            )
        if unknown_names:
            print(
                f"warning: {len(unknown_names)} 'skipping YARA.*' names not "
                f"present in the .yar (e.g. {unknown_names[:5]})",
                file=sys.stderr,
            )

    if not removals:
        print("nothing to remove; rules file is already clean", file=sys.stderr)
        return 0

    # tally
    reason_counter: Counter[str] = Counter()
    for rs in removals.values():
        for r in rs:
            reason_counter[r] += 1

    print(
        f"removing {len(removals)} of {len(rules)} rules",
        file=sys.stderr,
    )
    print("reasons:", file=sys.stderr)
    for reason, count in reason_counter.most_common():
        print(f"  {count:6d}  {reason}", file=sys.stderr)

    if args.verbose:
        print("\nremoved rules:", file=sys.stderr)
        for name in sorted(removals):
            s, e, _ = by_name[name]
            print(
                f"  - {name}  (lines {s}..{e}): {'; '.join(removals[name])}",
                file=sys.stderr,
            )

    if args.dry_run:
        return 0

    drop: set[int] = set()
    for name in removals:
        s, e, _ = by_name[name]
        for ln in range(s, e + 1):
            drop.add(ln)

    out_lines = [ln for i, ln in enumerate(lines, start=1) if i not in drop]
    out_text = "".join(out_lines)

    out_path = args.output or args.rules
    if out_path == args.rules and not args.no_backup:
        backup = args.rules.with_suffix(args.rules.suffix + ".bak")
        if not backup.exists():
            shutil.copy2(args.rules, backup)
            print(f"backup written to {backup}", file=sys.stderr)
        else:
            print(f"backup {backup} already exists; not overwriting",
                  file=sys.stderr)

    out_path.write_text(out_text, encoding="utf-8")
    print(
        f"wrote {out_path} ({len(out_lines)} lines, "
        f"removed {len(lines) - len(out_lines)})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
