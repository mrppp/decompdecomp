"""Renaming the callees an Xbox 360 project's C names by offset, once its target objects name them.

Before its targets carried relocations, a delinked function's call was a bare displacement, and Ghidra's drafts
(and so the agents' C) named the callee by where it landed in the object as Ghidra laid it out: `DAT_006cfe34`.
That name depends on the calling function's own place, so one name means different callees in different functions
of the same file (on one game, `DAT_006cfe34` was FUN_9291176c in one function and FUN_9291177c in the next).
With relocations the target names the callee itself, and the C has to say the same: each function's calls are
renamed inside that function only, by objdiff's pairing of the target's relocation with the C's, and a callee
the file declared at file scope under its old name is declared under its new one too, with the same prototype.
"""

from __future__ import annotations

import re

DEFINITION = re.compile(r"\b(\w+)\s*\([^;{}()]*(?:\([^;{}()]*\)[^;{}()]*)*\)\s*\{")
CALLS = ("b", "bl")


def _blank(text: str) -> str:
    """`text` with comments, strings and character literals blanked to spaces (same length), so braces and
    names inside them are not read as code."""
    out = []
    i, n = 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j < 0 else j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
        elif text[i] in "\"'":
            q, j = text[i], i + 1
            while j < n and text[j] != q:
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
        else:
            out.append(text[i])
            i += 1
            continue
        out.append(re.sub(r"[^\n]", " ", text[i:j]))
        i = j
    return "".join(out)


def function_spans(text: str) -> dict[str, tuple[int, int]]:
    """{function: (start, end)} for each definition in `text`, from its name to its closing brace."""
    code = _blank(text)
    spans: dict[str, tuple[int, int]] = {}
    for m in DEFINITION.finditer(code):
        depth, at = 0, m.end() - 1
        while at < len(code):
            if code[at] == "{":
                depth += 1
            elif code[at] == "}":
                depth -= 1
                if depth == 0:
                    break
            at += 1
        name = m.group(1)
        if name not in spans and name not in ("if", "for", "while", "switch", "do", "else", "return", "sizeof"):
            spans[name] = (m.start(1), at + 1)
    return spans


def plan(rows: list[tuple[str, str, str]], renamed: list[tuple[str, str]]) -> dict[str, str]:
    """{name in the C: the target's name} for one function, from its diff: only calls (b, bl), only a whole
    callee (no `+offset`: a call into a function's middle is no rename), and only a name that means one callee."""
    seen: dict[str, set[str]] = {}
    for mark, left, right in rows:
        if mark == " " or not left or left.split()[0] not in CALLS:
            continue
        for target, mine in renamed:
            if target in left and mine in right and "+" not in target:
                seen.setdefault(mine, set()).add(target)
    return {mine: next(iter(t)) for mine, t in seen.items() if len(t) == 1}


def rename(text: str, plans: dict[str, dict[str, str]]) -> str:
    """`text` with each function's `plans[function]` applied inside that function only, and a file-scope
    declaration of a renamed callee repeated under its new name (the file's own definitions are never renamed)."""
    spans = function_spans(text)
    defined = set(spans)
    edits = []  # (start, end, replacement), applied from the end
    added: dict[str, str] = {}  # new name -> old name whose file-scope declaration it copies
    for fn, names in plans.items():
        names = {old: new for old, new in names.items() if old not in defined and old != new}
        if fn not in spans or not names:
            continue
        start, end = spans[fn]
        pattern = re.compile(r"\b(" + "|".join(map(re.escape, sorted(names, key=len, reverse=True))) + r")\b")
        body, code = text[start:end], _blank(text[start:end])  # (names in comments and strings stay)
        parts, last = [], 0
        for m in pattern.finditer(code):
            parts += [body[last:m.start()], names[m.group(1)]]
            last = m.end()
        edits.append((start, end, "".join(parts) + body[last:]))
        for old, new in names.items():
            added.setdefault(new, old)
    out = text
    for start, end, body in sorted(edits, reverse=True):
        out = out[:start] + body + out[end:]
    # declarations at file scope (outside every function), cloned for the new names
    code = _blank(out)
    inside = [(s, e) for s, e in function_spans(out).values()]
    lines, at = [], 0
    for line in out.splitlines(keepends=True):
        lines.append((at, line))
        at += len(line)
    extra = []
    for new, old in added.items():
        if _declared_at_file_scope(code, new, inside):
            continue
        for pos, line in lines:
            if any(s <= pos < e for s, e in inside):
                continue
            if re.search(rf"\b{re.escape(old)}\s*\(", line) and line.rstrip().endswith(";"):
                extra.append((pos + len(line), re.sub(rf"\b{re.escape(old)}\b", new, line)))
                break
    for pos, line in sorted(extra, reverse=True):
        out = out[:pos] + (line if line.endswith("\n") else line + "\n") + out[pos:]
    return out


def _declared_at_file_scope(code: str, name: str, inside: list[tuple[int, int]]) -> bool:
    for m in re.finditer(rf"\b{re.escape(name)}\s*\(", code):
        if not any(s <= m.start() < e for s, e in inside):
            return True
    return False


def migrate(fp, protected: set[str], before: dict, log=print) -> str | None:
    """Rename the callees in every source file whose functions call them by offset, once the targets name them.

    `protected`: the functions that match now; a file whose renaming would cost one of them, or that no longer
    compiles with it, is put back. Each file's text goes into `before` ({path: text}) before the file is written,
    so a reimport that is taken back, or an error midway, puts the C back too. Returns what changed, as a sentence. Wine's compiler fails now and then on its own: a build is tried three
    times before it is believed.
    """
    from ...forks.objdiff import ObjdiffError
    from ...forks.project import ForkError

    def build(unit) -> bool:
        target = fp._target(unit.base)
        return any(fp.run(["ninja", target], log=lambda *_: None)[0] for _ in range(3))

    def judged(unit, sym):
        try:
            return fp.diff(unit, sym)
        except (ObjdiffError, ForkError):
            return None

    changed = names = reverted = 0
    for unit in fp.units():
        if unit.base is None or not unit.source:
            continue
        src = fp.root / unit.source
        if not src.is_file():
            continue
        text = src.read_text(encoding="utf-8", errors="replace")
        spans = function_spans(text)
        plans = {}
        for sym in spans:
            d = judged(unit, sym)
            if d is not None and d.match_percent is not None and not d.matched:
                if p := plan(d.rows, d.renamed):
                    plans[sym] = p
        if not plans:
            continue
        before.setdefault(src, text)

        def keeps(unit=unit, spans=spans) -> bool:  # it builds, and every function that matched still does
            return build(unit) and all(getattr(judged(unit, s), "matched", False) for s in spans if s in protected)

        src.write_text(rename(text, plans), encoding="utf-8")
        ok = keeps()
        if not ok and len(plans) > 1:
            # two functions' names for different callees can clash once renamed (one name declared two ways):
            # each function's renaming alone, kept where the file still builds and nothing it matched is lost
            src.write_text(text, encoding="utf-8")
            build(unit)
            kept_plans: dict[str, dict[str, str]] = {}
            for fn in sorted(plans, key=lambda f: f not in protected):  # (a matched function's first)
                trial = {**kept_plans, fn: plans[fn]}
                src.write_text(rename(text, trial), encoding="utf-8")
                if keeps():
                    kept_plans = trial
            src.write_text(rename(text, kept_plans), encoding="utf-8")
            ok = bool(kept_plans) and keeps()
            plans = kept_plans
        if not ok:
            src.write_text(text, encoding="utf-8")
            del before[src]
            build(unit)
            reverted += 1
            continue
        changed += 1
        names += sum(len(p) for p in plans.values())
    if not changed and not reverted:
        return None
    said = f"{names} callee name{'s' if names != 1 else ''} in {changed} source file{'s' if changed != 1 else ''} " \
           "renamed to the functions the calls reach"
    if reverted:
        said += f" ({reverted} file{'s' if reverted != 1 else ''} left as they were: renamed, they lost a match " \
                "or didn't compile)"
    log(said)
    return said
