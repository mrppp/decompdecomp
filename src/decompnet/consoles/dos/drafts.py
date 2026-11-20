"""Ghidra's drafts of a DOS game's functions, in the project's C: briefs show them, and autopilot tries them.

Ghidra drafts each function of a delinked target object (forks/ghidra.py decompile_object) without the game around
it, and with Watcom's spellings: a function is func_0001A2B0_ (register convention) or _func_0001A2B0 (stack), a
global __D_0001A2B0 where it's read or written as a word and _D_0001A2B0 where its address is taken. Ghidra has no
Watcom calling convention: it reads a register function's arguments as GCC's __regparm3 (eax, edx, ecx), which is
Watcom's (eax, edx, ebx, ecx) for up to two, so a draft with three or more register arguments isn't compilable as
it stands (its third would come from the wrong register).
"""

from __future__ import annotations

import re

GHIDRA_HEADER = "ghidra.h"
GHIDRA_H = """/* Ghidra's names for the types and operations it can't tell yet, so its machine drafts compile as they are:
 * autopilot tries them (`#include "ghidra.h"`). The game's own types are better: agents write those in common.h. */
#ifndef GHIDRA_H
#define GHIDRA_H

typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined3;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned char byte;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned short word;
typedef unsigned int uint;
typedef unsigned int uint3;
typedef unsigned long ulong;
typedef unsigned int dword;
typedef long long longlong;
typedef unsigned long long ulonglong;
typedef unsigned long long qword;
typedef long double float10;
typedef int code();

#define CONCAT11(a, b) ((unsigned short)(((unsigned short)(unsigned char)(a) << 8) | (unsigned char)(b)))
#define CONCAT22(a, b) ((unsigned int)(((unsigned int)(unsigned short)(a) << 16) | (unsigned short)(b)))
#define CONCAT31(a, b) ((unsigned int)(((unsigned int)(a) << 8) | (unsigned char)(b)))
#define CONCAT13(a, b) ((unsigned int)(((unsigned int)(unsigned char)(a) << 24) | ((unsigned int)(b) & 0xffffff)))
#define SUB41(x, n) ((unsigned char)((unsigned int)(x) >> ((n) * 8)))
#define SUB42(x, n) ((unsigned short)((unsigned int)(x) >> ((n) * 8)))
#define ZEXT14(x) ((unsigned int)(unsigned char)(x))
#define ZEXT24(x) ((unsigned int)(unsigned short)(x))
#define SEXT14(x) ((int)(signed char)(x))
#define SEXT24(x) ((int)(short)(x))

#endif
"""
# What no C stands for: registers read before they're set, its stack view, partial variables, flag helpers
_UNWRITABLE = re.compile(r"\b(unaff_\w+|in_stack_\w+|extraout_\w+|in_E[ABCD]X|in_E[SD]I|in_EBP|in_ESP|in_[A-Z]{2}\b|"
                         r"stack0x\w+|halt_baddata|swi|LOCK|UNLOCK|CARRY\d|SCARRY\d|SBORROW\d|POPCOUNT|"
                         r"in\(|out\()\b|\.\_\d+_\d+_")
_FUNC = re.compile(r"\b_?(func_[0-9A-Fa-f]{8})_?(?:@\d+)?(?![\w@])")
_DATA = re.compile(r"\b(_{1,2})(D_[0-9A-Fa-f]{8})\b")
_HEAD = re.compile(r"^(?P<ret>[^\n;{}]*?)\s*\b(?P<conv>__cdecl|__stdcall|__fastcall|__regparm\d)?\s*"
                   r"(?P<name>_?func_(?P<addr>[0-9A-Fa-f]{8})_?(?:@\d+)?)\s*\((?P<params>[^()]*)\)\s*\{", re.M)


def adapt(text: str) -> str:
    """A draft as the project's C spells its names: func_0001A2B0 and D_0001A2B0."""
    text = re.sub(r"/\* WARNING: Globals starting with '_' overlap[^*]*\*/\s*", "", text)
    text = _DATA.sub(lambda m: m.group(2), text)
    return _FUNC.sub(lambda m: m.group(1), text)


# Watcom's register arguments, in order: what Ghidra calls a register it saw read before it was set, when it's one
WATCOM_ARGS = ("EAX", "EDX", "EBX", "ECX")


def _register_arguments(body: str, params: list[str]) -> tuple[str, list[str]]:
    """A register function's arguments past Ghidra's (__regparm3 reads two as Watcom passes them): an unaff_EBX,
    or in_EBX, it reads before setting is Watcom's third, unaff_ECX its fourth (the arguments before it given as
    int where Ghidra saw none)."""
    for k in (2, 3):
        reg = WATCOM_ARGS[k]
        local = re.search(rf"^[ \t]*(?P<type>[\w ]+?)\s*(?P<ptr>\**)\s*(?:unaff|in)_{reg};[ \t]*\n", body, re.M)
        if local is None:
            continue
        while len(params) < k:
            params.append(f"int param_{len(params) + 1}")
        if len(params) > k:
            break
        name = f"param_{k + 1}"
        params.append(f"{local.group('type').strip()} {local.group('ptr')}{name}")
        body = body[:local.start()] + body[local.end():]
        body = re.sub(rf"\b(?:unaff|in)_{reg}\b", name, body)
    return body, params


def compilable(draft: str, symbol: str, stack: dict[str, str], known: str = "") -> tuple[str, str] | None:
    """Ghidra's draft (as it gave it) as C that compiles in the function's source file, (prelude, definition), or None.
    `symbol`: its Watcom symbol (_func_X@8: __stdcall); `stack`: the C name of each of the game's stack-convention
    functions -> its keyword (__cdecl, __stdcall), for the calls to them; `known`: the header and file's text, whose
    declarations are used as they are."""
    text = re.sub(r"/\*.*?\*/", "", adapt(draft), flags=re.S)  # (briefs' drafts come adapted already)
    head = _HEAD.search(text)
    if head is None:
        return None
    body = text[head.end():].rstrip()
    if not body.endswith("}"):
        return None
    params = [p.strip() for p in head.group("params").split(",") if p.strip() not in ("", "void")]
    conv = head.group("conv") or ""
    is_stack = symbol.startswith("_")
    if not is_stack and len(params) > 2 and conv.startswith("__regparm"):
        return None  # its third argument: GCC's ecx, Watcom's ebx
    if not is_stack:
        body, params = _register_arguments(body, params)
    if _UNWRITABLE.search(body):
        return None
    if conv == "__fastcall" or (conv == "__stdcall" and "@" not in symbol):
        return None
    name = f"func_{head.group('addr').upper()}"
    ret = head.group("ret").strip() or "void"
    globals_: dict[str, str] = {}
    for m in re.finditer(r"(&?)\b(D_[0-9A-F]{8})\b", body):
        # Ghidra takes the address of a global it sees as bytes (&_D_...), and reads a word as itself (__D_...)
        kind = "undefined1" if m.group(1) else "undefined4"
        if globals_.setdefault(m.group(2), kind) != kind:
            return None  # read as a word and as a byte: Ghidra's view of it isn't one C declaration
    callees = sorted({m.group(1) for m in _FUNC.finditer(body)} - {name})
    lines = []
    for callee in callees:
        if not re.search(rf"\b{callee}\s*\(", known):
            lines.append(f"int {stack[callee] + ' ' if callee in stack else ''}{callee}();")
    for g, kind in sorted(globals_.items()):
        if not re.search(rf"\b{g}\b", known):
            lines.append(f"extern {kind} {g};")
    prelude = "\n".join([f'#include "{GHIDRA_HEADER}"', *lines]) + "\n"
    keyword = ("__stdcall " if "@" in symbol else "__cdecl ") if is_stack else ""
    definition = f"{ret} {keyword}{name}({', '.join(params) or 'void'})\n{{{body[:-1]}}}\n"
    return prelude, definition
