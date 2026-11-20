"""The functions of a 32-bit DOS game (an LE module), found from its code and its fixups.

A DOS/4GW executable has no function table and no symbols, so starts come from evidence that names them: the entry
point, the target of every direct call (followed from what is already known, never from a linear sweep that
could read a jump table as code), and every code address the data holds (fixups from a data object into code: a
game's tables of function pointers), or that code loads as a value (`push offset f`, `mov reg, offset f`). A run of
fixups in code, four bytes apart, is a switch's jump table: its targets are inside a function, not starts. Each
function's extent is traced by following its jumps (and its switch tables) until every path ends in a return or a
jump out of it; it never runs into the next known start.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass

import capstone
from capstone import x86 as cs_x86

from .le import OFFSET32, Module

_CS = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
_CS.detail = True
JUMPS_COND = {cs_x86.X86_INS_JAE, cs_x86.X86_INS_JA, cs_x86.X86_INS_JBE, cs_x86.X86_INS_JB, cs_x86.X86_INS_JCXZ,
              cs_x86.X86_INS_JECXZ, cs_x86.X86_INS_JE, cs_x86.X86_INS_JGE, cs_x86.X86_INS_JG, cs_x86.X86_INS_JLE,
              cs_x86.X86_INS_JL, cs_x86.X86_INS_JNE, cs_x86.X86_INS_JNO, cs_x86.X86_INS_JNP, cs_x86.X86_INS_JNS,
              cs_x86.X86_INS_JO, cs_x86.X86_INS_JP, cs_x86.X86_INS_JS, cs_x86.X86_INS_LOOP, cs_x86.X86_INS_LOOPE,
              cs_x86.X86_INS_LOOPNE}
ENDS = {cs_x86.X86_INS_RET, cs_x86.X86_INS_RETF, cs_x86.X86_INS_IRET, cs_x86.X86_INS_IRETD, cs_x86.X86_INS_HLT}


@dataclass
class Found:
    starts: dict[int, str]  # start -> why ("entry", "call", "data pointer", "code pointer")
    functions: list[tuple[int, int]]  # (start, length), sorted
    tables: dict[int, list[int]]  # jump table address -> its targets
    unclear: list[int]  # starts whose code didn't decode to an end
    cut: list[int]  # functions whose traced code ran into another start: one of the two is wrong


_TABLES: dict[int, dict[int, list[int]]] = {}  # (find's jump tables, for _after_functions)


def _tables(mod: Module) -> dict[int, list[int]]:
    """Runs of three or more OFFSET32 fixups in code, 4 bytes apart, all targeting code: switch jump tables."""
    code = [o for o in mod.objects if o.executable]
    in_code = lambda a: any(o.base <= a < o.base + o.size for o in code)  # noqa: E731
    fx = [f for f in mod.fixups if f.kind == OFFSET32 and in_code(f.source) and in_code(f.target)]
    out: dict[int, list[int]] = {}
    run: list = []
    for f in fx + [None]:
        if f is not None and run and f.source == run[-1].source + 4:
            run.append(f)
            continue
        if len(run) >= 3:
            out[run[0].source] = [r.target for r in run]
        run = [f] if f is not None else []
    return out


FILLERS = {b"\x90", b"\x8b\xc0", b"\x8b\xd2", b"\x8d\x00", b"\x8d\x12", b"\x8d\x40\x00", b"\x8d\x52\x00",
           b"\x8d\x80\x00\x00\x00\x00", b"\x8d\x92\x00\x00\x00\x00", b"\x00"}  # nop, mov/lea reg,[reg], padding


def _skip_filler(data: bytes, at: int, end: int) -> int:
    while at < end:
        for f in sorted(FILLERS, key=len, reverse=True):
            if data[at:at + len(f)] == f and at + len(f) <= end:
                at += len(f)
                break
        else:
            return at
    return at


def _clean_end(o, start: int, limit: int, table_fields: set[int]) -> bool:
    """Whether the code at `start` decodes, without an invalid or privileged-looking byte, to a return or an
    unconditional jump before `limit`: what code reads like, and data rarely does."""
    at = start
    while at < limit:
        if at in table_fields:
            return False
        ins = next(_CS.disasm(o.data[at - o.base:at - o.base + 16], at, 1), None)
        if ins is None or ins.id in (cs_x86.X86_INS_INT3, cs_x86.X86_INS_IN, cs_x86.X86_INS_OUT, cs_x86.X86_INS_INSB,
                                     cs_x86.X86_INS_INSD, cs_x86.X86_INS_OUTSB, cs_x86.X86_INS_OUTSD):
            return False
        if ins.id in ENDS or ins.id == cs_x86.X86_INS_JMP:
            return True
        at += ins.size
    return False


def _after_functions(mod: Module, code: list, functions: list[tuple[int, int]], table_fields: set[int],
                     starts: dict[int, str]) -> list[int]:
    """Starts right after a known function's end (past its filler) whose code decodes to a proper end."""
    new = []
    for i, (start, length) in enumerate(functions):
        o = next(o for o in code if o.base <= start < o.base + o.size)
        nxt = functions[i + 1][0] if i + 1 < len(functions) else o.base + o.size
        nxt = min(nxt, o.base + o.size)
        at = _skip_filler(o.data[:nxt - o.base], start + length - o.base, nxt - o.base) + o.base
        if at < nxt and at not in starts and at not in table_fields and _clean_end(o, at, nxt, table_fields):
            new.append(at)
    # and right after a switch's jump table (a function's tables sit between it and the next function)
    for table, targets in _TABLES.get(id(mod), {}).items():
        o = next((o for o in code if o.base <= table < o.base + o.size), None)
        if o is None:
            continue
        end = table + 4 * len(targets)
        nxt = next((s for s, _ in functions if s >= end), o.base + o.size)
        at = _skip_filler(o.data[:nxt - o.base], end - o.base, nxt - o.base) + o.base
        if at < nxt and at not in starts and at not in table_fields and _clean_end(o, at, nxt, table_fields):
            new.append(at)
    if functions:  # (and the code object's first bytes, before any known function)
        for o in code:
            first = min((s for s, _ in functions if o.base <= s < o.base + o.size), default=o.base + o.size)
            at = _skip_filler(o.data[:first - o.base], 0, first - o.base) + o.base
            if at < first and at not in starts and _clean_end(o, at, first, table_fields):
                new.append(at)
    return new


def find(mod: Module) -> Found:
    """The functions of `mod` (relocated: its fixup fields hold their targets)."""
    code = [o for o in mod.objects if o.executable]

    def in_code(a: int) -> bool:
        return any(o.base <= a < o.base + o.size for o in code)

    def obj(a: int):
        return next(o for o in code if o.base <= a < o.base + o.size)

    tables = _tables(mod)
    _TABLES[id(mod)] = tables
    table_bytes = {t + 4 * k for t, targets in tables.items() for k in range(len(targets))}
    table_fields = {a + i for a in table_bytes for i in range(4)}
    starts: dict[int, str] = {}
    if in_code(mod.entry):
        starts[mod.entry] = "entry"
    for f in mod.fixups:
        if f.kind != OFFSET32 or not in_code(f.target):
            continue
        if not in_code(f.source):
            starts.setdefault(f.target, "data pointer")
    # code pointers: an instruction whose immediate is a fixed-up code address (push offset f / mov reg, offset f)
    fixed = {f.source: f for f in mod.fixups if f.kind == OFFSET32 and in_code(f.target) and in_code(f.source)
             and f.source not in table_fields}

    functions: list[tuple[int, int]] = []
    unclear: list[int] = []
    done: set[int] = set()
    queue = sorted(starts)
    calls: dict[int, int] = {}
    while True:
      while queue:
          start = queue.pop()
          if start in done:
              continue
          done.add(start)
          o = obj(start)
          seen: set[int] = set()
          todo = [start]
          end = start
          ok = True
          while todo:
              at = todo.pop()
              while at not in seen and in_code(at) and (at == start or at not in starts):
                  if at in table_fields:
                      break
                  ins = next(_CS.disasm(o.data[at - o.base:at - o.base + 16], at, 1), None)
                  if ins is None:
                      ok = False
                      break
                  seen.add(at)
                  end = max(end, at + ins.size)
                  for k in range(ins.size - 3):  # a pointer to code in its operand
                      if (f := fixed.get(at + k)) is not None and ins.id in (cs_x86.X86_INS_PUSH, cs_x86.X86_INS_MOV):
                          # (and code there: a hand-written library keeps variables in its code object, and
                          # `mov reg, offset var` reads just like a function pointer; five of one game's were zeros)
                          to = obj(f.target)
                          if f.target not in starts and _clean_end(to, f.target, to.base + to.size, table_fields) \
                                  and to.data[f.target - to.base:f.target - to.base + 2] != b"\0\0":
                              starts[f.target] = "code pointer"
                              queue.append(f.target)
                  if ins.id == cs_x86.X86_INS_CALL:
                      op = ins.operands[0]
                      if op.type == cs_x86.X86_OP_IMM and in_code(op.imm):
                          calls[at] = op.imm
                          if op.imm not in starts:
                              starts[op.imm] = "call"
                              queue.append(op.imm)
                  elif ins.id in ENDS:
                      break
                  elif ins.id == cs_x86.X86_INS_JMP:
                      op = ins.operands[0]
                      if op.type == cs_x86.X86_OP_IMM:
                          if in_code(op.imm) and op.imm not in starts and op.imm > start:
                              todo.append(op.imm)  # (a jump to another function's start is a tail call)
                      elif op.type == cs_x86.X86_OP_MEM and op.mem.disp in tables:
                          todo.extend(t for t in tables[op.mem.disp] if t not in starts)
                      break
                  elif ins.id in JUMPS_COND:
                      op = ins.operands[0]
                      if op.type == cs_x86.X86_OP_IMM and in_code(op.imm) and op.imm not in starts:
                          todo.append(op.imm)
                  at += ins.size
          if not ok:
              unclear.append(start)
          functions.append((start, end - start))
      # code after a known function (past its alignment filler) that decodes to a proper end is a function too:
      # Watcom lays functions end to end, and one reached only through a computed call is never traced to
      new = _after_functions(mod, code, sorted(functions), table_fields, starts)
      if not new:
          break
      for a in new:
          starts[a] = "after a function"
      queue = sorted(new)
    functions.sort()
    # a function never runs into the next start: one traced past it (a jump table's targets, say) stops there
    starts_sorted = sorted(starts)
    fixed_fns = []
    cut = []
    for start, length in functions:
        i = bisect.bisect_right(starts_sorted, start)
        nxt = starts_sorted[i] if i < len(starts_sorted) else start + length
        if nxt - start < length:
            cut.append(start)
        fixed_fns.append((start, min(length, nxt - start)))
    return Found(starts, fixed_fns, tables, unclear, cut)
