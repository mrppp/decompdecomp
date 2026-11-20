"""A 32-bit DOS game's functions cut into ELF32 objects, one per source file, as Watcom's compiled objects read
once converted (omf.py): what objdiff compares with what the project's C compiles to.

Each function gets a section of its own, so where it sits in a file never moves what its calls name (the lesson of
an Xbox 360 game whose matches reopened when leaves were added between them). Its relocations say what its code
refers to, as a compiled object's do:
- every address the LE module fixes up (le.py: exact, nothing guessed) is an R_386_32 to what is there: a function
  (its symbol, plus how far in), the program's data at that address (`_D_XXXXXXXX`, C's `D_XXXXXXXX`, as the PC
  console names data), or a place in the function itself (its jump tables: a local label);
- every call and jump out of the function (relative, so never fixed up) is an R_386_PC32 to its target's symbol.
A function's symbol is its C name as Watcom spells it: `func_XXXXXXXX_` for the register convention Watcom
defaults to, `_func_XXXXXXXX` for a stack-convention one (it reads its arguments from [ebp+8] on: __cdecl), and
`_func_XXXXXXXX@8` for one that also takes them off the stack as it returns (`ret 8`: __stdcall). A shareware game's
sound library is __stdcall code Watcom built with a frame (-of) and for size (-os), whose `push ebp; mov ebp, esp`
is 55 89 E5 (Watcom's encoding as GNU as's: it isn't GCC's code).
"""

from __future__ import annotations

import bisect
import struct
from dataclasses import dataclass, field

import capstone
from capstone import x86 as cs_x86

from . import omf
from .le import OFFSET32, Module

_CS = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
_CS.detail = True
UNIT_BYTES = 0x1000  # a source file: neighbouring functions of about this many bytes
GAP_BYTES = 0x400  # a hole this big between functions starts another file


@dataclass
class Function:
    addr: int
    size: int
    name: str  # C name: func_XXXXXXXX
    convention: str = "register"  # Watcom's default; "stack": __cdecl, or __stdcall where `pops`; "plain": -5s's own
    relocs: list[tuple[int, int, str | None, int]] = field(default_factory=list)  # (offset, R_386_*, symbol, addend)
    pops: int = 0  # the bytes of arguments a stack-convention function takes off as it returns (__stdcall: ret 8)

    @property
    def symbol(self) -> str:
        return watcom_symbol(self.name, self.convention, self.pops)


def watcom_symbol(name: str, convention: str, pops: int = 0) -> str:
    """How Watcom spells a function's C name: name_ (register convention), _name (__cdecl), _name@8 (__stdcall),
    and name as it is in a game built with the stack convention (-3s to -6s: "plain", Watcom's own stack-based
    convention, the caller taking the arguments off)."""
    if convention == "plain":
        return name
    if convention != "stack":
        return f"{name}_"
    return f"_{name}@{pops}" if pops else f"_{name}"


def pops(mod: Module, addr: int, size: int) -> int:
    """The bytes a function's `ret N` takes off the stack (0: a plain ret)."""
    o = mod.object_at(addr)
    if o is None:
        return 0
    for ins in _CS.disasm(o.data[addr - o.base:addr - o.base + size], addr):
        if ins.id == cs_x86.X86_INS_RET and ins.operands:
            return ins.operands[0].imm
    return 0


def data_symbol(addr: int) -> str:
    """The program's data at an address, as Watcom spells C's D_XXXXXXXX (an underscore in front, like MSVC's)."""
    return f"_D_{addr:08X}"


def convention(mod: Module, addr: int, size: int) -> str:
    """"stack" when the function sets up a frame and reads an argument above its return address ([ebp+8] on), the
    way a cdecl or hand-written function takes its arguments; Watcom's own functions take theirs in registers."""
    o = mod.object_at(addr)
    if o is None:
        return "register"
    code = o.data[addr - o.base:addr - o.base + min(size, 64)]
    # push ebp; mov ebp, esp, as Microsoft encodes it (8B EC) or Watcom and GNU as do (89 E5)
    if not code.startswith((b"\x55\x8b\xec", b"\x55\x89\xe5")):
        return "register"
    for ins in _CS.disasm(code, addr):
        for op in ins.operands:
            if op.type == cs_x86.X86_OP_MEM and op.mem.base == cs_x86.X86_REG_EBP and op.mem.disp >= 8:
                return "stack"
    return "register"


def functions(mod: Module, found: list[tuple[int, int]], default: str = "register") -> list[Function]:
    """Functions with their names, conventions and relocations (`mod` relocated, `found` from dosfind). `default`:
    the convention the game was built with (its library code says: watcomlib.best). A stack-convention game's
    functions are all stack ones (most read their arguments from esp, with no frame to tell them by)."""
    def made(a: int, n: int) -> Function:
        if default == "stack":  # its own convention's are plain; one that takes its arguments off is __stdcall
            p = pops(mod, a, n)
            return Function(a, n, f"func_{a:08X}", "stack" if p else "plain", pops=p)
        conv = convention(mod, a, n)
        return Function(a, n, f"func_{a:08X}", conv, pops=pops(mod, a, n) if conv == "stack" else 0)
    out = [made(a, n) for a, n in sorted(found)]
    starts = [f.addr for f in out]
    by_addr = {f.addr: f for f in out}
    code = [o for o in mod.objects if o.executable]

    def in_code(a: int) -> bool:
        return any(o.base <= a < o.base + o.size for o in code)

    def owner(a: int) -> Function | None:
        i = bisect.bisect_right(starts, a) - 1
        return out[i] if i >= 0 and a < out[i].addr + out[i].size else None

    fixups = sorted((f.source, f.target) for f in mod.fixups if f.kind == OFFSET32)
    sources = [s for s, _ in fixups]
    for fn in out:
        lo, hi = fn.addr, fn.addr + fn.size
        relocs = []
        fixed = set()
        for k in range(bisect.bisect_left(sources, lo), bisect.bisect_left(sources, hi - 3)):
            src, target = fixups[k]
            fixed.update(range(src, src + 4))
            if lo <= target < hi:
                relocs.append((src - lo, omf.R_386_32, None, target - lo))  # a label in the function itself
            elif in_code(target) and (t := owner(target)) is not None:
                relocs.append((src - lo, omf.R_386_32, t.symbol, target - t.addr))
            else:
                relocs.append((src - lo, omf.R_386_32, data_symbol(target), 0))
        o = mod.object_at(lo)
        if o is None:
            continue
        for ins in _CS.disasm(o.data[lo - o.base:hi - o.base], lo):
            if ins.size < 5 or ins.id not in (cs_x86.X86_INS_CALL, cs_x86.X86_INS_JMP) or not ins.operands:
                continue
            op = ins.operands[0]
            field_at = ins.address + ins.size - 4
            if op.type != cs_x86.X86_OP_IMM or field_at in fixed:
                continue
            target = op.imm & 0xFFFFFFFF
            if lo <= target < hi:
                continue
            t = by_addr.get(target) or owner(target)
            if t is None:
                continue
            relocs.append((field_at - lo, omf.R_386_PC32, t.symbol, target - t.addr))
        fn.relocs = sorted(relocs)
    return out


def units(fns: list[Function]) -> dict[str, list[Function]]:
    """Source files: runs of neighbouring functions of about UNIT_BYTES, split where a big hole parts them."""
    out: dict[str, list[Function]] = {}
    cur: list[Function] = []
    for fn in fns:
        if cur and (fn.addr + fn.size - cur[0].addr > UNIT_BYTES or fn.addr - (cur[-1].addr + cur[-1].size) > GAP_BYTES):
            out[f"text_{cur[0].addr:08X}"] = cur
            cur = []
        cur.append(fn)
    if cur:
        out[f"text_{cur[0].addr:08X}"] = cur
    return out


def elf(mod: Module, fns: list[Function]) -> bytes:
    """One ELF32 i386 relocatable object of `fns`, a section each, REL relocations with their addends in place."""
    segments = []
    publics = []
    externs: list[str] = []
    for i, fn in enumerate(fns):
        o = mod.object_at(fn.addr)
        if o is None:
            raise ValueError(f"{fn.name} is in no object of the module")
        data = bytearray(o.data[fn.addr - o.base:fn.addr - o.base + fn.size])
        seg = omf.Segment(f"_TEXT_{fn.name}", "CODE", fn.size, 16, data)
        for off, rtype, name, addend in fn.relocs:
            value = addend - 4 if rtype == omf.R_386_PC32 else addend  # (PC32 counts from the field's start)
            struct.pack_into("<i" if value < 0 else "<I", data, off, value)
            if name is None:  # a label in this function: its own section's symbol, the addend says where
                seg.relocs.append((off, rtype, ("seg", i)))
                continue
            if name not in externs:
                externs.append(name)
            seg.relocs.append((off, rtype, ("ext", externs.index(name))))
        segments.append(seg)
        publics.append((fn.symbol, i, 0, True))
    module = omf.Module(segments, publics, externs)
    return omf.to_elf(module)
