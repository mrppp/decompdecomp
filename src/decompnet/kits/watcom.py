"""Watcom C, the user's own copies: the compilers DOS games of 1993-1997 were built with (Watcom C/C++ 9.5, 10.0,
10.5, 10.6 and 11.0, and Open Watcom 1.x after them). The DOS console builds with OpenWatcom 2 (toolchains.toml), a
descendant whose code differs in places: an old Watcom keeps eax in a `void` function (push edx; xor edx, edx ...
pop edx), where OpenWatcom 2 uses eax freely, and no flag or pragma of OpenWatcom 2's gives that back. A game's
functions that differ that way match only with its own compiler.

A copy is a Watcom folder as its installer laid it out, or as its CD holds it (Watcom 10.0's has WATCOM/ uncompressed:
that folder will do): binnt/wcc386.exe (the Windows-hosted compiler; Open Watcom's core is in binnt/wccd386.dll,
Watcom 10's is binb/wcc386.exe, which the launcher in binnt loads) and h/ (its headers). Its version is the one the compiler prints, read from those files
("Watcom C32 Optimizing Compiler Version 10.6"). On Linux and macOS it runs through wine: wibo can't run it (it calls
GetOEMCP, which wibo hasn't). Tried under wine with Watcom C/C++ 9.5b (installed with its own installer, NT host
chosen), 10.0a (its CD) and OpenWatcom 2's own binnt build. A shareware game of 1993 was built with 9.5: its calls'
arguments and its void functions' registers come out as 9.5b's, not 10.0a's or OpenWatcom 2's.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import Kit, OwnCompiler, file_version, find

BANNER = re.compile(rb"(Open )?Watcom C(?:32| x86 32-bit) Optimizing Compiler\s*(?:Version\s+)?(\d+\.\d+[A-Za-z]?)", re.I)
# where a copy's compiler keeps its banner: Open Watcom's in binnt, Watcom 10's in binb (the compiler itself, in
# Watcom's own LX format: binnt/wcc386.exe is a small Windows launcher that loads it)
HOLDS_BANNER = ("binnt/wccd386.dll", "binnt/wcc386.exe", "binb/wcc386.exe", "binw/wcc386.exe")


class Watcom(Kit):
    id = "watcom"
    name = "Watcom C (your own copy)"
    platform = "DOS"
    description = ("A Watcom C/C++ of your own (9.5 to 11.0, or Open Watcom 1.x) for the DOS games OpenWatcom 2 doesn't "
                   "build exactly: give its folder (the one with binnt and h). On Linux and macOS it runs through "
                   "wine.")
    files = ("binnt/wcc386.exe", "h/stdio.h")
    places = ("WATCOM", "watcom")

    def build(self, folder: Path) -> str | None:
        """Its version: "10.6", or "Open Watcom 1.9". From the compiler's version resource where it has one (Open
        Watcom's do: 2.0.27366.57404; Open Watcom numbers its releases from 1.0, Watcom's ran to 11.0), else from the
        banner it prints, where it's in the file as it is."""
        for rel in HOLDS_BANNER:
            path = find(folder, rel)
            if path is not None and (resource := file_version(path)):
                major, minor = (resource.split(".") + ["0"])[:2]
                return f"{'Open Watcom ' if int(major) < 9 else ''}{major}.{minor}"
        for rel in HOLDS_BANNER:
            path = find(folder, rel)
            if path is None:
                continue
            try:
                m = BANNER.search(path.read_bytes())
            except OSError:
                continue
            if m:
                version = m.group(2).decode()
                return f"Open Watcom {version}" if m.group(1) else version
        return None

    def compilers(self, folder: Path) -> list[OwnCompiler]:
        build, exe, h = self.build(folder), find(folder, "binnt/wcc386.exe"), find(folder, "h", dirs=True)
        if exe is None:
            return []
        build = build or "unknown"  # (offered all the same: its version only names it)
        number = build.split()[-1]
        version, name = (f"ow-{number}", f"your {build}") if build.startswith("Open") else \
            (f"watcom-{number}", f"your Watcom C32 {build}")
        return [OwnCompiler(version, name, exe, (h,) if h else (), runner="wine", build=build)]

    def verify(self, folder: Path) -> str:
        build = self.build(folder)
        return f"Watcom C32 {build}" if build else "its compiler doesn't say which version it is"


WATCOM = Watcom()
