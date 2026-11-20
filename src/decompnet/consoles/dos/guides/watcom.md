# Watcom C for 32-bit DOS (DOS/4GW games)

Which compiler builds your file: the project's (Watcom 9.5, 10.x or OpenWatcom 2) or the file's own (get_function
and compiler_map say). Watcom 9.5 and 10.x are 1993-95 compilers: write C89 for them.

C89 for Watcom 9.5 and 10.x (a file that doesn't build costs you an attempt)
- Declare every function before its first use, or the file stops: `Error! E1011: Symbol 'func_00011310' has not
  been declared`. Put prototypes at the top of the file or in a header it includes.
- Declarations only at the start of a block, before any statement; no `for (int i = 0; ...)`.
- No `long long`, `bool`, `true`/`false`, `inline`, `//` after a statement on the same line in old headers, `stdint.h`
  or designated initialisers. Use `int`, `short`, `char`, `unsigned`, and the types in common.h.
- A function returning nothing is `void f(void)`; an empty parameter list `f()` declares no parameters at all.

Registers and calls (Watcom's register convention, the default)
- Arguments in eax, edx, ebx, ecx, in that order; more on the stack, which the callee takes off (`ret N`).
- The result in eax. A function keeps every other register: it pushes what it uses (`push edx` ... `pop edx`).
  Old Watcom (9.5, 10.x) keeps eax too in a `void` function, writing through edx instead: if the original uses edx
  for a store where you'd expect eax, the function returns nothing.
- Its symbol is `func_XXXXXXXX_`; in C you write `func_XXXXXXXX`.
- `__cdecl` functions (symbol `_func_XXXXXXXX`) read their arguments from the stack ([esp+4], or [ebp+8] with a
  frame) and the caller cleans up. `__stdcall` ones (`_func_XXXXXXXX@8`) take them off themselves (`ret 8`): declare
  and define them with the keyword, `int __stdcall func_0001051B(short a, int b)`, and every call to them too.
- The order a call loads its arguments in (eax before edx, or edx first) is the compiler's, not your C's: when only
  that differs, the file's compiler is the wrong one (try_compiler), not the C.

Frames, flags and the same C coming out differently
- No frame by default: locals and arguments are esp-relative. A function that starts `push ebp; mov ebp, esp`
  (55 89 E5) was built with -of (a frame kept), usually with -os -s (for size, no stack checks): a library's code
  often was. search_flags tries those; a file keeps the flags its functions match with.
- `push N; call __CHK` at a function's start is a stack check: the original had them on (flags without -s).
- -ox optimises for speed: loops unrolled, `xor eax, eax`, `lea` arithmetic; -os keeps code short.
- Inline assembly is C here: Watcom's `#pragma aux` puts instructions into the functions that call a name (a game's
  fixed-point multiply `imul ebx` / `shrd eax, edx, 16` everywhere), and `inp`/`outp`/`_disable`/`_enable` are
  intrinsics. Write the call the original source made (`FixedMul(a, b)` with its `#pragma aux` in a header), not
  the instructions.

Data
- The game's data is `D_XXXXXXXX` (extern, by address): `extern int D_00071168;`. Name and type it in a header
  once its purpose is clear (rename_symbol), so every file gets it.
- Ghidra's drafts read a global as a word when they write `D_...` and as bytes when they take `&D_...`: the real
  type is in the code (`movsx` is a signed short or char, `movzx` unsigned).
