# Hiding Logic in C++ Exception Handlers: Reversing the `nothing` CTF Binary

I came across this challenge from CDDC CTF and the first reversing pass was honestly suspiciously boring. The binary presented itself as an "MD5 vector viewer", and most of the visible code really did look like it just indexed a table of MD5 constants. It even printed:

```text
There is no flag in this binary, good luck!
```

That was the trap. After reversing the normal `.text` code and finding almost nothing, the interesting part turned out to be in `.eh_frame`, the section used by the exception unwinder. The hidden logic was not a normal C++ `catch` block. It was a forged DWARF unwind expression attached to the `process_selection` function, and it silently changed the program state while a C++ exception was being unwound.

This post is written as a beginner-friendly introduction to that idea: what C++ exception handling is, why exception metadata is powerful, how this challenge hides a maze inside the unwinder, and how to solve it.

The recovered flag is:

```text
CDDC2026{863355e39e7c64d7}
```

## What Is Exception Handling?

Exception handling is a way for a program to say, "something unusual happened here, let another part of the program handle it."

In C++, the source-level version looks like this:

```cpp
try {
    value = numbers.at(index);
} catch (const std::out_of_range& e) {
    std::cout << "bad index\n";
}
```

When `numbers.at(index)` fails, it throws an exception. The program does not simply return from the function. Instead, the runtime walks back through the call stack until it finds a suitable handler. While doing that, it must restore registers, restore stack frames, run destructors, and eventually transfer control to a landing pad, which is the compiler-generated code behind a `catch` or cleanup block.

On Linux x86-64 C++ binaries, this is commonly implemented using the Itanium C++ ABI exception model. LLVM's exception handling documentation describes this as "zero-cost" exception handling because the normal path does not constantly check for exceptions. Instead, the compiler emits out-of-line metadata tables that are consulted only when an exception is thrown. See the [LLVM exception handling documentation](https://llvm.org/docs/ExceptionHandling.html), the [Itanium C++ ABI exception handling specification](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html), and MaskRay's excellent [C++ exception handling ABI writeup](https://maskray.me/blog/2020-12-12-c%2B%2B-exception-handling-abi).

Important sections you often see in ELF C++ binaries are:

- `.eh_frame`: call-frame/unwind information. It tells the unwinder how to recover the caller's register state.
- `.eh_frame_hdr`: a lookup table for `.eh_frame`.
- `.gcc_except_table`: language-specific exception tables, often called LSDA tables.
- `.text`: the normal executable code.

The important beginner takeaway is this: exception handling is not just "code in catch blocks". It also depends on metadata that the runtime trusts while unwinding the stack.

## Is This Specific to C++?

Not completely. Other languages and runtimes also use exceptions, stack unwinding, or unwind metadata. Even C binaries may contain unwind tables for debugging, profiling, backtraces, or cleanup mechanisms.

But C++ is a particularly good place to find this behavior because exceptions are a language feature, destructors must run correctly during unwinding, and C++ ABI compatibility requires a fairly rich runtime protocol. On Itanium ABI platforms, C++ exception handling uses personality functions such as `__gxx_personality_v0`, unwind APIs such as `_Unwind_RaiseException`, and tables such as `.eh_frame` and `.gcc_except_table`.

That is why C++ binaries are a natural target for this kind of trick.

## Why Can Exception Metadata Hide Logic?

The unwinder needs to answer questions like:

- Where is the caller's stack frame?
- What was the caller's return address?
- Where was register `rbx` saved?
- Should this frame run a cleanup or catch block?

DWARF call-frame information answers these questions using a compact bytecode language. The DWARF standard defines instructions such as `DW_CFA_val_expression`, which says: to recover a register, evaluate this DWARF expression. The DWARF expression language itself has stack operations, arithmetic, comparisons, and branches such as `DW_OP_bra`. See the [DWARF 5 standard](https://dwarfstd.org/doc/DWARF5.pdf), especially the call-frame information and expression sections.

Normally, compilers emit boring expressions like "the old `rbx` is stored at CFA-24". But if someone manually patches `.eh_frame`, the unwinder may evaluate a much more complicated expression. That expression can behave like hidden code.

That is what happens in this challenge.

## First Look at `nothing`

The binary is a statically linked Linux x86-64 ELF:

```text
ELF 64-bit LSB executable, x86-64, statically linked, not stripped
```

Interesting sections:

```text
.text              0x401140
.rodata            0x57b000
.eh_frame_hdr      0x59e61c
.eh_frame          0x5a7620
.gcc_except_table  0x5dadc0
```

Useful symbols:

```text
process_selection(unsigned long, unsigned long)  0x404990
main                                             0x404a90
md5_vectors                                      0x5ee538
```

The visible program is a menu:

```text
Enter MD5 vector and element of vector (0 to quit):
```

For valid indexes, `process_selection(row, col)` prints an MD5 constant and returns it. Then `main` updates a hidden state in `rbx`:

```text
rbx = rbx * 0x1337133713371337 + returned_md5_constant
```

For invalid indexes, `std::vector::at` throws `std::out_of_range`. `main` catches it and prints:

```text
invalid selection: 0x...
```

The visible catch block does not update `rbx`. That is what makes the hidden update so easy to miss.

## The Suspicious `.eh_frame` Entry

The FDE, or Frame Description Entry, for `process_selection` is absurdly large:

```text
FDE for pc=0x404990..0x404a89
length=0x5ed0
```

Inside it is a huge rule for recovering register 3, which is `rbx` on x86-64:

```text
DW_CFA_val_expression register 3, expression length 24225 bytes
```

That should immediately feel wrong. `process_selection` does not need a 24 KB expression just to describe how to restore `rbx`.

During normal execution, this expression is not used. But when `process_selection` throws an exception, the unwinder must virtually unwind out of that function and reconstruct the caller's register state. It asks `.eh_frame` how to restore `rbx`, evaluates the giant expression, and writes the result into the unwound context.

So the exception path secretly does this:

```text
rbx = hidden_dwarf_expression(old_rbx, row, col)
```

The main catch block then continues as if nothing strange happened.

## What The Hidden Expression Reads

In this binary, the DWARF expression uses three important registers:

- `reg3` or `rbx`: the old hidden state.
- `reg6` or `rbp`: the second input after subtracting 1.
- `reg15` or `r15`: the first input after subtracting 1.

The visible code does this before calling `process_selection`:

```text
r15 = first_input - 1
rbp = second_input - 1
```

So when the DWARF expression checks `row` and `col`, the actual user input must be one larger.

The expression starts by splitting the low 9 bits of `rbx` into three 3-bit coordinates:

```text
x =  rbx        & 7
y = (rbx >> 3)  & 7
z = (rbx >> 6)  & 7
```

That gives a 7 by 7 by 7 maze. Valid coordinates are 0 through 6, so there are:

```text
7 * 7 * 7 = 343 nodes
```

The direction mapping is:

```text
row 0, user enters 1: +z
row 1, user enters 2: -z
row 2, user enters 3: +y
row 3, user enters 4: -y
row 4, user enters 5: +x
row 5, user enters 6: -x
```

The second input is not a small index. It is a huge 64-bit key for that maze edge. If the direction and key match an edge, the unwind expression updates `rbx`.

## Finding the Hidden Maze

I wrote a small DWARF expression evaluator for the subset of opcodes used here:

- `DW_OP_lit*`
- `DW_OP_reg*`
- `DW_OP_pick`, `DW_OP_dup`, `DW_OP_drop`
- arithmetic and bitwise operations
- `DW_OP_bra`
- `DW_OP_skip`

Then I extracted all transition rules. The result was:

```text
343 grid nodes
685 directed edges
```

A normal perfect maze with 343 nodes has 342 corridors. If every corridor is stored in both directions, that is:

```text
342 * 2 = 684 directed edges
```

This binary has 685. The extra edge is the exit.

The one-way exit is:

```text
from low state 0xd8
coordinates (x=0, y=3, z=3)
direction row 5, meaning -x
edge key 0xa902e60a7f6fa12f
to low state 0xd7, where x=7 and the state is outside the maze
```

That is a very cute design: the flag is not at the opposite corner. It is behind a hidden one-way edge out of the maze.

## Solving The Challenge

To solve it, I treated the low 9 bits of `rbx` as the maze node, ran BFS from node 0 to the exit node `0xd8`, then replayed the full 64-bit state transitions and finally took the one-way exit.

Before the exit:

```text
rbx = 0x2f31b3e9e113c4d8
low = 0xd8
```

After the exit:

```text
rbx = 0x863355e39e7c64d7
```

One easy detail to miss: before printing the final value, `main` changes the stream base to hexadecimal. So the program prints the `rbx` value in lowercase hex, not decimal:

```text
CDDC2026{863355e39e7c64d7}
```

Here is the input path. Each line is:

```text
<first menu number> <second menu number>
```

After the last pair, enter `0` to make the program print the flag.

```text
3 1799121165995579149
5 3914893227639445988
3 15720859667770848431
5 6514942902019856686
3 12050138871615075494
3 8506687384820378018
5 8830553518961432572
1 10993831882347084422
6 2918532100902113147
3 10690005738817816901
6 7821653584400824179
1 15510975798030433612
1 5413046965242148631
5 9488261042762293537
5 2924074538170737981
4 7749150083305344096
5 10378700739254585932
1 13182832570535431554
5 1984049735716794835
2 6125986714500779242
3 13197877086969382576
2 18236150707686591847
6 6520633482835953801
2 15872336494378486585
5 4557820006251003343
5 15210149490740035280
1 11743063324895600485
1 10823413806977799387
3 17438726689155059035
1 7466952077958551878
4 10580248298836270078
1 10373721678312983329
3 3907572765624484060
1 7860980643744735998
4 16533290221609859921
6 17369419465975013907
2 2071019886289168489
4 7044321032594560470
6 5325651480940856018
4 16029369613283683553
6 15599368956508047627
1 12575082836961116032
6 5146432833168690031
3 2078713529369962107
6 11838743719203474119
3 2690634150709032059
6 4336375871946884442
3 8193106971482310060
2 14585420843661761536
4 10930091676796669525
2 6451960275488736312
2 15740136364482567557
4 7176294920748401388
4 3731741876678728148
6 12178549275125326128
0
```

## How To Find This Kind Of Trick Yourself

When a C++ reversing challenge looks empty, check exception metadata.

Good signs:

- The visible code catches exceptions.
- A function throws on an "invalid" input path.
- `.eh_frame` is unusually large.
- A single FDE is much larger than the function it describes.
- `readelf --debug-dump=frames` shows `DW_CFA_expression` or `DW_CFA_val_expression`.
- `objdump` and decompilers show no update, but runtime state changes after an exception.

Useful commands:

```bash
readelf -S ./nothing
readelf --debug-dump=frames ./nothing
readelf --debug-dump=frames-interp ./nothing
objdump -d -Mintel -C ./nothing
nm -C ./nothing
strings -a ./nothing
```

For this challenge, the important question was:

```text
How is rbx restored when process_selection throws?
```

The answer was: by evaluating a malicious-looking DWARF expression.

## Crafting Your Own Hidden Logic

For learning and CTF use, there are two levels.

The easy level is ordinary source-level exception logic:

```cpp
uint64_t state = 0;

try {
    throw std::runtime_error("secret path");
} catch (const std::exception&) {
    state ^= 0x1337;
}
```

This teaches the control-flow idea, but it is not very hidden. A decompiler will usually show the catch block.

The harder level is unwind-metadata logic:

1. Keep a state value in a callee-saved register such as `rbx`.
2. Call a function that can throw.
3. Patch that function's FDE in `.eh_frame`.
4. Add a `DW_CFA_val_expression` rule for `rbx`.
5. Make the DWARF expression read old `rbx` and input registers.
6. Return the new `rbx` value from the expression.
7. Catch the exception normally in the caller.

At source level, the catch block looks innocent. The real update happens while the unwinder reconstructs the caller's register context.

In assembly, people often emit custom CFI using directives such as `.cfi_escape`, or they compile normally and patch `.eh_frame` afterward with a script. The second approach is more convenient for CTF challenges because you can generate arbitrary DWARF bytecode from Python.

The big warning: do not use this in production software. It is fragile, ABI-specific, hard to maintain, and hostile to debuggers and reverse engineers. As a CTF trick, though, it is excellent.

## How CHOP Works

CHOP is easiest to understand by analogy with ROP.

In ROP, an attacker chains small instruction sequences called gadgets. Each gadget is normal executable code, but the chain creates a new hidden program.

In CHOP-style exception-handler obfuscation, the "gadgets" are exception or unwind actions. Instead of direct branches in `.text`, the program moves through hidden states when exceptions are raised, dispatched, unwound, or caught. The visible code may only show boring throw/catch plumbing, while the meaningful transitions live in:

- catch filters
- landing pads
- personality routines
- LSDA tables
- unwind metadata
- DWARF expressions used by `.eh_frame`

This challenge is especially sneaky because the hidden logic is not even in a visible landing pad. It is in the rule for restoring `rbx`. The unwinder thinks it is recovering a register; the challenge author uses that recovery step as a tiny virtual machine.

So the CHOP mental model is:

```text
normal code path:        boring decoy
exception event:         trigger hidden dispatcher
unwind metadata:         compute next state
catch block:             resume loop
final exit:              print hidden state as flag
```

I did not find a single canonical public specification for "CHOP" under that exact name, so I am using it here as the common CTF-style idea of chaining exception-handler or unwinder behavior to implement hidden control flow. For the underlying mechanics, the best references are still the Itanium C++ ABI, LLVM's exception handling docs, and the DWARF standard.

## Other Funny Exception-Handling Tricks

This is not the only way exception machinery can become "code".

Windows SEH and VEH tricks:

Windows Structured Exception Handling and Vectored Exception Handling can be used to catch faults such as access violations, illegal instructions, or breakpoints. A handler can inspect or modify the CPU context and continue execution somewhere else. That makes SEH/VEH useful for anti-debugging, opaque control flow, and old exploitation techniques. Microsoft documents SEH in [Structured Exception Handling](https://learn.microsoft.com/en-us/windows/win32/debug/structured-exception-handling), VEH in [Vectored Exception Handling](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling), and the C/C++ SEH extension in [Structured Exception Handling (C/C++)](https://learn.microsoft.com/en-us/cpp/cpp/structured-exception-handling-c-cpp?view=msvc-170).

SJLJ exception handling:

Setjmp/longjmp exception handling stores runtime handler state in a list instead of using DWARF tables. LLVM's docs compare SJLJ with DWARF zero-cost exceptions. Because handler registration happens at runtime, SJLJ gives a different place to hide state transitions.

EH metadata shadowing and virtualization:

Modern obfuscation research also pays attention to exception metadata. For example, the 2026 XuanJia paper discusses protecting exception-handling semantics because exposed EH metadata can leak structure useful to reverse engineers. That is the defensive mirror image of this challenge: metadata is powerful enough that both obfuscators and reversers care about it.

Signal-frame and unwind-adjacent tricks:

Unix signals are not C++ exceptions, but they are another example of "the runtime restores a saved context". Techniques such as sigreturn-oriented programming abuse the context-restoration step instead of normal function returns. The shape is similar: if the runtime trusts a saved context, that context can become a weird control-flow mechanism.

## Final Thoughts

The fun part of this challenge is that it punishes a very natural reversing habit: only looking at `.text`. The real program is split between normal code and metadata that most people treat as boring compiler output.

The visible code says:

```text
There is no flag in this binary
```

The unwinder quietly replies:

```text
There is a 7x7x7 maze in your exception metadata.
```

That is a lovely CTF lesson: when a C++ binary throws exceptions, the handler is not the whole story. The path to the handler can compute too.

## References

- [Itanium C++ ABI: Exception Handling](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html)
- [LLVM Exception Handling documentation](https://llvm.org/docs/ExceptionHandling.html)
- [DWARF Debugging Information Format Version 5](https://dwarfstd.org/doc/DWARF5.pdf)
- [MaskRay: C++ exception handling ABI](https://maskray.me/blog/2020-12-12-c%2B%2B-exception-handling-abi)
- [Microsoft: Structured Exception Handling](https://learn.microsoft.com/en-us/windows/win32/debug/structured-exception-handling)
- [Microsoft: Vectored Exception Handling](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [Microsoft: Structured Exception Handling (C/C++)](https://learn.microsoft.com/en-us/cpp/cpp/structured-exception-handling-c-cpp?view=msvc-170)
- [XuanJia: A Comprehensive Virtualization-Based Code Obfuscator for Binary Protection](https://arxiv.org/abs/2601.10261)
