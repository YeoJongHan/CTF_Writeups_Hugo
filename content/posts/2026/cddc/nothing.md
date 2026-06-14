---
title: "Hiding Logic in C++ Exception Unwinder"
draft: false
weight: 0
date: 2026-06-13T16:45:27+08:00
categories: ["2026"]
tags: ["CDDC 2026", "Reverse", "C++"]
series: ["CDDC"]
---

I came across this challenge from DSTA's Brainhack CDDC 2026 CTF and there was this particular Reverse Engineering challenge that suspiciously did nothing. The binary presented itself as an "MD5 vector viewer", and most of the visible code just looked like it takes the user's input as 2 numbers between 1 and 8 inclusive, then index a table of MD5 constants and feed the constant into an LCG-like algorithm.

After reversing the functions and finding almost nothing, the interesting part turned out to be in the `.eh_frame` section, which is used by the exception unwinder. The hidden logic was not a normal C++ `catch` block, it was a forged DWARF unwind expression attached to the `process_selection` function, and it changed the program's state while a C++ exception was being unwound.

In view of today's world of advanced LLMs, it is possible to simply get an LLM to reverse engineer the whole binary and get the flag. However, this post is written as a beginner-friendly introduction to the idea of hiding logic in C++ exception-unwinding cleanup paths: what C++ exception handling is, how this challenge hides instructions in the unwinding process, and how to hide logic in the unwinder.

C++ exception handling is implemented differently depending on the compiler, platform, ABI, and architecture ([this other blog](https://www.msreverseengineering.com/blog/2024/8/20/c-unwind-metadata-1) explains the MSVC implementation). In this post, we will focus on the GCC implementation commonly used on Linux.

[Download nothing.zip](/gitbook/assets/nothing.zip)

## How C++ Runs Destructors During Exceptions

During a normal function's execution flow, resources would be allocated then destroyed. Destruction of allocated resources is required in C++ because the language lacks an automatic garbage collector. Destruction is done to avoid issues like memory leaks, dangling pointers, and resource exhaustion.

In C++, destruction of a resource can be done by using **destructors**, which works together with **constructors** to allocate and release resources. In source code, it would look like this:
```cpp
class SomeClass {
    int* data;
public:
    SomeClass() { // Constructor
        data = new int[100];
    }

    ~SomeClass() { // Destructor
        delete[] data;
    }
};
```

The problem is what happens if a resource is allocated but an exception is triggered? Something like:
```cpp
    SomeClass obj;
    throw std::runtime_error("Oops!");
    // obj.~SomeClass() is called during stack unwinding
```

C++ automatically calls the destructor when it is time to release the object, including during exception stack unwinding.

> [!NOTE]
> Note that in modern C++, types such as std::vector, std::string, etc. already have destructors, so user-defined classes often do not need to write their own destructors. More information on this can be read from https://medium.com/@sagarmadala/this-covers-some-in-depth-concepts-releated-to-c-constructors-destructors-and-inheritance-196d653cd816

In GCC C++ exception handling, the important things to know are **protected regions**, **landing pads**, **unwinder**, **unwind metadata**, **exception-handler metadata**, and **personality routine**.

#### Protected Regions

The **protected regions** are similar to MSVC's **__wind** regions. These regions contain code for which a cleanup routine exists. This can be imagined to be similar to the **try{}** code region.

#### Landing Pad

The **landing pad** is similar to MSVC's **__unwind** regions. This is a compiler-generated code that the **unwinder** can transfer control to during exception handling, that is if an exception was thrown in a **protected region**. Some landing pads can be imagined to be like the **catch{}** code region, while others are cleanup landing pads. A cleanup landing pad does not necessarily handle exceptions. Instead, it runs cleanup code such as calling destructors.

#### Unwinder

When an exception is thrown, the program cannot simply jump directly to the nearest `catch` block. Before it reaches the handler, C++ must make sure that any local objects that are no longer needed are properly destroyed. This job is handled by the **unwinder**.

The **unwinder** is part of the runtime implementation of C++ exception handling.It walks backward through the call stack, frame by frame, looking for a matching exception handler. While doing this, it uses compiler-generated metadata to decide whether each function has cleanup work that must run. If cleanup is needed, the unwinder transfers control to a landing pad.

```cpp
try {
    // Protected region starts here.
    risky();
    // Protected region ends here if execution is normal.
} catch (const std::exception& e) {
    // Handler landing pad, conceptually.
    // If risky() throws a matching exception, the unwinder
    // transfers control here.
    handle_error(e);
}
```

> [!NOTE]
> More information can be found on the documentation on the Itanium C++ ABI https://itanium-cxx-abi.github.io/cxx-abi/abi.html

#### Unwind Metadata

The **unwind metadata** is a compiler-generated information that tells the **unwinder** how to walk backwards through the stack frames safely, restore registers, find return addresses, and recover the caller's frame.

In GCC C++, this is stored in the `.eh_frame` and `.eh_frame_hdr` sections.

The `.eh_frame_hdr` section contains a lookup table to map functions to **Frame Descriptor Entry** (FDE) in the `.eh_frame` section, for the **unwinder** to perform a faster lookup for the right entry in `.eh_frame`.

The `.eh_frame` section is made up of **Common Information Entries** (CIEs) and **Frame Descriptor Entries** (FDEs). A **CIE** contains common unwind settings, while an **FDE** describes how to unwind a particular function or code range. The **FDE** body contains **Call Frame Instructions** (CFI), which in this challenge contains DWARF **CFI**.

To read parsed unwind information, we can run `llvm-objdump --dwarf=frames ./nothing`

#### Exception-Handling Metadata

The **exception-handling metadata** is a compiler-generated information that tells the **personality routine** what to do when an exception passes through a function.

The `.gcc_except_table` section stores this information. This is often called the **LSDA** (Language-Specific Data Area). This maps protected regions to landing pads and describes cleanup actions and catch handlers.

> [!NOTE]
> You can read up more from this blog https://martin.uy/blog/understanding-the-gcc_except_table-section-in-elf-binaries-gcc/index.html

#### Personality Routine

The **personality routine** is a decision maker used during unwinding. It checks whether a stack frame has cleanup code or a matching `catch` handler and tells the **unwinder** which **landing pad**, if any, should be used.

### Control Flow

Putting it all together, the **unwinder** uses the **unwind metadata** to walk back through the stack. For each stack frame, the **personality routine** uses the **exception-handling metadata** to determine whether the current instruction belongs to a **protected region** and whether control should transfer to a corresponding **landing pad** for cleanup or exception handling.

The whole process is more clearly visualized later during the analysis of the `nothing` binary.

The important takeaway is that exception handling is not just the code in the catch{} blocks. It also depends on metadata that the runtime trusts while unwinding the stack.

## Why Can Unwind Metadata Hide Logic?

The **unwinder** needs to answer questions like:

- Where is the caller's stack frame?
- What was the caller's return address?
- Where was register `rbx` saved?
- Should this frame run a cleanup or catch block?

**DWARF Call Frame Information** answers these questions using a compact bytecode language. The DWARF standard defines instructions such as `DW_CFA_val_expression`, which says: to recover a register, evaluate this DWARF expression. The DWARF expression language itself has stack operations, arithmetic, comparisons, and branches such as `DW_OP_bra`.

> [!NOTE]
> See the [DWARF 5 standard](https://dwarfstd.org/doc/DWARF5.pdf), especially the **Call Frame Information** and **DWARF Expressions** sections.

Normally, compilers emit expressions like "the old `rbx` is stored at ...", but if someone manually patches `.eh_frame`, the unwinder may evaluate a much more complicated expression which can behave like hidden code. 

That is what happens in this challenge.

## Looking back at `nothing`

The binary is a statically linked Linux x86-64 ELF.

The program takes in 2 numbers between 1 to 8 inclusive, which we will call `row` and `col`. For valid indexes, `process_selection(row, col)` prints an MD5 constant and returns it. Then `main` updates a hidden state in `rbx` (`0x404C4C`):

```text
rbx = rbx * 0x1337133713371337 + returned_md5_constant
```

Nothing else seems particularly important.

This is where my GPT 5.5 found something suspicious in the `.eh_frame` section.

Running `llvm-objdump --dwarf=frames ./nothing | grep FDE`, we can see that the FDE for `process_selection` is absurdly large for such a small function (`process_selection` starts at `0x0404990` and ends at `0x0404A5B`):

<figure><img src="/gitbook/assets/llvmobjdump.png" alt=""><figcaption><p>LLVM Objdump</p></figcaption></figure>

The 2nd field indicates the size of the FDE's content, which is **0x5ed0** bytes.

This indicates that the `.eh_frame` is likely modified. We will come back to that later.

With the information on how C++ handles exception, we can look at the exception control flow of the binary for when an exception is thrown in the `process_selection` function.

### Exception Control Flow

I've asked an LLM to create a python script for me that parses the entries in `.gcc_except_table` and given an address, it returns all the **protected regions** that the address is in.

[Download gcc_except_table_parser.py](/tools/RE/gcc_except_table_parser.py)

If we give the address of the `process_selection` function, we see the protected region this address is in starts from `0x404be8` and ends at `0x404c51`.

<figure><img src="/gitbook/assets/gcc_table_parsed.png" alt=""><figcaption><p>Protected Regions</p></figcaption></figure>

If we open IDA and look at the disassembly, we see a **try{** comment at the start address:

<figure><img src="/gitbook/assets/try_start_disasm.png" alt=""><figcaption><p>Start address</p></figcaption></figure>

And the **try** block ends at the end address:

<figure><img src="/gitbook/assets/try_end_disasm.png" alt=""><figcaption><p>End address</p></figcaption></figure>

> [!NOTE]
> This try block is difficult to see as it isn't shown in IDA's decompiler, but it can be seen in the disassembly. 
> 
> Unfortunately as of IDA Pro 9.2, I think there is no way to display this on the decompiler as the only supported decompiled try/catch handlers is only for the MSVC implementation, not GCC.

This means that if any exception is thrown in this protected range, including in the `process_selection` function, then the **unwinder** would transfer execution to the landing pad at `0x404c69`. If no exception is thrown, it would continue normal execution and the protected region ends at `0x404c51`.

### Whole Exception Handling Process

{{< tabs >}}

{{< tab label="'main' executes and reaches the try block (protected region)" >}}
<figure><img src="/gitbook/assets/main_try_block.png" alt=""><figcaption><p>Main try block</p></figcaption></figure>
{{< /tab >}}

{{< tab label="Program enters protected region, prompts for 2 numbers, and calls 'process_selection'" >}}
<video controls autoplay muted loop playsinline style="max-width: 100%; height: auto;">
  <source src="/gitbook/assets/videos/main_process_selection.mp4" type="video/mp4">
</video>
{{< /tab >}}

{{< tab label="'process_selection' detects an invalid index and calls 'std::__throw_out_of_range_fmt'" >}}
<figure><img src="/gitbook/assets/process_selection_throw.png" alt=""><figcaption><p>Process Selection Throw Exception</p></figcaption></figure>
{{< /tab >}}

{{< tab label="'std::__throw_out_of_range_fmt' calls '__cxa_throw', which starts the exception propagation" >}}
<figure><img src="/gitbook/assets/throw_out_of_range.png" alt=""><figcaption><p>Throw out of range</p></figcaption></figure>

<figure><img src="/gitbook/assets/cxa_throw.png" alt=""><figcaption><p>cxa_throw</p></figcaption></figure>
{{< /tab >}}

{{< tab label="Runtime enters the generic unwinder, '_Unwind_RaiseException' is the unwinder's entry point" >}}
<figure><img src="/gitbook/assets/unwind_raiseexception.png" alt=""><figcaption><p>Unwind_RaiseException</p></figcaption></figure>
{{< /tab >}}

{{< tab label="'_Unwind_RaiseException' calls 'uw_init_context_1', which calls 'uw_frame_state_for' to locate the FDE for the current instruction pointer" >}}
<figure><img src="/gitbook/assets/unwind_init.png" alt=""><figcaption><p>Unwind Init</p></figcaption></figure>

<figure><img src="/gitbook/assets/unwind_frame_state.png" alt=""><figcaption><p>Unwind Frame State</p></figcaption></figure>
{{< /tab >}}

{{< tab label="'uw_frame_state_for' calls 'Unwind_Find_FDE', to find the FDE given the PC, that is in 'process_selection'" >}}
<figure><img src="/gitbook/assets/unwind_find_fde.png" alt=""><figcaption><p>Unwind Find FDE</p></figcaption></figure>

<video controls autoplay muted loop playsinline style="max-width: 100%; height: auto;">
  <source src="/gitbook/assets/videos/finding_fde.mp4" type="video/mp4">
</video>

`uw_frame_state_for` eventually calls `execute_cfa_program`, to interpret the FDE's CFI.

Then `uw_update_context_1` is called, which calls `execute_stack_op` to run the DWARF expressions and computes the register values.

<figure><img src="/gitbook/assets/uw_update_context.png" alt=""><figcaption><p>uw_update_context</p></figcaption></figure>

<figure><img src="/gitbook/assets/execute_stack_op.png" alt=""><figcaption><p>execute_stack_op</p></figcaption></figure>
{{< /tab >}}

{{< tab label="the unwinder calls the personality routine '__gxx_personality_v0' (in Unwind_RaiseException) for 'main'" >}}
<figure><img src="/gitbook/assets/gxx_personality.png" alt=""><figcaption><p>gxx_personality</p></figcaption></figure>
{{< /tab >}}

{{< tab label="In '__gxx_personality_v0', the LSDA says the landing pad is 0x404c69. Execution then resumes at 0x404c69" >}}
<figure><img src="/gitbook/assets/lsda_landingpad.png" alt=""><figcaption><p>LSDA landing pad</p></figcaption></figure>

<figure><img src="/gitbook/assets/landing_pad.png" alt=""><figcaption><p>Resume at landing pad</p></figcaption></figure>
{{< /tab >}}

{{< /tabs >}}

This showcases the execution process of the exception handler. In this challenge, the FDE for the `process_selection` function is clearly modified due to its suspiciously large size, which means the FDE's CFI is hiding some logic that the unwinder would interpret and evaluate while unwinding. This requires reverse engineering the CFI DWARF instructions.

## The Suspicious `.eh_frame` Entry

Normally, we can read the DWARF instructions using `llvm-objdump --dwarf=frames ./nothing` but because a **0xae** byte is placed there, a decoding error is returned. This might be deliberate as that **0xae** byte is skipped over but placed there to mess up normal decoders.

<figure><img src="/gitbook/assets/dwarf_decoding_error.png" alt=""><figcaption><p>DWARF decoding error</p></figcaption></figure>

Therefore my LLM generated a python script to decode the DWARF instructions to make them readable.

[Download dwarf_expr_dis.py](/tools/RE/dwarf_expr_dis.py)

<figure><img src="/gitbook/assets/decode_dwarf.png" alt=""><figcaption><p>Decoding DWARF instructions</p></figcaption></figure>

When `process_selection` throws an exception, the **unwinder** asks `.eh_frame` how to restore `rbx`, evaluates the giant expression, and writes the result into the unwound context with `rbx` changed. This `rbx` contains the accumulator result, which essentially modifies the accumulator state and therefore, the generated flag.

To get the correct flag, you would just have to enter the correct values in the correct order, so that a large number (>8) is entered for the second input, triggering the exception but also changing the accumulator state.

This giant CFI expression can be reversed manually by spotting the pattern that it uses to check the user input for certain values. However, in this modern day, it just takes a single prompt to GPT 5.5 and this whole expression can be solved. Therefore, I wouldn't go through how to reverse this whole thing.

> [!TIP]
> If you'd like to do this manually (I don't know why you would), you can refer to the [DWARF 5 documentation](https://dwarfstd.org/doc/DWARF5.pdf) under **DWARF Expression** to figure out what each expression does.

These are the first few inputs that you have to enter, that throws an exception but also changes the accumulator value:
```text
3 1799121165995579149
5 3914893227639445988
3 15720859667770848431
5 6514942902019856686
3 12050138871615075494
3 8506687384820378018
5 8830553518961432572
...
```

Flag: `CDDC2026{863355e39e7c64d7}`

Props to the challenge author for being creative; utilizing the rbx accumulator state and creating a 3D maze using the lower bits. It would be an amazing challenge, if not for GPT 5.5.

## Crafting Your Own Hidden Logic

We want to hide important logic in the exception-unwinding metadata, but how can we do that?

One method is to use the `.cfi_escape` directive to inject custom FDE CFI into the `.eh_frame`. This is done during compile-time. Information on CFI directives can be read up here: https://sourceware.org/binutils/docs/as/CFI-directives.html.

Another method is to compile the binary first, then patch the `.eh_frame`. This method is more viable for more complex logic as we can for example, create a python script to handle repetitive instructions.

The patcher would have to modify the values of the FDE properly so that the binary can run without any issues. This includes the FDE's metadata like the length of the FDE body, the address range, etc.

Patching comes with an issue, where it requires space to write the custom CFI. This can be fixed by reserving space for your custom CFI before compiling the binary. Something like:
```cpp
    .rept 0x20
    .cfi_escape 0x96
    .endr
```

Where **0x96** is a DWARF **NOP** instruction, and this is repeated **0x20** times.

In the Makefile, `-Wl,--no-relax` is required to be added to the **LDFLAGS** as this tells the linker to not compress or cleanup the repetitive NOP bytes.

However, compiling this introduces a decoding error when trying to decode using **llvm-objdump**. This is because **0x96** represents **DW_OP_nop** and it is not a top-level CFI. Top-level CFI are **DW_CFA_\*** instructions.

> [!NOTE] But there is also 0x00 which is **DW_CFA_nop**, but this gets compressed by the linker for some reason so I never got it to work.

<figure><img src="/gitbook/assets/unable_to_decode_dwarf.png" alt=""><figcaption><p>Unable to decode error</p></figcaption></figure>

To fix this, we can write some bogus top-level CFI first, then write the padding nops:
```cpp
    .cfi_escape 0x16, 0x03, 0x20, 0x53
    .rept 0x20
    .cfi_escape 0x96
    .endr
```

This works when you run **llvm-objdump** on the compiled binary.

<figure><img src="/gitbook/assets/dwarf_nops.png" alt=""><figcaption><p>DWARF NOPs</p></figcaption></figure>

You can then proceed to patch these bytes to create your own custom CFI. Congratulations! You're now ready to recreate **DOOM** or **Bad Apple** using just CFIs! (I don't know if it's turing complete, but I think it's possible)

<figure><img src="/gitbook/assets/badmeme.png" alt=""></figure>

## Can it be malicious?

<span style="font-size:2em;font-weight:bold;">Absolutely!</span>

CFI can manipulate and influence the control flow of the program, especially since it can modify register values.

This is something to look out for when performing malware analysis as it would be very hard to spot for an analyst.

<figure><img src="/gitbook/assets/malmeme.png" alt=""></figure>

## Final Thoughts

Although GPT solved this challenge, the fun part about this is that it was innovative and required looking at other sections other than `.text`. I found that learning how exception handlers work was pretty interesting, and there are probably more things that can be patched other than the CFIs.

Possible rev + pwn challenge in the future?

## References

- [C++ Unwind Exception Metadata: A Hidden Reverse Engineering Bonanza](https://www.msreverseengineering.com/blog/2024/8/20/c-unwind-metadata-1)
- [C++ Object Lifecycle: Constructors, Destructors, and Initialization Done Right](https://medium.com/@sagarmadala/this-covers-some-in-depth-concepts-releated-to-c-constructors-destructors-and-inheritance-196d653cd816)
- [Understanding the .gcc_except_table section in ELF binaries (GCC)](https://martin.uy/blog/understanding-the-gcc_except_table-section-in-elf-binaries-gcc/index.html)
- [Sourceware CFI Directives](https://sourceware.org/binutils/docs/as/CFI-directives.html)
- [Itanium C++ ABI: Exception Handling](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html)
- [DWARF Debugging Information Format Version 5](https://dwarfstd.org/doc/DWARF5.pdf)
