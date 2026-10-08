/* SPDX-License-Identifier: MPL-2.0 OR MIT
 *
 * The original source code is from [trapframe-rs](https://github.com/rcore-os/trapframe-rs),
 * which is released under the following license:
 *
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2020 - 2024 Runji Wang
 *
 * We make the following new changes:
 * * Add the `trap_handler_table`.
 * * Adjust some symbol names.
 * * Disable alternate macro mode after using it.
 * * Report the RSP pushed by the CPU in the trap frame.
 *
 * These changes are released under the following license:
 *
 * SPDX-License-Identifier: MPL-2.0
 */

.equ NUM_INT, 256

.text
.code64

.altmacro # enable alternate macro mode to use "%i"

.macro DEF_HANDLER, i
_trap_handler_\i:
.if \i == 8 || (\i >= 10 && \i <= 14) || \i == 17
    # error code pushed by CPU
    push    \i          # interrupt vector
    jmp     trap_common
.else
    push    0           # fill in error code in TrapFrame
    push    \i          # interrupt vector
    jmp     trap_common
.endif
.endm

_trap_handlers:
.set i, 0
.rept NUM_INT
    DEF_HANDLER %i
    .set i, i + 1
.endr

.rodata

.macro DEF_TABLE_ENTRY, i
    .quad _trap_handler_\i
.endm

.global trap_handler_table
trap_handler_table:
.set i, 0
.rept NUM_INT
    DEF_TABLE_ENTRY %i
    .set i, i + 1
.endr

.noaltmacro # disable alternate macro mode; otherwise, it may leak to other files

.text
.code64

trap_common:
    cld                     # clear DF before going to Rust to conform to x86-64 calling convention
    push rax
    mov ax, [rsp + 4*8]     # load cs
    and ax, 0x3             # test
    jz _trap_from_kernel    # continue trap

_trap_from_user:
    # kernel stack:
    # - ptr to UserContext
    # - ss
    # - rsp
    # - rflags
    # - cs
    # - rip
    # - error code
    # - trap num
    # - rax

    swapgs                  # swap in kernel gs
    mov rax, [rsp + 6*8]    # rax = user rsp
    mov gs:12, rax          # store user rsp -> scratch at TSS.sp1

    mov rsp, [rsp + 8*8]    # load rsp <- UserContext
    add rsp, 20*8           # rsp -> top of UserContext
    mov rax, gs:4           # rax = kernel stack

    # push trap_num, error_code
    push [rax - 6*8]        # push error_code
    push [rax - 7*8]        # push trap_num
    # push general registers
    push [rax - 3*8]        # push rflags
    push [rax - 5*8]        # push rip
    mov rax, [rax - 8*8]    # pop rax
.extern trap_syscall_entry
    jmp trap_syscall_entry

_trap_from_kernel:
    # kernel stack:
    # - ss
    # - rsp                 # ss:rsp is unconditionally pushed in 64-bit mode
    # - rflags
    # - cs
    # - rip
    # - error code
    # - trap num
    # - rax

    pop rax
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rbp
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax

    # The image-only IDT places the hardware frame on a private IST landing
    # stack. Compiled Host handlers run on the protected native Task stack.
    lea r11, [rip + KERNELET_HOST_STATE_PTR]
    lea r10, [rip + __cpu_local_start]
    sub r11, r10
    mov r11, qword ptr gs:[r11]
    test r11, r11
    jz .Lordinary_kernel_trap
    mov r10, [rsp + 136]         # Saved instruction pointer
    cmp r10, [r11 + 16]          # CarrierState::image_start
    jb .Lordinary_kernel_trap
    cmp r10, [r11 + 24]          # CarrierState::image_end
    jae .Lordinary_kernel_trap
    mov r10, [r11 + 32]          # Pointer to the instance's stable run-state word
.Lclaim_image_trap:
    # Host IRQ delivery survives a tenant stop. Claim IMAGE with its sticky
    # stop bit preserved, process the Host callback and acknowledgment, then
    # let the final no-stop commit select fixed exit. A stop racing this CAS
    # must retry the claim instead of discarding a delivered physical IRQ.
    mov eax, [r10]
    mov edx, eax
    and edx, 0x7fffffff
    cmp edx, 1                   # IMAGE owns the interrupted image continuation
    jne .Lexit_unclaimed_image
    mov edx, eax
    xor edx, 3                   # IMAGE(1) -> ENTERING(2), preserving STOP
    lock cmpxchg dword ptr [r10], edx
    jne .Lclaim_image_trap
    lidt [r11 + 64]              # Restore native IDT before any Host handler
    mov [r11 + 8], rsp            # CarrierState::image_rsp (saved landing frame)
    mov r10, [r11 + 48]           # CarrierState::host_root
    mov cr3, r10
    mov rsp, [r11]                # CarrierState::host_rsp
    sub rsp, 8
    mov rdi, [r11 + 8]
    call kernelet_host_trap_handler
    cli
    lea r11, [rip + KERNELET_HOST_STATE_PTR]
    lea r10, [rip + __cpu_local_start]
    sub r11, r10
    mov r11, qword ptr gs:[r11]
    mov r10, [r11 + 32]
    # A Host-selected forced yield leaves the complete original continuation
    # on this pinned IST frame. The trap's SERVICE -> RETURNING edge is
    # complete; redirect back through ENTERING without ever publishing IMAGE
    # while the Host root and stack remain active.
    mov rdx, [r11 + 8]
    lea rcx, [rip + kernelet_host_forced_yield]
    cmp [rdx + 136], rcx
    jne .Lcommit_image_trap
    mov eax, 4
    mov edx, 2
    lock cmpxchg dword ptr [r10], edx
    jne .Lleave_stopped_image
    mov rsp, [r11 + 8]
    jmp kernelet_host_resume_image_trap
.Lcommit_image_trap:
    mov eax, 4
    mov edx, 1
    lock cmpxchg dword ptr [r10], edx
    jne .Lleave_stopped_image
    mov r10, [r11 + 56]           # CarrierState::active_root
    test r10, r10
    jnz .Lrestore_image_root
    mov r10, [r11 + 48]
.Lrestore_image_root:
    mov cr3, r10
    mov rsp, [r11 + 8]
    jmp .Lreturn_from_kernel_trap

.Lleave_stopped_image:
    call kernelet_host_cancel_trap_return_impl
    mov eax, -5
    jmp kernelet_host_exit

.Lexit_unclaimed_image:
    # The frame still lives on the image IST, so no Rust Host callback may
    # run before the fixed exit restores the protected root and stack.
    mov eax, -5
    jmp kernelet_host_exit

.Lordinary_kernel_trap:
    # NMI/debug may interrupt the final image commit or early landing prefix.
    # Keep nested Host handling on the native IDT. An image IST can also
    # capture a Host instruction in the entry or service transition. Such a
    # frame stays on its landing stack, but compiled Host code must use the
    # protected carrier stack.
    lea r11, [rip + KERNELET_HOST_STATE_PTR]
    lea r10, [rip + __cpu_local_start]
    sub r11, r10
    mov r11, qword ptr gs:[r11]
    test r11, r11
    jz .Lnative_idt_ready
    lidt [r11 + 64]
    cmp rsp, [r11 + 304]         # CarrierState::landing_start
    jb .Lnative_idt_ready
    cmp rsp, [r11 + 312]         # CarrierState::landing_end
    jae .Lnative_idt_ready
    mov rdi, rsp                 # Preserve the interrupt frame on the IST
    mov r10, cr3                 # The active root may change inside a prefix
    mov rsp, [r11]              # CarrierState::host_rsp
    push r10                     # Interrupted CR3, restored after the handler
    push rdi                     # Landing-stack frame for iretq
    sub rsp, 8                  # SysV call alignment on the native Task stack
    mov r10, [r11 + 48]         # CarrierState::host_root
    mov cr3, r10
    call trap_handler
    cli
    add rsp, 8
    pop r11                     # Original landing-stack frame
    pop r10                     # Original CR3
    mov cr3, r10
    mov rsp, r11
    jmp .Lreturn_from_kernel_trap
.Lnative_idt_ready:
    mov rdi, rsp
    call trap_handler

.global kernelet_host_resume_image_trap
kernelet_host_resume_image_trap:
.Lreturn_from_kernel_trap:
    lea r11, [rip + KERNELET_HOST_STATE_PTR]
    lea r10, [rip + __cpu_local_start]
    sub r11, r10
    mov r11, qword ptr gs:[r11]
    test r11, r11
    jz .Lrestore_kernel_registers
    mov r10, [r11 + 32]
    mov eax, [r10]
    and eax, 0x7fffffff
    cmp eax, 1
    jne .Lrestore_kernel_registers
    # A nested physical IRQ can interrupt Host handling while the saved
    # carrier phase is IMAGE (e.g. an NMI in a final commit). Its return still
    # belongs to an outer Host IRQ frame. Keep the native IDT until that outer
    # handler has unwound; reusing the image IST would overwrite its frame.
    lea r10, [rip + {interrupt_level}]
    lea rax, [rip + __cpu_local_start]
    sub r10, rax
    cmp byte ptr gs:[r10], 0
    jne .Lrestore_kernel_registers
    lidt [r11 + 74]
.Lrestore_kernel_registers:
    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rbp
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    # skip trap_num, error_code
    add rsp, 16

    iretq
