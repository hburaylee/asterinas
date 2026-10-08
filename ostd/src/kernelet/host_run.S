/* SPDX-License-Identifier: MPL-2.0 */

/* The offsets below are fixed by CarrierState in host_run.rs. */
.set HOST_RSP, 0
.set IMAGE_RSP, 8
.set RUN_STATE, 32
.set HOST_ROOT, 48
.set ACTIVE_ROOT, 56
.set HOST_IDTR, 64
.set IMAGE_IDTR, 74

/* Phase values come from host_run.rs, which owns the carrier state machine. */
.set PHASE_STARTING, {phase_starting}
.set PHASE_IMAGE, {phase_image}
.set PHASE_ENTERING, {phase_entering}
.set PHASE_RETURNING, {phase_returning}

/* Resolve the CPU-local slot at run time; the assembler cannot subtract two
 * linker-defined symbols in a displacement in this object file. */
.macro load_carrier
    leaq KERNELET_HOST_STATE_PTR(%rip), %r11
    leaq __cpu_local_start(%rip), %r10
    subq %r10, %r11
    movq %gs:(%r11), %r11
.endm

.text
.code64

.global kernelet_host_enter
.type kernelet_host_enter, @function
.balign 16
kernelet_host_enter:
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    load_carrier
    movq %rsp, HOST_RSP(%r11)
    movq %rdi, %r12
    movq %rsi, %rsp
    andq $-16, %rsp
    movq %rdx, %rdi
    movq %rcx, %rsi
    movq RUN_STATE(%r11), %r11
    movl $PHASE_STARTING, %eax
    movl $PHASE_IMAGE, %r10d
    lock cmpxchgl %r10d, (%r11)
    jne .Linvalid_service
    load_carrier
    lidt IMAGE_IDTR(%r11)
    sti
    nop
    call *%r12
    ud2
.size kernelet_host_enter, .-kernelet_host_enter

.global kernelet_host_exit
.type kernelet_host_exit, @function
.balign 16
kernelet_host_exit:
    cli
    load_carrier
    lidt HOST_IDTR(%r11)
    movq HOST_ROOT(%r11), %r10
    movq %r10, %cr3
    movq HOST_RSP(%r11), %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret
.size kernelet_host_exit, .-kernelet_host_exit

/* The native Task stack owns every compiled service frame. The validated
 * kernel half lets bounded services keep the current root. Arguments
 * remain in their SysV registers across this entry; only rax/r10/r11 are
 * scratch. The common return handles both scalar and rax:rdx pair results. */
.macro service name, implementation
.global \name
.type \name, @function
.balign 16
\name:
    cli
    load_carrier
    movl $PHASE_IMAGE, %eax
    movl $PHASE_ENTERING, %r10d
    movq RUN_STATE(%r11), %r11
    lock cmpxchgl %r10d, (%r11)
    jne .Linvalid_service
    load_carrier
    movq %rsp, IMAGE_RSP(%r11)
    movq HOST_RSP(%r11), %rsp
    lidt HOST_IDTR(%r11)
    cld
    subq $8, %rsp
    call \implementation
    jmp .Lservice_return
.size \name, .-\name
.endm

service kernelet_service_log_write, kernelet_host_log_write_impl
service kernelet_service_mmio_read, kernelet_host_mmio_read_impl
service kernelet_service_mmio_write, kernelet_host_mmio_write_impl
service kernelet_service_vcpu_idle, kernelet_host_vcpu_idle_impl
service kernelet_service_vcpu_on_spin, kernelet_host_vcpu_on_spin_impl
service kernelet_service_vcpu_boot, kernelet_host_vcpu_boot_impl
service kernelet_service_vcpu_kick, kernelet_host_vcpu_kick_impl
service kernelet_service_oops, kernelet_host_oops_impl
service kernelet_service_grains_request, kernelet_host_grains_request_impl
service kernelet_service_pt_root_register, kernelet_host_pt_root_register_impl
service kernelet_service_pt_root_unregister, kernelet_host_pt_root_unregister_impl
service kernelet_service_pt_activate, kernelet_host_pt_activate_impl
service kernelet_service_tlb_shootdown, kernelet_host_tlb_shootdown_impl
service kernelet_service_vcpu_yield, kernelet_host_vcpu_yield_impl
service kernelet_service_user_run, kernelet_host_user_run_impl
service kernelet_service_fpu_save, kernelet_host_fpu_save_impl
service kernelet_service_fpu_load, kernelet_host_fpu_load_impl
service kernelet_service_kstack_alloc, kernelet_host_kstack_alloc_impl
service kernelet_service_kstack_free, kernelet_host_kstack_free_impl

/* Rust service frames and Host guards are gone. Keep the two ABI result words
 * while the common epilogue checks pending virtual interrupts on the
 * protected Host stack, with physical IRQs masked. */
.Lservice_return:
    pushq %rax
    pushq %rdx
    call kernelet_host_prepare_service_return_impl
    movq %rax, %r9
    load_carrier
    movq RUN_STATE(%r11), %r11
    movl $PHASE_RETURNING, %eax
    movl $PHASE_IMAGE, %r10d
    lock cmpxchgl %r10d, (%r11)
    jne .Lservice_stopped
    load_carrier
    popq %rdx
    popq %rax
    lidt IMAGE_IDTR(%r11)
    movq ACTIVE_ROOT(%r11), %r10
    testq %r10, %r10
    jnz .Lservice_root_ready
    movq HOST_ROOT(%r11), %r10
.Lservice_root_ready:
    movq %cr3, %r11
    cmpq %r11, %r10
    je .Lservice_root_unchanged
    movq %r10, %cr3
.Lservice_root_unchanged:
    load_carrier
    movq IMAGE_RSP(%r11), %rsp
    testq %r9, %r9
    jnz .Lservice_upcall
    sti
    nop
    ret

/* RSP points at the service's original return address. After the synthetic
 * return, virq_entry sees its original RIP at [RAX-8] and the service result
 * at [RAX], with every other register preserved by that fixed image entry. */
.Lservice_upcall:
    movq (%rsp), %r10
    movq %r10, -16(%rsp)
    movq %rax, -8(%rsp)
    leaq -8(%rsp), %rax
    addq $8, %rsp
    jmp *%r9

.Lservice_stopped:
    addq $16, %rsp
    call kernelet_host_cancel_service_return_impl
    movq $-5, %rax
    jmp kernelet_host_exit

/* The interrupt adapter saved every interrupted GPR and the hardware return
 * frame on this carrier's private IST. Its first IRET reaches here with IF
 * and TF masked. Touch no image-stack memory: the fixed stub switches to the
 * protected Host stack before calling Rust or the native scheduler. */
.global kernelet_host_forced_yield
.type kernelet_host_forced_yield, @function
.balign 16
kernelet_host_forced_yield:
    cli
    load_carrier
    movq HOST_RSP(%r11), %rsp
    lidt HOST_IDTR(%r11)
    movq HOST_ROOT(%r11), %r10
    movq %r10, %cr3
    cld
    subq $8, %rsp
    call kernelet_host_forced_yield_impl
    call kernelet_host_prepare_yield_return_impl
    load_carrier
    movq RUN_STATE(%r11), %r11
    movl $PHASE_RETURNING, %eax
    movl $PHASE_IMAGE, %r10d
    lock cmpxchgl %r10d, (%r11)
    jne .Lyield_stopped
    load_carrier
    movq ACTIVE_ROOT(%r11), %r10
    testq %r10, %r10
    jnz .Lyield_root_ready
    movq HOST_ROOT(%r11), %r10
.Lyield_root_ready:
    movq %r10, %cr3
    movq IMAGE_RSP(%r11), %rsp
    jmp kernelet_host_resume_image_trap
.Lyield_stopped:
    call kernelet_host_cancel_trap_return_impl
    movq $-5, %rax
    jmp kernelet_host_exit
.size kernelet_host_forced_yield, .-kernelet_host_forced_yield

.global kernelet_service_stop
.type kernelet_service_stop, @function
.balign 16
kernelet_service_stop:
    cli
    load_carrier
    movl $PHASE_IMAGE, %eax
    movl $PHASE_ENTERING, %r10d
    movq RUN_STATE(%r11), %r11
    lock cmpxchgl %r10d, (%r11)
    jne .Linvalid_service
    load_carrier
    movq %rsp, IMAGE_RSP(%r11)
    movq HOST_RSP(%r11), %rsp
    lidt HOST_IDTR(%r11)
    movq HOST_ROOT(%r11), %r10
    movq %r10, %cr3
    cld
    subq $8, %rsp
    call kernelet_host_stop_impl
    jmp kernelet_host_exit
.size kernelet_service_stop, .-kernelet_service_stop

.Linvalid_service:
    movq $-5, %rax
    jmp kernelet_host_exit
