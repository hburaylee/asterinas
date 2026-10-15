/* SPDX-License-Identifier: MPL-2.0 */

/* The offsets below are fixed by CarrierState in host_run.rs. */
.set HOST_RSP, 0
.set IMAGE_RSP, 8
.set RUN_STATE, 32
.set HOST_ROOT, 48
.set ACTIVE_ROOT, 56
.set STACK_POOL_START, {stack_pool_start}
.set STACK_POOL_END, {stack_pool_end}
.set STACK_POOL_LIVE, {stack_pool_live}
.set STOP_STATE, {stop_state}
.set STACK_STRIDE, {stack_stride}
.set STACK_BYTES, {stack_bytes}
.set STACK_RESERVE, {stack_reserve}

/* Phase values come from host_run.rs, which owns the carrier state machine. */
.set PHASE_STARTING, {phase_starting}
.set PHASE_IMAGE, {phase_image}
.set PHASE_ENTERING, {phase_entering}
.set PHASE_RETURNING, {phase_returning}
.set STOP_REQUESTED, {stop_requested}

/* Resolve the CPU-local slot at run time; the assembler cannot subtract two
 * linker-defined symbols in a displacement in this object file. */
.macro load_carrier
    leaq KERNELET_HOST_STATE_PTR(%rip), %r11
    leaq __cpu_local_start(%rip), %r10
    subq %r10, %r11
    movq %gs:(%r11), %r11
.endm

/* Physical IRQs are masked and the current carrier alone writes its phase.
 * The separate instance word is the remote stop publication. Its final load
 * is the admission point; a later stop reaches the next trap/service through
 * the reaper's IPI. On x86 these atomic Acquire/Release accesses are MOVs.
 * Keep r11 as the authenticated carrier for the following fixed stub. */
.macro commit_phase previous, next, rejected
    movq STOP_STATE(%r11), %r10
    testl $STOP_REQUESTED, (%r10)
    jnz \rejected
    movq RUN_STATE(%r11), %r10
    cmpl $\previous, (%r10)
    jne \rejected
    movl $\next, (%r10)
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
    commit_phase PHASE_STARTING, PHASE_IMAGE, .Linvalid_service
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

/* Ordinary service frames share the current image Task stack. Validate its
 * Host-owned pool slot and reserve before the first push or call. Arguments
 * remain in their SysV registers across this entry; only rax/r10/r11 are
 * scratch. The common return handles both scalar and rax:rdx pair results. */
.macro service name, implementation
.global \name
.type \name, @function
.balign 16
\name:
    cli
    load_carrier
    commit_phase PHASE_IMAGE, PHASE_ENTERING, .Linvalid_service
    movq %rsp, IMAGE_RSP(%r11)
    movq %rsp, %rax
    andq $-STACK_STRIDE, %rax
    cmpq STACK_POOL_START(%r11), %rax
    jb .Linvalid_stack
    cmpq STACK_POOL_END(%r11), %rax
    jae .Linvalid_stack
    leaq STACK_BYTES+STACK_RESERVE(%rax), %r10
    cmpq %r10, %rsp
    jb .Linvalid_stack
    subq STACK_POOL_START(%r11), %rax
    shrq $19, %rax
    movq STACK_POOL_LIVE(%r11), %r10
    btq %rax, (%r10)
    jnc .Linvalid_stack
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
service kernelet_service_kstack_alloc, kernelet_host_kstack_alloc_impl
service kernelet_service_kstack_free, kernelet_host_kstack_free_impl
.if {rq1_bench}
service kernelet_service_rq1_echo, kernelet_host_rq1_echo_impl
.endif

/* Rust service frames and Host guards are gone. Keep the two ABI result words
 * while the common epilogue checks stop on the shared Task stack,
 * with physical IRQs masked. */
.Lservice_return:
    pushq %rax
    pushq %rdx
    call kernelet_host_prepare_service_return_impl
    load_carrier
    commit_phase PHASE_RETURNING, PHASE_IMAGE, .Lservice_stopped
    popq %rdx
    popq %rax
    movq ACTIVE_ROOT(%r11), %r10
    testq %r10, %r10
    jnz .Lservice_root_ready
    movq HOST_ROOT(%r11), %r10
.Lservice_root_ready:
    movq %cr3, %rcx
    cmpq %rcx, %r10
    je .Lservice_root_unchanged
    movq %r10, %cr3
.Lservice_root_unchanged:
    movq IMAGE_RSP(%r11), %rsp
    /* Keep the STI interrupt shadow through RET, so a pending physical IRQ
     * observes the image continuation rather than this Host return stub. */
    sti
    ret

.Lservice_stopped:
    addq $16, %rsp
    call kernelet_host_cancel_service_return_impl
    movq $-5, %rax
    jmp kernelet_host_exit

.global kernelet_service_stop
.type kernelet_service_stop, @function
.balign 16
kernelet_service_stop:
    cli
    load_carrier
    commit_phase PHASE_IMAGE, PHASE_ENTERING, .Linvalid_service
    movq %rsp, IMAGE_RSP(%r11)
    movq HOST_RSP(%r11), %rsp
    movq HOST_ROOT(%r11), %r10
    movq %r10, %cr3
    cld
    subq $8, %rsp
    call kernelet_host_stop_impl
    jmp kernelet_host_exit
.size kernelet_service_stop, .-kernelet_service_stop

.Linvalid_stack:
    load_carrier
    movq HOST_RSP(%r11), %rsp
    movq HOST_ROOT(%r11), %r10
    movq %r10, %cr3
    cld
    subq $8, %rsp
    call kernelet_host_stack_invalid_impl
    movq $-5, %rax
    jmp kernelet_host_exit

.Linvalid_service:
    movq $-5, %rax
    jmp kernelet_host_exit

/* A hook's catch_unwind is inside the callback. RBX retains the shared-stack
 * continuation, and the native preemption guard protects this hook stack. */
.global kernelet_host_on_hook_stack
.type kernelet_host_on_hook_stack, @function
.balign 16
kernelet_host_on_hook_stack:
    pushq %rbx
    movq %rsp, %rbx
    movq %rdx, %rsp
    andq $-16, %rsp
    subq $16, %rsp
    movq %rdi, %r11
    movq %rsi, %rdi
    call *%r11
    movq %rbx, %rsp
    popq %rbx
    ret
.size kernelet_host_on_hook_stack, .-kernelet_host_on_hook_stack
