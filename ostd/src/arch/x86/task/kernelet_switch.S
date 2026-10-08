/* SPDX-License-Identifier: MPL-2.0 */

.text
.code64

/* VcpuRecord.stack_limit; checked by abi.rs. */
.set STACK_LIMIT, 96

.global context_switch
.type context_switch, @function
context_switch: /* next, current, next stack limit, vCPU record */
  mov rax, [rsp]
  mov [rsi + 56], rax
  mov [rsi + 0], rsp
  mov [rsi + 8], rbx
  mov [rsi + 16], rbp
  mov [rsi + 24], r12
  mov [rsi + 32], r13
  mov [rsi + 40], r14
  mov [rsi + 48], r15
  mov rsi, rdx
  mov rdx, rcx

.global first_context_switch
.type first_context_switch, @function
first_context_switch: /* next, next stack limit, vCPU record */
  mov rsp, [rdi + 0]
  /* Publish the new stack bound before any Rust resumes on that stack. */
  mov [rdx + STACK_LIMIT], rsi
  mov rbx, [rdi + 8]
  mov rbp, [rdi + 16]
  mov r12, [rdi + 24]
  mov r13, [rdi + 32]
  mov r14, [rdi + 40]
  mov r15, [rdi + 48]
  mov rax, [rdi + 56]
  mov [rsp], rax
  ret
.size context_switch, .-context_switch
.size first_context_switch, .-first_context_switch

.global kernel_task_entry_wrapper
.type kernel_task_entry_wrapper, @function
kernel_task_entry_wrapper:
  .cfi_startproc
  .cfi_undefined rip
  endbr64
  add rsp, 8
  call kernel_task_entry
  .cfi_endproc
.size kernel_task_entry_wrapper, .-kernel_task_entry_wrapper
