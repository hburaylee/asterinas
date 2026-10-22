/* SPDX-License-Identifier: MPL-2.0 */

.text
.code64

/* The compiler calls mcount at the top of every function that survives
 * inlining and requires every register and the flags preserved.  Check the
 * current vCPU's stack limit and stop the kernelet if the frame would step
 * below the 16 KiB reserve. */

.global mcount
.type mcount, @function
mcount:
  push rax
  push rcx
  push rdx
  push rsi
  push rdi
  push r8

  lea rax, [rip + KERNELET_BOOT_ARGS]
  mov rax, [rax]
  test rax, rax
  jz 1f

  /* vCPU record: boot + PAGE_SIZE + gs_slot * 128. */
  mov rcx, [rax + 192]         /* BootArgs.cpu_slot_gs_offset */
  mov rcx, gs:[rcx]
  shr rcx, 16
  movzx ecx, cx
  imul rcx, rcx, 128
  lea rcx, [rax + rcx + 4096]

  /* stack_limit + 16 KiB reserve. */
  mov rdx, [rcx + 96]          /* VcpuRecord.stack_limit */
  add rdx, 16384
  cmp rsp, rdx
  jae 1f

  /* stop(STOP_STACK_OVERFLOW=2, 0, NULL, 0). */
  lea r8, [rip + KERNELET_SERVICES]
  mov r8, [r8]
  test r8, r8
  jz 1f
  mov edi, 2                   /* kind */
  xor esi, esi                 /* code */
  xor edx, edx                 /* msg */
  xor ecx, ecx                 /* len */
  call qword ptr [r8 + 144]    /* stop */

1:
  pop r8
  pop rdi
  pop rsi
  pop rdx
  pop rcx
  pop rax
  ret
.size mcount, .-mcount
