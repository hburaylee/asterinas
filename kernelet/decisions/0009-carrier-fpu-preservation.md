<!-- SPDX-License-Identifier: MPL-2.0 -->

# 暂时保留 carrier 外层 FPU 保存与恢复

记录日期：2026-10-16，对应开销排查第 11 项。用户要求先记录本项。
当前机制保留；重复保存的频率、性能影响和优化方案待评估，本轮不修改实现。

## 当前行为及原因

Host 真正切出 carrier 时，`pause_carrier_context()` 将物理 FPU 状态保存到
该 carrier 的 `fpu_stage`，并设置 `fpu_paused`。恢复时，仅在该标志为真时
加载快照。首次进入 Image 另有一次中性 FPU 状态初始化加载。普通 Host Task
不执行这套 carrier 扩展，调度器再次选择当前 Task 时也不执行该切换。

Image 内部用户线程仍沿用 `CpuSync`：仅在最新状态为 `OnCpu` 时保存，
仅在状态为 `InMemory` 时于返回用户态前恢复。同一线程的系统调用往返通常
不触发这对操作。当前 `FpuContext::save/load` 直接使用 XSAVE/FXSAVE 和
XRSTOR/FXRSTOR，没有额外的 FPU 服务调用或缓冲区复制。

进入 Image 内核后，用户线程的最新 FPU 状态可能仍在物理寄存器中。
Host 若切走 carrier 而不保护该状态，其他用户线程可能覆盖它；恢复后 Image
仍会认为其 `OnCpu` 状态有效。因此不能按 `IMAGE/SERVICE/IDLE` 阶段或
“正在执行内核代码”简单跳过，也不能将这项保护当作诊断代码用 cfg 关闭。

这与 book 的
[按 carrier 保护浮点状态](https://github.com/tatetian/kernelet-book/blob/2d0d5769be63f465aebfe8312dfa558453502821/src/blueprint/asterinas-mode/virtualizing-ostd/tasks.md#carriers)
方向一致。本项没有新增与 book 不同的设计决策。

## 待测问题及重新评估条件

原生用户线程被抢占时同样需要保护 FPU，不能将每次 carrier 保存恢复全部
算作 Kernelet 的净新增开销。待测问题是：Image 内层刚保存线程状态，Host
又相邻保存 carrier 时，可避免的重复发生多少次，实际成本占比是多少。

后续如开展测量，应区分内层线程切换、外层 carrier 切换和用户态往返，
分别记录硬件保存/恢复次数及耗时，保持工作负载和对照条件一致。
目前没有对应性能结果，不声称这是已证明的瓶颈。

若测量证明值得优化，再评估可信的物理 FPU 所有权及有效性协议。
允许省略外层操作之前，必须保证最新线程状态已保存、下次用户态执行前
正确恢复，并覆盖抢占、迁移和跨层过渡。`fpu_paused` 本身不能证明这些条件。
该协议尚未设计或实现，不将普通布尔标志作为已有安全方案。

源码入口：`ostd/src/kernelet/host_run.rs` 的
`pause_carrier_context()`、`restore_carrier_context()` 和 `enter_vcpu()`；
`ostd/src/arch/x86/cpu/context/mod.rs` 的 `FpuContext::save/load`；
`kernel/core/src/process/posix_thread/cpu_sync.rs` 的
`before_schedule()` 和 `before_user_exec()`。
