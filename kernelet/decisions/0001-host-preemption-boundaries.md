<!-- SPDX-License-Identifier: MPL-2.0 -->

# 保留 carrier 调度入口，移除 Host guard 释放时的自动抢占检查

决策状态：已接受，2026-10-16。代码基线为 `fa17efba049ef0f6511ebd9c33b05be7a104bb1e`。

Host 继续使用已有调度器。启用 `kernelet-host` 后，释放普通 Host 的
`DisabledPreemptGuard` 不再额外调用 `check_preempt()`；它只减少原有计数。
这项选择减少 Kernelet 支持对普通 Host 调度边界的改变。carrier 通过已有的
专用入口交还物理 CPU。该决定不承诺 guard 释放后立即兑现 pending 抢占请求。

## 与 kernelet-book 的关系

对照版本为上游 `tatetian/kernelet-book` 的
[`2d0d5769be63f465aebfe8312dfa558453502821`](https://github.com/tatetian/kernelet-book/tree/2d0d5769be63f465aebfe8312dfa558453502821)。

- [Asterinas Scheduling](https://github.com/tatetian/kernelet-book/blob/2d0d5769be63f465aebfe8312dfa558453502821/src/blueprint/asterinas-mode/virtualizing-ostd/scheduling.md#giving-the-processor-back-cooperative)
  要求在临界区结束和内核中断返回时检查抢占，并指出任务切换跳过 guard
  析构，因此开启中断的底层原语也需要覆盖检查。
- [D118](https://github.com/tatetian/kernelet-book/blob/2d0d5769be63f465aebfe8312dfa558453502821/src/notes/design-register.md)
  又把一组 guard 修改限定在 `kernelet` feature。书没有完整区分这里每个检查的
  Host OSTD 与 Image vOSTD 作用范围。

本决定刻意收窄对上述临界区结束要求的实现：保留 Image 的内部调度处理，
不在所有 Host preemption guard 的析构中追加物理调度检查。
这是对书中作用范围的明确实现选择；不将书的表述歧义写成已经证明的规范冲突。

## 保留的机制与取舍

- 本轮 [B 决策](0002-cpu-sync-preemption.md) 取代第 2 项此前保留检查的决定：
  `arch::irq::enable_local()` 和 `enable_local_and_halt()` 恢复上游物理 IRQ 原语，
  不再进入新增的 Host 抢占处理。
- 普通 Host 内核中断返回不追加通用调度点，保留仅处理已认证 carrier 的
  `finish_image_trap()`。
- `yield_entry → yield_dispatch → vcpu_yield → Task::yield_now()` 保留。
  `vcpu_yield` 显式进入 Host 调度器，不依赖 guard 析构来完成 yield。
- `user_run` 处理物理中断后的显式 Host `scheduler::might_preempt()` 保留。
- Image 的本地与共享 guard 计数、虚拟中断恢复及内部 Task 调度处理保留。
  Image Task 切换与 Host carrier 让出物理 CPU 是两个不同操作。

被放弃的方案是在所有 Host guard 释放时继续检查抢占。它可以更早兑现某些
pending 请求，但也扩大普通 Host 的调度边界。删除后，在 Host guard 仍被持有时
延期的请求会等待后续显式调度、用户执行循环或 idle 路径等已保留的调度点。
仍需验证 carrier 的进展和延迟；不能仅由专用入口存在就推导完整调度覆盖。

## 关联决策的状态

| 讨论项 | 决定 | 实现状态 |
| --- | --- | --- |
| 1：用户上下文与 `fault_addr` | 选择 A：保留统一类型，将字段填写移至 Kernelet 专用入口 | 已实现；普通 Host 使用 `RawUserContext::run()` 返回的局部值，专用 `run_host_user()` 填写共享字段。2026-10-16 全量审查时更新此状态 |
| 2：通用开启中断检查 | B：恢复上游物理 IRQ 原语 | 已实施，取代此前保留决定 |
| 3：Host preemption guard 释放检查 | 删除 Host 专用的自动检查 | 本次实施 |
| 5：CpuSync 访问保护 | B：Host 恢复上游访问路径，保留 Image 保护 | [已实施并完成所列验证](0002-cpu-sync-preemption.md) |

本文件记录本轮已经讨论的边界，不是全部 book 差异的审计清单。
后续不同取舍以新的决策文件记录，并引用所对照的 book 提交。

## 首次 guard 修改的验证与证据范围

以下记录仅属于最初删除 guard Drop 检查的一轮，当时仍保留 IRQ-enable 检查。
本轮恢复普通 Host 调度边界的结果记录在 [B 决策](0002-cpu-sync-preemption.md)。

使用同一份 Host-only 回归
`host_preempt_guard_drop_keeps_pending_request`，在 x86-64 KVM、q35、
1 vCPU、8 GiB 的真实 OSTD 测试内核中验证：

| 实现 | Host OSTD 结果 | QEMU 原始退出码 |
| --- | --- | --- |
| 保留旧 guard 检查，仅加入新测试 | 358 passed，1 failed；唯一失败为 guard 释放使 worker 提前运行 | 65 |
| 删除 guard 检查，同一份测试 | 359 passed，0 failed | 33 |

每组 passed 均包含 3 项明确的 VMX/EPT 不可用 self-skip。新回归在单 CPU 下实际
执行；它确认中断开启时释放最后一个 Host guard 不会提前运行 worker，pending
请求保持存在，随后通过显式 `Task::yield_now()` 完成真实 worker 的执行和清理。
前后两轮的测试源码和 OSDK 二进制相同。

两轮 OSDK 均完成编译和 ISO 创建，但默认启动因缺失 ext2 镜像退出 2；上述运行
结果来自各轮刚生成 ISO 的无磁盘 QEMU 启动，不表示默认启动配置已修复。
验证产物保存在父 checkout 的 `.scratch/host-guard-drop-20261016/`。

这只验证所选 Host OSTD 套件及该调度边界，不证明实际 Image 负载、carrier
竞争下的进展或延迟、SMP 和性能。`fa17efb` 的既有性能结果属于旧源码身份，
不能作为删除此检查后的性能证据。
