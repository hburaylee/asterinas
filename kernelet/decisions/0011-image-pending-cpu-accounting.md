<!-- SPDX-License-Identifier: MPL-2.0 -->

# Image 负责 pending CPU 样本的归属与结算

已接受并实现，2026-10-16，对应开销排查第 13 项。Host 仅给当前 carrier 的
per-vCPU 计数器增加样本并发布 pending，不再按 RSP 定位内部 Task 栈或为采样
获取实例共享栈池锁。Image 在虚拟时钟 upcall、当前 Task 退出和切换边界结算
CPU 时间。upcall 重定向的栈空间安全校验保留；后续
[第 14 项](0012-stack-live-validation.md) 将该校验的共享锁替换为固定布局和原子 live 位。

## 归属边界

只在 upcall 中按当前 Task 消费全部 pending，会把关闭虚拟 IRQ 期间积累的
样本转移给下一 Task。因此，Image 在关闭虚拟 IRQ、取得目标 Task 执行权后，
紧靠 CURRENT_TASK_PTR 交接之前，一次性取走本 vCPU 的 user/kernel 样本。
这次原子交换定义逻辑交接边界：之前属于旧 Task，之后属于新 Task。
交换后至实际切栈的交接指令计入新 Task，明确放弃旧实现按物理 RSP 精确区分
这些指令的归属。不得把本次变更称为严格保持旧采样口径。

旧 batch 保存在 Image 私有的 per-vCPU PREVIOUS_TASK_TICKS 中。在新栈上，
使用旧 Task 的存活引用结算保存的 batch，随后才释放 switched_to_cpu，允许
迁移或退休。结算旧 Task 时不再读取当前 per-vCPU pending。没有 adopted
Task 的 bootstrap 首次交接明确丢弃无 owner 的样本。同 Task 重选不交接。
CPU 时钟与 CPU timer 回调仍在 L1 执行，期间物理 tick 仅排队 L2 timer 事件。

## 数据与安全边界

user/kernel accounting pending 打包在一个 64 位原子字内，各占 32 位，避免
两次交换产生两个归属边界。字段占 VcpuRecord 的 offset 120 尾部空位，总长
仍为 128 字节，原字段偏移及汇编 ABI 保持不变。子计数器达到 u32::MAX 后
再增加样本会停止 Image，不丢弃、回绕或进位到另一类；1000 Hz 下一个计数器
连续约 49.7 天未结算才达到该上限。通用虚拟 timer 计数独立保留，CPU 时间
结算不会提前消费或重放 timer 事件。

Host 不解引用 Image Task 指针，不获取新身份信息，普通 Host 调度和物理
中断边界不增加处理。Host 的栈分配配额、live bitmap、guard、TLB 确认及
upcall reserve 校验继续存在。删除栈顶的样本 cache line 后，完整映射恢复为
可用栈；合法空栈 RSP 等于映射上端时，仍须按其下方字节所属的 live slot
验证 reserve，并禁止释放当前栈。

这采用 book 的
[pending 与 upcall 基本流程](https://github.com/tatetian/kernelet-book/blob/2d0d5769be63f465aebfe8312dfa558453502821/src/blueprint/asterinas-mode/virtualizing-ostd/interrupts-and-time.md#the-tick)，
但显式增加逻辑交接边界，替代其“回调总属于物理中断时的 Task”假定。仍只在
carrier 实际执行 Image 时采样；Host 运行其他任务时不补发 CPU 时间。

验证收据和限制见父 checkout 的
`.scratch/pending-task-ticks-20261016/REPORT.md`。本次不提供性能加速比例。
