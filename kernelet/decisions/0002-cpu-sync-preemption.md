<!-- SPDX-License-Identifier: MPL-2.0 -->

# 普通 Host 的 CpuSync 保护随调度边界一起收窄

决策状态：已接受、已实施并完成下述验证，2026-10-16。

讨论第 5 项选择 B：在普通 Host 的 `CpuSync::get/set()` 不会被中途调度的前提下，
去掉 `kernelet-host` 为这些访问器增加的 preemption guard，恢复上游普通 Host
路径；Image 构建的 guard 继续保留。性能是目标，不能以删除必要保护换取速度。

## 成组实现

本轮明确选择 B，取代第 2 项此前保留通用 IRQ-enable 检查的决定：

- `ostd/src/arch/x86/irq/ops.rs` 的两个开启中断入口恢复上游
  `01acaa7eeed755a32fc658e7d732b080061b4872` 的实现，文件逐字节相同。
- 移除已无调用者的 Host `check_preempt()` 及其 re-export。
- `CpuSync::get/set()` 的 preemption guard 仅在 `feature = "kernelet"` 下编译。
- 普通 Host 的 guard 释放和中断返回不追加通用物理抢占处理。
  保留现有 carrier 专用 `yield_entry → vcpu_yield → Task::yield_now()`、
  `user_run` 中的显式 Host 调度，以及 `finish_image_trap()` 的 carrier 鉴别。

Image 的内部 Task 保护及 carrier 的硬件 FPU/TLS 保存恢复没有因本轮修改而删除。

## 旧实现中的重入窗口

`CpuSync` 用 `RefCell` 存储 FPU、FS base 和 GS base，并用 `OnCpu`、`InMemory`、
`Both` 跟踪最新状态的位置。切换前的 Host 回调也访问同一对象。因此，持有
`RefCell` 借用或尚未完成位置转换时，不能重入该回调。

仅撤掉通用物理中断返回调度不足以满足这个条件。旧实现还存在以下调用链：

```text
CpuSync::get() 的 reg.borrow_mut()
  → GsBase::save_from_cpu()
  → 内部 DisabledLocalIrqGuard 析构
  → arch::irq::enable_local()
  → Host check_preempt()
  → 切换前回调重新访问 CpuSync
```

该链解释了旧 Host guard 的作用。只将访问器的 cfg 改为
`feature = "kernelet"` 会暴露这一风险，因此本轮同时移除物理 IRQ-enable
的新增调度处理。恢复中断本身不再调用 Host 调度器。

## 保存、克隆和释放路径审计

当前实际 `UserReg` 只有 FPU、FS base 和 GS base 三种实现：

- FS base 是寄存器指令与 Copy/Clone；GS base 使用临时 IRQ guard 和寄存器指令，
  没有自定义 Clone/Drop。
- FPU 保存/恢复使用 XSAVE/FXSAVE 与 XRSTOR/FXRSTOR。其 Clone 分配并复制
  XSaveArea，set 替换旧值时的 Box Drop 经过内核堆、Segment/Frame 释放。
- 当前堆分配、日志和可选诊断路径使用 IRQ/锁保护、原子或固定缓冲区，
  未发现主动 `yield`、`park`、等待队列睡眠或其他任务切换调用。
  部分路径会忙等；这不是无延迟的证明。OOM abort 不属于正常返回路径。

`get` 的保存发生在 RefMut 内，保存返回后释放借用，再更新位置；尾部 Clone
期间 Ref 仍存活。`set` 替换旧对象的 Drop 发生在 RefMut 内，赋值和借用释放后
再更新位置。因此 `UserReg` 的操作及 Clone/Drop 不得主动切换所属任务，
该契约已经写入源码。未来新增实现、分配器或诊断回调需重新审计。

## 安全与验证要求

- Image 的本地 preemption guard、共享 guard 计数和内部 Task 调度保护继续保留。
- carrier 的硬件 FPU/TLS 保存、恢复、状态所有权和服务验证不因本决定而删除。
- 审计 Host `get/set` 的全部实际寄存器实现及 Clone、Drop、诊断和分配路径，
  确认不会在借用或状态转换中途进入 Host 调度器。
- 用真实调度验证活跃借用期间经过 IRQ 恢复不会隐式调度，离开借用后显式调度
  能执行排队工作。GS 保存也使用这一 IRQ 原语；不把借用边界测试写成在实际
  `CpuSync` 中注入了 pending 请求。
- 在 Host 与 Image 中验证 TLS、FPU、信号及线程切换的状态正确性。
  编译成功不能代替这些运行验证。

## 实际验证范围

两项新 OSTD 回归在实际 Task 持有 `RefCell` 可变借用时设置 pending 请求，
分别经过普通 IRQ 恢复和实际 timer 唤醒的 IRQ-enable-and-halt 边界；释放借用后
用显式 yield 完成 worker，再断言边界。worker 不访问同一个 RefCell，因此
测试证明是否发生了任务切换，不宣称复现了完整 CpuSync 的重入异常。

| 阶段 | 实际 OSTD 结果 | QEMU 原始退出码 |
| --- | --- | --- |
| 旧物理 IRQ 检查，加入新测试 | Host 360 passed、2 failed；唯一两失败均为借用期间 worker 提前运行 | 65 |
| 恢复上游物理 IRQ 原语，同一份测试 | Host 362 passed、0 failed | 33 |
| 恢复后 Native | 258 passed、0 failed | 33 |

每套 passed 均包含 3 项 VMX/EPT 不可用 self-skip；新回归均在单 CPU 下实际执行。
前后测试文件相同，after 相关 OSTD 源码无漂移。OSDK 默认无 ext2 启动退出 2 的
原始失败保留；实际套件结果来自对应新 ISO 的无磁盘 KVM 启动。

完整内核的 standalone Host-on 及 paired Host+Image release 构建均实际退出 0。
同一 paired VM 中，现有 `cpu_register_preemption.c` 原样编译的同一程序分别在
普通 Host 和真实运行的 Image 内执行，均输出精确 PASS 且退出 0。该程序检查
4 个 pthread 的 TLS cookie 与 MXCSR 控制状态、信号返回，以及 1024 次 fork/wait。
Image 实例随后成功删除，QMP 关闭和 VM 退出成功。构建期间相关源码没有漂移。

验证产物位于父 checkout 的 `.scratch/host-native-boundaries-20261016/`：
根目录记录 OSTD 阶段，`kernel/` 记录两次构建及实际 Host/Image 回归。
运行环境为 x86-64 KVM、1 vCPU、8 GiB。未覆盖多 vCPU/SMP 压力、完整 XMM/YMM/x87
数据 canary、独立 arch_prctl GET/SET 用例或全部竞争时序，也不是完整安全证明。
未测量独立性能收益。这些访问器并非普通无信号 `getpid` 的逐次路径，不能将已有
整体耗时差值归给它们。

该选择与 [Host 调度边界决策](0001-host-preemption-boundaries.md) 一起审查。
它是实现层的保护范围调整，不是更改 Kernelet 的 FPU/TLS 隔离契约。
