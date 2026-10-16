<!-- SPDX-License-Identifier: MPL-2.0 -->

# carrier 同步直接切换注册页表根

已接受并实现，2026-10-16，对应开销排查第 12 项方案 C。非零注册根的同步
`pt_activate` 从旧 Image 根直接切换到目标根，省去中间 HostRoot；普通 Host
`VmSpace::activate()` 分支保持原实现。本次不提供性能加速比例。

## 提交与生命周期

原路径先停用旧根，安装 HostRoot，再登记目标根，由服务返回汇编写目标 CR3。
当前在 `kernelet_host_pt_activate_impl()` 持有注册表锁、物理 IRQ 关闭期间，
通过 carrier 专用 `VmSpace::activate_registered_root()` 同步提交：

1. 保留旧 token、CPU 引用与 active CPU 位，锁住 carrier 的目标根记录。
2. 在新根 state 锁内检查有效性、写目标 CR3、记录 generation 并发布 active
   CPU 位。并发 shootdown 的快照不能进入该锁保护的提交区间。
3. 硬件已使用新根后替换记录，保留 carrier 的 CPU 引用，再撤销旧根的
   active CPU 位。同 token 重复激活不会移除自己的预约；停用状态中留下的
   desired token 也不会被误认为本 CPU 仍持有的预约。
4. 更新 carrier 的 desired-root 身份后进入 RETURNING。已有 prepare 快路
   保留新预约，返回汇编比较 CR3 后跳过重复写入。

没有引入跨服务返回的 pending 事务，也没有修改汇编布局或用户 ioctl ABI。
Host/Image 仍须配对重建，以满足现有共同源码 hash 契约。

无效或已退休目标失败时保留旧状态。`root=0`、等待、外层调度与固定退出
继续使用 HostRoot。若同步提交后发生停止，现有固定出口先安装 HostRoot，
再清理新根预约。普通 Host 地址空间若意外仍为当前软件 owner，专用接口
明确失败，不覆盖其硬件根或引用。

这细化了 book 的
[pt_activate 及地址空间恢复设计](https://github.com/tatetian/kernelet-book/blob/2d0d5769be63f465aebfe8312dfa558453502821/src/blueprint/asterinas-mode/virtualizing-ostd/memory.md#address-spaces-and-page-tables)，
保留根注册验证、shootdown、停止及回收边界。

## 验证与限制

最终 Host OSTD 报告 364 passed，Native OSTD 报告 258 passed，各含 3 项
VMX/EPT 环境自行跳过。新增硬件根切换回归覆盖直接交接、同根、退休根失败、
引用与 generation；32 轮实际另一 CPU 的 shootdown 发布与提交并发运行，
执行真实 flush/ack，但没有穷尽所有交错。

真实服务汇编夹具覆盖 A→B→A、同 A、无效根、root0、再次 A，随后覆盖
stop/panic 退出。该夹具绕过生产注册验证且手动保留根帧，不能独立证明实际
页表帧回收时序。真实配对 Image 的生产注册和 fork/wait 路径另行验证。

配对 release 构建与 Image 审计通过。发布版反汇编确认非零根路径无中间
deactivate、仅一次 CR3 写；root0 停用和返回时的同 CR3 跳过仍存在。
一个配置为 2 vCPU 的 Image，以及两个并发 Image（2+1 vCPU），均通过
线程、TLS/MXCSR、信号、1024 次 fork/wait 回归并正常删除。配置为多 vCPU
不证明用户线程实际运行于不同 CPU；真实跨 CPU 证据来自 OSTD IPI 回归。

证据位于父 checkout 的 `.scratch/carrier-direct-root-20261016/REPORT.md`。
这些验证不代表长期 SMP 压力、任意 NMI 时序或已测量的性能收益。
