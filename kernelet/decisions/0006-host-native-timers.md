<!-- SPDX-License-Identifier: MPL-2.0 -->

# carrier 定时等待复用 Host 定时器

决策状态：已接受并实现，2026-10-16。直接修改 `kernelet-host`，不新增配置开关。

## 行为与所有权

carrier 是普通 Host Task。`vcpu_idle()` 保留 Image 请求接口及现有 Host
`WaitQueue` 阻塞路径，定时唤醒改为登记到 Host 已有的单调时钟 `TimerManager`。
Kernelet 专用的 `BTreeMap` 截止时间队列、序号及 BSP tick 扫描已删除。
退出等待、reaper 的原生 Task 退休重试及相应测试等待也使用同一 Host 后端。

OSTD 位于 kernel 下层，不能直接引用 kernel 的 Timer 类型。新增的连接仅包含
一个初始化时注册的构造函数，以及可查询是否到期、释放时取消的定时器句柄。
kernel 的时间初始化在创建实例前注册该构造函数。后端使用原有
`MonotonicClock::timer_manager()`、`Timeout::After`、到期回调和取消操作，不添加
定时器队列、定时器扫描回调或新的物理时钟中断工作。

Host 后端必须能够在 IRQ 关闭时登记或取消，不得阻塞。生产配置缺少后端时明确
失败，不静默改用另一套定时器。该接口和连接代码只编译到 `kernelet-host`。

## 时间与唤醒语义

Image 传入绝对截止时间，OSTD 根据 Image 当前单调时间计算剩余时长，保留既有的
最短等待限制，再由 Host 的单调定时器登记这个相对时长。超时检查使用同一个
Host 定时器的时钟，避免用另一时间基准判断后导致一次唤醒后再次睡眠却无人通知。
无期限等待不创建定时器；已有待处理事件时直接返回。

Host 等待条件继续检查虚拟事件和停止请求。事件或停止请求提前唤醒后，释放
定时器句柄会取消剩余超时。到期通知只持有等待队列的弱引用，不保留 Image、
carrier 或实例状态。取消时不等待已经开始执行的回调；该回调至多唤醒仍然存活的
队列，等待方仍需重新检查条件。旧实例的取消不会撤销其他实例的定时器。

Host TimerManager 可能保留已经取消的回调节点，直到原有管理流程清理该节点。
该行为沿用普通 Host 定时器；不将取消描述为立即物理删除所有元数据。

## 验证范围

Host 内核新增两项回归直接使用真实 `TimerManager`，覆盖到期、重新登记、取消、
相邻定时器独立性及等待队列的弱引用生命周期。测试时手动推进时钟，以便准确
判断边界；实际 Host/Image 运行另行验证真实时间与调度路径。

独立 OSTD 测试不链接 kernel 的 TimerManager，因此显式注册仅用于 ktest 的
普通 FIFO Task 定时后端。它验证 OSTD 的委托与生命周期路径，不作为真实
Host 定时器的验证或性能证据；生产代码没有该替代后端。

实际验证记录位于父 checkout 的
`.scratch/host-native-timers-20261016/VERIFICATION.md`。尚未测量性能收益。
