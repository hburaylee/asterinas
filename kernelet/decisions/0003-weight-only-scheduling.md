<!-- SPDX-License-Identifier: MPL-2.0 -->

# Host 权重调度直接替代额外 CPU 记账

决策状态：已接受、已实现并完成下述验证，2026-10-16。直接修改 `kernelet-host`，
不保留另一套可选调度模式。此前新增的独立 Cargo feature 已撤销。

## 当前行为

carrier 与实例的专用设备 worker 共同分摊固定权重 W：N 个 carrier、M 个
worker 均使用实例 nice 和固定除数 N+M。nice 更新同时作用于两者；共享
reaper/close worker 不属于此固定集合。睡眠线程的份额不自动转借。
没有独立累计 CPU 记账、配额窗口、quota 等待或 quota tick 决策。
普通 `kernelet-host` 构建直接采用上述行为，无需附加 feature。
无竞争时可以使用空闲 CPU；线程数量和可运行状态仍影响实例的实际份额。
完整实例组调度是后续方向。

创建或更新预算时，任何非空 quota 请求都被拒绝；UAPI 返回 `EOPNOTSUPP`。
保留 ioctl 的 quota 字段以明确拒绝旧请求，不改变结构布局，不静默接受限制。
累计 CPU 时间返回 `STATS_UNAVAILABLE`，runtime 的 stats/status JSON 显示 null，
containerd metrics 不发布 CPU usage。throttled 时间为零。

## 实现边界

- 删除实例 CPU 计数器、配额窗口、配额等待队列与 carrier CPU 记账附着。
- 删除 Host timer 的 quota 决策、worker 的 quota 等待和服务边界的 quota 采样。
- carrier 的上下文指针直接归属 Host Task；切换时保留身份槽、TLS/FPU 和
  地址空间处理，不借用 CPU 记账对象保存安全状态。
- worker 使用独立 `AdoptedTask` 生命周期引用。重复附着失败会退还计数；
  错误 owner 无法 disown；正常 disown、Task 退出和 Task 销毁会释放引用并
  通知 reaper。释放发生在 Task 锁之外，保留 destroy / Zombie 边界。
- 显式计时单独放在 `task/accounting/measurement.rs`，仅 Image、RQ1/诊断与
  ktest 构建编译。普通 Host Task 不含该计时状态，切换及 timer 路径不调用
  采样，也不读取计时 enabled 标志。Host 的期限时钟仍服务 idle、reaper 和
  日志限制；这些用途不属于累计 CPU 记账。
- Image 的执行时钟仍扣除 Host 脱离 CPU 的时间；carrier 的 parked/stolen
  时间继续服务虚拟时钟语义，不据此进行实例 CPU 配额控制。

## 与设计书的关系

该阶段暂不提供设计书 [I6](https://github.com/tatetian/kernelet-book/blob/2d0d5769be63f465aebfe8312dfa558453502821/src/blueprint/asterinas-mode/principles.md)
要求的完整 CPU 归属和带宽上限。
[调度章节](https://github.com/tatetian/kernelet-book/blob/2d0d5769be63f465aebfe8312dfa558453502821/src/blueprint/asterinas-mode/virtualizing-ostd/scheduling.md)
列出的 W/N 过渡办法也不构成组调度。本决定保留内存、日志与生命周期限制，
不将权重调度描述为硬 CPU 隔离。

## 验证范围

本次直接修改后的实际结果：

- Host OSTD：356 passed、0 failed；Native OSTD：258 passed、0 failed。
  两套各含 3 项 VMX/EPT 环境不可用而自行跳过的测试。
  Host 新增权重配置拒绝 quota、重复 worker 附着退款、错误 owner 无法 disown
  的回归；已有 destroy/Zombie、worker 退出与 carrier 回收测试继续通过。
- 完整 paired Host+Image release 构建及 Image 审计成功。
- 真实 Host 与 Image 的 TLS/MXCSR 线程、信号和 fork 回归通过；Image 创建、
  运行、stats/status 的 CPU null、quota 创建返回 `EOPNOTSUPP`、删除通过。
- OSDK 原有 3 项构建特性测试通过。普通 Host ELF 未找到额外 CPU 记账相关
  符号，结合源码 cfg 确认采样状态与调用从普通 Host 路径中排除；这不是性能测量。
- 额外全内核 RQ1 diagnostics check 未通过：既有 `kernelet_rq1_tlb.rs` 宏导入
  与 `rq1_ram.rs` / `rq1_io.rs` 的 `inner_dma_slice()` 接口不匹配，共 5 个错误。
  三个报错文件与本轮修改前 SHA256 一致，未扩大本轮范围修复这些夹具。
  OSTD 的诊断计时模块已编译，但不将该全内核检查报告为通过。

产物在父 checkout 的 `.scratch/kernelet-host-no-cpu-accounting-20261016/`，
包括真实退出码、日志、源码校验和 `functional/result.json`。OSDK 默认 ext2
缺失退出 2 的日志保留；OSTD 实际结果来自对应 ISO 的无磁盘 QEMU 启动，
原始退出码 33。Native 套件之后只有注释清理；最终 Host 套件及 paired 构建
所覆盖的可执行源码无漂移。

此前可选模式的测试与产物属于旧实现，不能用来证明本次删除后的源码或性能。
运行环境为 x86-64 KVM、1 vCPU、8 GiB。未测量加速幅度或竞争公平性，未做
SMP 压力、完整硬件寄存器数据或 containerd RPC 运行验证。

后续诊断构建、普通调度数学和设备异步批次的更新见 [0013](0013-bounded-host-work.md)。上面的首次验证记录保留其原有范围。
