<!-- SPDX-License-Identifier: MPL-2.0 -->

# 有界的 Host 工作与异步块提交

状态：2026-10-16 已实施；验证收据位于父 checkout 的
`.scratch/kernelet-all-hotpaths-optimization-20261016/`。不据功能检查宣称提速百分比。
对照设计书提交 `2d0d5769be63f465aebfe8312dfa558453502821`。

## 计时器与普通 Host

carrier 继续复用普通 Host 的 TimerManager。开启 `kernelet-host` 后，队列使用
带位置索引的紧凑二叉堆；取消和重设直接 O(log n) 移除原注册，Timer 销毁也
移除注册。过期处理先释放队列锁，再获取 Timer 锁；已经取出的回调仍检查取消标记。
没有专用 tick 扫描或独立 CPU 用量记账。每个 carrier 的保守固定预留包含其
统计分片与一份 live deadline 注册。

Native/Image 的原 BinaryHeap 和 Timer 布局保留。Host 堆为更新位置索引增加
少量 Relaxed 原子 load/store，换取取消节点不积累；没有 BTree 节点分配或取消时
全队列扫描。该共享 timer 结构变更仍可能影响普通 Host 的 timer 操作，需测量。

公平调度在当前权重与队列权重均为整数时先约去比例因子。混合分数情况保留
精确宽计算和溢出检查，不增加队列成员或 CPU 用量记账。N+M 权重分摊继续生效。
服务/MMIO/IRQ 观察计数置于 Host 私有、缓存行隔离的 vCPU 分片，stats 查询时
汇总；内存、日志限额、adopted 和生命周期原子保留。

## MMIO 上半部与 worker

block/net/vsock/console/rng 的 notify 只记录 doorbell 并唤醒既有 worker，
不在物理 IRQ 关闭的服务 hook 内遍历 Guest descriptor。worker 每轮最多收集
一条完整链；多队列中被填满的队列不会挡住另一个队列。pending doorbell 在
inbox 满时保留，消费和后续 endpoint 唤醒会继续处理；reset 清除旧 doorbell。

这是对设计书“hook 中有界验证”的实现位置调整。权限、链长度、方向、重复 head、
环边界、generation 与停止检查仍保留。普通 Host 的通用抢占边界保持原有行为；
这些专用 worker 只在 Host 已请求让出时使用显式调度点。

## 原始块后端

每设备仍只有一个专用 worker。原始 BlockDevice 后端使用 Bio::submit，每批
最多四个在途请求，所有槽的 DMA 暂存合计最多 4 MiB；按需分配并复用，不能
理解为每槽预分配 4 MiB。固定请求/BIO 元数据额外预留，DMA 按实际字节同时
受 Host 与端点额度约束。空间不足先完成已有批次，再单独重试未提交请求。

这是有界异步批次，尚未实现任意完成驱动的持续补槽。完成按提交顺序收取，可能
等待较慢的前项。文件后端继续使用既有 read_at/write_at，不冒充异步存储。
flush 前先排空已提交 BIO，完成后再提交后续请求；reset/cancel 也等待真实 BIO
完成。旧 generation 不发布 used，read copyback 前检查代次；已经开始的复制
由 active/resetting 协议保护，归零前不得重新启用队列。

每个 BIO 的完成回调持有 DMA 与两份 charge 的所有权，即使提交者提前析构，
也不能在驱动仍拥有 DMA 时退还额度。并发读写不采用 Guest 零拷贝或额外 Host
线程。硬件 QD 吞吐、QD1 成本和竞争公平性均需后续实测。

## rootfs 与诊断

源树逐组件 openat(O_PATH|O_NOFOLLOW)，fstat 和内容读取绑定同一 inode。
目录通过自己持有的 /proc/self/fd 能力枚举；链接用 readlinkat 的空路径形式
读取已绑定链接本身，绝不跟随源树提供的链接读取内容。保留复制后内容/元数据
摘要比对、私有 staging、目的侧 no-follow agent 注入和不可变缓存。
这要求 Host 的 O_PATH、proc fd 与空路径 readlinkat 语义；源树可变导致构建
失败是允许的，不能以路径重试或外部内容替代来掩盖错误。

RQ1、diagnostics 及组合配置分别编译检查。并行 lost-holder 测试使用从未 listen
的残留 stream socket，避免并行 fork 暂时继承监听 FD 的窗口。生产恢复语义
不因此把 ECONNRESET、权限错误或无响应自动当作 stopped。

## Image FPU 审计边界

Image 的 FpuContext::save/load 固定为不可内联的现有状态包装函数，避免
ThinLTO 将恢复指令移入普通内核 hook 后违反产物审计。普通 Host 不增加此
属性。保留既定 FPU 所有权和保存/恢复；没有放宽 FXRSTOR 的审计白名单。
这是明确的调用边界取舍，尚未测量额外调用成本。

配对 RQ1 构建使用已有 KERNELET_RQ1_BENCH=1 与
KERNELET_RQ1_DIAGNOSTICS=1，使 Host/Image 同时启用同一服务表布局。
仅通过 RUSTFLAGS 启用 Host 的 cfg 不能证明 Image 也启用了相同配置。

Image 的当前页表核对继续读取实际 CR3。并发审计更新将控制寄存器写入
与只读查询分开，保留只读 CR2/CR3 查询，禁止修改 CR 和未经批准的 MSR
写入。本轮不再增加只读查询的调用包装，也不以软件缓存替代实际页表安全检查。
