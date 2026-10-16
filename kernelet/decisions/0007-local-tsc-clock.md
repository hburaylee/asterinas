<!-- SPDX-License-Identifier: MPL-2.0 -->

# Image 本地读取 TSC，移除 Host 周期时钟发布

已接受并实现，2026-10-16。用户选择把时间换算放到实际读取的位置，减少 Host
周期维护；读时间不调用 Host 服务，不切换到 Host 栈。本次不声称整体性能已加速。

与 kernelet-book main `2d0d5769` 的
[Time 设计](https://github.com/tatetian/kernelet-book/blob/2d0d5769be63f465aebfe8312dfa558453502821/src/blueprint/asterinas-mode/virtualizing-ostd/interrupts-and-time.md#time)
存在有意差异：book 共享 Host 动态时间快照，本实现仅在只读 BootArgs 中发布
固定的 TSC 频率与 Host-boot 时间原点。所有实例使用同一原点，时间在 carrier
未运行期间仍前进。Image 使用现有 ordered TSC 读取、整数换算和实例私有原子
最大值返回时间；Host 仅在创建和 idle 等实际需要时间的位置按需读取。

删除 ClockPage、物理页分配与映射、对应内存收费、Host tick 和 idle 返回路径
中的 publish。共享元数据布局收紧一页。BootArgs 的布局改变而总大小仍为
2336 字节；必须重建匹配的 Host/Image，并依赖共同源码 hash 拒绝旧构建，不能
仅凭结构大小判断兼容。realtime 的实例创建锚点语义保留。

实例私有最大值保留不回退语义，但无法修复 TSC 频率变化或 CPU 间的真实时钟
偏差。时间精度依赖稳定、同步的 TSC；本次没有声称支持不满足此条件的机器或
任意虚拟机迁移。共享参数保持只读，unsafe 仍限于 OSTD；未扩大 Image 指令权限。

Host 的期限唤醒机制独立保留。Image idle 仍把 Host-boot 期限的剩余时长转换到
Host 期限时钟域；不能等 Image 下次读时间才唤醒正在睡眠的 carrier。

验证产物位于父 checkout 的 `.scratch/local-tsc-clock-20261016/REPORT.md`。
Host OSTD 361 项、Native OSTD 258 项报告通过，各有 3 项 VMX/EPT 自行跳过。
Host 与真实 Image 均通过连续读时钟、相对/绝对休眠和 timerfd 截止时间回归。
两 CPU IPI 测试验证了不同 CPU 上的实际 TSC 换算及单调保护。用户态跨 CPU
交接测试因候选线程均运行于 CPU0 而失败，原始日志保留；该项没有视为通过。
这些是功能验证，不是性能测量或所有 TSC 平台的准确性证明。
