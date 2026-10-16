<!-- SPDX-License-Identifier: MPL-2.0 -->

# 普通 Host 尽早跳过 Image 中断返回处理

决策状态：已接受并实现，2026-10-16。直接修改 `kernelet-host`，不新增开关或状态。

## 修改

`finish_image_trap()` 最前面读取一次 Host 私有 CPU-local carrier 指针。为空则
立即返回，普通 Host 无需执行该钩子的返回特权级、中断层级、身份及 Image 状态
检查。Host 原有的 IRQ 回调、异常分类、确认和返回流程保留。

指针非空后，先检查返回特权级和中断层级。只有允许的任务上下文才解引用该指针，
并按原路径验证当前 Task、CpuSlot 的 vCPU、注册表中的实例身份和代次。验证部分
提取为私有 `carrier_state_from_ptr()`，复用已读取的地址，不再次读取 CPU slot。
其他调用者通过原有 `current_carrier_state()` 读取并委托同一个验证实现。

非空检查只决定是否需要继续检查，不构成身份认证。其正确性依赖既有 carrier
边界：进入/恢复时安装 CPU 指针，暂停/固定退出时清空，普通 Host Task 不保留
前一个 carrier 的指针。物理 IRQ 保持关闭，读指针到验证之间不跨上下文切换。
嵌套 IRQ 上下文只读取并判断该私有地址，不提前访问 carrier 状态。

虚拟 tick、停止请求、临界区、CPU-local 指令区域、专用 yield/virq 重定向及
栈边界验证保留。Host 用户拷贝故障恢复仍独立处理，因为普通 Host Task 也可能
执行相应拷贝，不能将它收进 carrier 专属门槛。

## 开销与验证边界

普通 Host 在这个 Image 返回钩子中只承担一次 CPU-local 指针读取及空值分支。
不将它描述为整条物理中断路径只有一次检查；正常 IRQ 入口的异常分类等仍存在。
没有测量加速幅度，也不将这一项称为已证明的性能瓶颈。

发布版反汇编确认空指针分支在 `InterruptLevel::current()` 调用之前直接进入
返回序列，carrier 的后续认证使用同一次指针读取。真实 carrier 的中断停止夹具
增加回归：停止已经发布时，在 L1 IRQ 回调中尝试执行 Image 返回处理，RIP、RSP
及 RFLAGS 均保持不变；外层 L0 返回继续执行原有停止逻辑。

实际验证记录位于父 checkout 的
`.scratch/carrier-trap-fastpath-20261016/VERIFICATION.md`。
