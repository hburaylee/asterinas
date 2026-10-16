<!-- SPDX-License-Identifier: MPL-2.0 -->

# 仅在 carrier 边界安装与清理 CPU 上下文

决策状态：已接受、已实现并完成下述验证，2026-10-16。
选择 B，直接修改 `kernelet-host`，不新增开关。

## 两类状态

Task 的 `carrier_context` 保存该 carrier 的状态地址，在脱离 CPU 时仍需保留，
供下次调度恢复。CPU-local 的 `KERNELET_HOST_STATE_PTR` 表示当前正在运行的
carrier；`CpuSlot` 是当前实例、vCPU 和代次的身份槽。普通 Host 任务运行时，
CPU 上的这两项状态必须为空。

Host 使用这些状态定位当前实例并核对边界身份，随后访问其 TLS/FPU、地址空间、
停止状态等。服务入口还验证当前 Task 等条件；身份清理不能由那些检查替代。

## 当前转换

| 转换 | 切出 | 切入 |
| --- | --- | --- |
| 普通任务 → 普通任务 | 空指针检查后跳过 | 空指针检查后跳过 |
| 普通任务 → carrier | 跳过 | 安装指针、身份并恢复 carrier 状态 |
| carrier → 普通任务 | 保存 carrier 状态并清空 CPU 状态 | 跳过 |
| carrier A → carrier B | 保存 A 并清空 CPU 状态 | 安装并恢复 B |
| carrier 固定退出 | 清空 Task 地址并显式清空 CPU 状态 | 无需等待下次调度 |

调度器只有遇到非零 Task 地址才调用 pause/restore。这两个 unsafe 函数的契约
明确要求非零、有效且仍被 Task 固定的 carrier 地址。清理由独立的
`clear_carrier_context()` 完成，并同时用于 pause 尾部及 `set_carrier_context(0)`。
因此，普通任务的恢复路径不再承担替上一 carrier 清理的责任。

清理前完成 TLS/FPU 保存、Host 根页表安装、恢复标志及暂停时间记录，随后先
撤销公开身份，再清空 Host 私有指针。上述过程保持物理 IRQ 关闭；下一任务的
post-schedule handler 仍在新 carrier 恢复之后执行。carrier 状态直到清理完成
仍然有效，Task 执行所有权按原路径释放。

`CpuSlot` 的发布原语没有改变：鉴别字段仍通过单个对齐 QWORD 更新，保留字段
仍为零。这不意味着身份槽与私有指针构成一次原子事务。NMI 可观察到转换中的
状态，原有机器事件处理边界保留；本次没有增加 NMI 屏蔽或声称验证全部 NMI 时序。

## 开销边界

旧普通任务 A → B 路径会清空身份槽两次，共四条显式 GS 写指令，并写零到
CPU-local carrier 指针。现在这些额外写入从普通任务之间的切换中删除，保留
切入、切出各一次 Task 地址读取和条件判断。不将它描述为整个上下文切换没有
GS 写入，也不将静态指令减少换算为未测量的性能收益。

carrier A → B 相比旧实现会多一次私有指针清零，之后再安装 B；它用于维持
清理后的空状态。这一取舍优先缩短普通 Host 路径，不声称所有转换都减少写入。

## 验证

已有真实 entry/service/idle/fault/stop/unwind 夹具中增加身份断言：carrier 的
Host hook 读取到对应身份；carrier 停在 idle 服务时，普通 Task 读取到空身份
和空私有指针；正常、停止及异常退出后不残留 CPU 上下文。
实际结果：

- Host OSTD：356 passed、0 failed，含 3 项 VMX/EPT 能力不可用的环境自跳过。
  新增断言覆盖真实 idle 服务暂停后的普通 Task、entry 故障/停止路径，以及
  正常、stop 和 unwind 的 service 退出。原有 TLS、根页表和生命周期回归通过。
- paired Host+Image release 构建与 Image 审计成功。
- 2 Host vCPU、8 GiB KVM 中，两个单 vCPU Image 并发执行现有 TLS/MXCSR、
  pthread、信号和 fork 回归，两个结果均通过。同一 VM 的普通 Host 在 Image
  创建前及两个 Image 存活时执行相同程序，也都通过。两个实例均成功删除，
  VM 正常关闭。
- 初始双实例各配置 512 MiB 时返回 ENOSPC；日志保留。最终按既有每用户
  1 GiB 的 Guest ceiling 加 Host storage 总预约限制，各配置 384 MiB 后通过。
  没有修改资源限制、回归程序或降低断言。

产物在父 checkout 的 `.scratch/carrier-boundary-cleanup-20261016/`，最终真实
实例结果为 `functional-confirmed/result.json`。OSTD 默认启动缺失 ext2 磁盘
的退出 2 保留；实际套件来自同次 ISO 的无磁盘 QEMU 启动，原始退出码 33。
验证期间可执行源码无漂移。

没有记录每次 Host 任务切换，因此双实例并发不能证明实际发生了某次直接的
carrier A → B 转换。该转换的检查属于静态调用与状态顺序审查。未注入 NMI，
未做长期 SMP 压力或完整硬件寄存器数据验证。尚未测量性能收益。
