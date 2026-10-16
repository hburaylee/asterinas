<!-- SPDX-License-Identifier: MPL-2.0 -->

# 栈空间认证复用固定布局和原子 live 位

已接受并实现，2026-10-16，对应第 14 项方案 B。upcall/yield 的栈空间认证
改为固定几何信息与一次 Acquire live 位读取；分配、释放和额度状态继续由
原栈池锁保护。日志与停止消息的栈范围判定、carrier 初始栈基址及布局读取
也复用此机制。没有增加普通 Host 路径检查或修改共享 ABI。

## 状态所有权与寿命

Host 私有的 `Arc<StackPoolLayout>` 同时持有 arena、固定边界和 atomic bitmap；
`ExecutionResources` 与锁内分配器各持一个引用。验证只借用布局，不在读路径
克隆 Arc，不读取非原子的 allocated/mapped/allocating 状态。固定额外元数据
计入资源预留预算。内部池类型和字段收窄为 private，调用者只能经资源接口
验证范围或请求分配、释放。

分配在映射及远端 TLB 确认完成后 Release 发布 live；释放在原锁下清 live，
保留已映射槽供复用。固定布局和 bitmap 不移动、不增长。跨 CPU Task 发布
仍遵守原来的队列锁和执行所有权协议；Acquire 读取不承诺墙钟意义上的最新
状态，也不建立 Task 身份的持续 pin。

验证保留完整边界条件：范围不倒置、处于同一个 live 栈槽、避开 guard，
以及 upcall reserve 下界。当前栈通过 `rsp-1` 定位，接受合法空栈 top，拒绝
零、上下溢出和越界。普通字节范围保留旧接口的空范围和上端点语义。

持续身份仍由受审计 vOSTD 的 Task Arc、switched_to_cpu 和退栈后释放协议
保护。原锁也只持有到布尔检查结束。本改动不增加对任意恶意 vOSTD 提前释放
其他 carrier 栈的防御承诺；未来若逐槽立即 unmap 或扩大该信任边界，需要
重设计 pin/回收协议。

## 同类路径检查

| 路径 | 结果 |
|---|---|
| upcall/yield 重定向的 reserve 校验 | 固定布局与 Acquire live 查询，移除栈池锁 |
| 日志、停止消息的栈字节范围判定 | 使用同一查询；Image→stack→grant 授权按顺序短路 |
| carrier 初始栈基址 | 固定 vCPU 范围和几何信息，无分配器锁 |
| 栈池 bounds 与 bitmap 地址读取 | 固定布局直接读取，无分配器锁 |
| 分配、释放、Task 额度、mapped slot 计数 | 可变状态，保留原锁 |
| grant 接受访问/销毁状态、页表根注册和 shootdown | 独立生命周期协议，保留原锁 |

短路授权只减少已经满足归属后的后续查询；源字节的共享借用授权、复制重叠
拒绝、异常恢复和真实失败语义保持原样。对已超出物理内存范围的地址，原
`owns_range` 本来就可能在取锁前失败，因此不将短路统一描述成省去一把 grant 锁。

## 验证边界

新增 Host 回归比较生产验证与独立的旧锁算法，覆盖持有分配器锁时仍可调用
全部只读接口、未发布/分配/释放/复用、boot/普通/末槽及端点笛卡尔积。
另一回归在真实远端 CPU 上验证发布、清位和复用可见性，并让两个 CPU 各
更新同一 bitmap word 的不同位 4096 次。直接位更新仅验证原子协议，不能
冒充实际 Task 身份或生命周期保护。

Host/Native OSTD、配对 release 构建、真实 Image 与并发 Image 回归及发布版
反汇编收据见父 checkout 的 `.scratch/stack-live-validation-20261016/REPORT.md`。
独立审查见同目录 `REVIEW.md`。本次未测量速度收益。

实施前的机制比较与原始资料保留在
[调研记录](../research/0014-upcall-stack-validation.md)。
