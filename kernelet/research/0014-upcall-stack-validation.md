<!-- SPDX-License-Identifier: MPL-2.0 -->

# 第 14 项调研：upcall 栈认证中的共享锁

状态：实施前的设计调研快照。方案 B 随后已实施，当前实现与验证见
[决策记录](../decisions/0012-stack-live-validation.md)。以下源码哈希与比较保留
调研阶段的状态；本调研没有性能测量。

## 结论

当前最小的候选是复用 Host 私有的固定 arena 布局和 live bitmap，把 upcall 的**瞬时空间归属认证**改为边界计算加一次 Acquire 原子读取。这个候选可以避免读路径的实例锁；成立前提是 arena/bitmap 的整体寿命、slot 映射保留规则、Image 执行所有权协议继续有效。它不提供 Task 身份或 slot 代次的持续 pin。不能把“映射未撤销”推导成“对象未更换”。

这属于经典的三个问题：地址范围属于哪个固定池、该位置此刻是否发布为 live、同一个执行对象是否在整个使用期存活。前两项可以只读认证；第三项必须由所有权或回收协议负责。把三项混为一谈会误选 RCU、seqcount 或裸引用计数。

## 当前源码身份与读取范围

工作区：`/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015`。HEAD 为 `fa17efba049ef0f6511ebd9c33b05be7a104bb1e`，工作区存在并行未提交修改，因此不能单靠 HEAD 复现本结论。以下 SHA256 固定本次直接读取的相关文件，不包含其他 session 的无关改动。

记录时间：2026-10-16T12:24:38.075084+00:00。

| 文件 | SHA256 |
|---|---|
| `ostd/src/kernelet/control.rs` | `966efac6920686ff59b26911632eddd1b11eed33373fee00adf9706f3a9d33f7` |
| `ostd/src/kernelet/host_run.rs` | `14c9af25f9dbdf545d883169daa2688eccef0c8ca214ef697040d259a4069c21` |
| `ostd/src/kernelet/host_run.S` | `1ca29b40318e517a4ebab823f6adb1220896107e72d6b35c5d1c911e62a82ebc` |
| `ostd/src/kernelet/host_run/resources.rs` | `8b29054b3409ac0fbcd256a1d0a34ff05aa6537a8f555d957a832b801417190a` |
| `ostd/src/task/processor.rs` | `cf058377ae2a31f9cb42bbe5ad90efcdf138f5139f2f43173d53dd6a5f587a27` |
| `ostd/src/task/kernelet_stack.rs` | `a1eb0303fba67dc78822a388732233da2b6312cfff118186ad1ee5f4755b38fd` |
| `ostd/src/mm/kspace/kvirt_area.rs` | `cf2a7e4954043a724ac500468c2d8f501f531ecbdb6b3051bb72937bae997d0c` |

图索引显示部分路径已变化，汇编索引不完整；本次以直接源文件读取为准。未实施或验证本文候选，也未审查整个 dirty tree。

## 当前检查保护什么

[redirect_image_return](/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015/ostd/src/kernelet/host_run.rs:921) 先计算 `rsp-UPCALL_STACK_RESERVE`，在 `stacks.lock()` 下验证同一个已分配 slot 及整个保留范围。锁在布尔条件求值后已经释放，后面的 trap-frame 改写、IRET 和 Image stub 执行都不持有它。因此，这把锁没有单独把原 Task 或 slot 身份 pin 到 upcall 完成。

[StackPool](/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015/ostd/src/kernelet/host_run/resources.rs:310) 创建时固定 arena、slot 数量和 bitmap；[stack_pool_layout](/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015/ostd/src/kernelet/host_run/resources.rs:188) 把稳定 bounds/bitmap 地址交给 carrier。[分配](/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015/ostd/src/kernelet/host_run/resources.rs:215) 在锁外完成 mapping 与远端 TLB ack，然后置 allocated、Release 发布 live；[释放](/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015/ostd/src/kernelet/host_run/resources.rs:407) 校验地址及请求者当前栈后清 allocated/live，不解除映射。[KVirtArea::drop](/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015/ostd/src/mm/kspace/kvirt_area.rs:498) 才解除整个区域，并通过同步回收路径等实际 TLB acknowledgement。

[服务汇编入口](/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015/ostd/src/kernelet/host_run.S:93) 已经用固定 bounds、算术和 bitmap 位检查认证栈，说明这些数据可在 carrier 寿命内稳定提供。它不是 upcall 端点语义的完整实现：upcall 必须继续用 `rsp-1` 归属空栈 top，不能直接照搬服务入口的向下对齐。

## 身份在检查之后由谁保护

正常 Image 路径中，[switch_to_task](/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015/ostd/src/task/processor.rs:110) 在 CURRENT/PREVIOUS CPU-local cell 中转移 Task 的 Arc 引用；[before_switching_to](/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015/ostd/src/task/processor.rs:195) 先取得 incoming 的 switched_to_cpu 执行权。[after_switching_to](/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015/ostd/src/task/processor.rs:251) 保留 outgoing Arc，处理完交接再 Release 执行权，随后才 drop previous 引用。[KernelStack::drop](/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015/ostd/src/task/kernelet_stack.rs:94) 才向 Host 释放普通 slot；bootstrap 则明确在新栈上退休。

[carrier 入口](/home/ubuntu/asterinas/.scratch/kernelet-rebase-20261015/ostd/src/kernelet/control.rs:1626) 在调用固定入口前 clone resources/execution Arcs，并保留到固定出口返回，提供整体 arena/bitmap 寿命。`KernelStack` 及其服务入口保持 crate-private，正常可达调用遵守受审计 vOSTD 的 Task 引用/执行权约定。

据此，正常 Task 生命周期的持续保护来自 Image 引用/执行权和退栈后的释放约定；Host 的短验证锁与固定映射是额外的空间认证及底层存储寿命。Host `free()` 只拒绝请求 carrier 的 saved_rsp 命中该 slot，不扫描其他 carrier 或验证一个 Host-owned Task generation。本文没有证明恶意/损坏 vOSTD 跨 carrier 提前释放活跃栈会被 Host 完全阻止。

这一限制也存在于当前“验证完就放锁”的方案中。bitmap 候选只能替换同一层的认证，不能以“已有锁也有窗口”证明所有身份攻击都安全；如果目标要求 Host 强制持续身份保护，应单独引入 pin/代次协议并定义其起止。

## 经典机制与本题的适用性

| 机制 | 原本解决的事 | 对本题的判断 |
|---|---|---|
| 固定布局 + live 位 | 固定池的位置和发布状态 | 在整体寿命已保留、布局不可变时，可以无锁检查 membership；不证明旧 Task 身份 |
| 引用计数 | 最后一个持有者结束后才释放对象 | Image 已有 Task Arc；若 Host 另建 pin，获取 pin 本身也须与退役串行，不能先拿裸地址再无条件加计数 |
| RCU | 移除引用后，等待旧 reader 退出再回收 | 适合未来要动态替换目录或回收映射的情况；当前目录不替换，直接引入会增加回收协议。RCU 读区间如果在实际使用前结束，也不再保护使用期 |
| seqcount | 读者重试以取得一致的多字段快照 | 当前几何信息固定，动态信息仅一位；不需要多字段一致快照。seqcount 本身不防对象释放，并需避免 hardirq reader 抢占奇数代次 writer |
| hazard pointer | reader 发布保护，reclaimer 延迟被保护对象的回收 | 可实现持续保护，但需保护发布、源值复核、清除和退役扫描；是更强的回收模型，不能降成一个 live load |
| generation + pin | 验证身份代次，并阻止该代次在使用期回收 | 若确实要求 Host 的持续 Task 身份保证才需要。只有“读两遍 generation”仍有最后一次检查之后的使用窗口 |

Linux 的 [RCU 说明](https://docs.kernel.org/RCU/whatisRCU.html) 将移除和回收分开，并要求在 reader 结束后才能回收。本文仅据此区分发布和寿命，不将某种 Linux RCU 配置的指令成本搬到本项目。固定参考为 [Linux v6.16 原始文档](https://raw.githubusercontent.com/torvalds/linux/v6.16/Documentation/RCU/whatisRCU.rst)。

Linux [seqcount 文档](https://docs.kernel.org/locking/seqlock.html) 明确提示 writer 不能被 reader 中断，且不能用它保护会被 writer 失效的指针。固定参考为 [v6.16 seqlock.rst](https://raw.githubusercontent.com/torvalds/linux/v6.16/Documentation/locking/seqlock.rst)。因此，seqcount 不是“便宜的对象寿命锁”。

Linux [kref 规则](https://docs.kernel.org/core-api/kref.html#kref-rules) 要求持有有效引用再复制引用；从查找结构首次获得引用时要与释放串行。其 [refcount 内存序说明](https://docs.kernel.org/core-api/refcount-vs-atomic.html) 也不能替代首次获取时的生命周期证明。这直接排除“从 RSP 算到地址后无条件 fetch_add pin 就安全”的推导。

最接近本题的官方反例是 [SLAB_TYPESAFE_BY_RCU](https://docs.kernel.org/core-api/mm-api.html#c.SLAB_TYPESAFE_BY_RCU)：延迟释放底层 page 不阻止对象在该地址重用，身份校验仍是独立要求。[Linux v6.16 slab.h](https://raw.githubusercontent.com/torvalds/linux/v6.16/include/linux/slab.h) 保留该说明。因此 `live:1→0→1` 对旧地址查询不可区分代次；但若接口只回答当前固定位置的 membership，代次未必是接口要求。

[Michael 2004 原论文的 IBM 作者机构页面](https://research.ibm.com/publications/hazard-pointers-safe-memory-reclamation-for-lock-free-objects) 说明 hazard pointers 面向安全回收与 ABA；这里只读取其摘要，不援引未读取的实验正文或性能结论。操作协议以作者参与的 [WG21 P2530R3](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/p2530r3.pdf) 第 2 节及 try_protect 规范为依据：保护地址后再读取源并比较，退役对象等保护结束后才回收。本文不是宣称该 2023 提案就是当前语言标准。

Linux [atomic bitops 文档](https://docs.kernel.org/core-api/wrappers/atomic_bitops.html) 区分普通位测试、原子 RMW 和 acquire 位测试；“位操作”不自动提供发布内存序。本项目候选应明确使用 `AtomicU64::load(Acquire)` 与已有 Release 发布配对，并保持 writer 对同一个 word 的原子更新，不能把整字改成非原子读改写。

## 候选方案与操作成本

以下是源码级操作结构，不是已编译指令数或时间测量；不预设所有机制都更慢。

| 方案 | 重定向读路径 | 分配/释放路径 | 条件与作用 |
|---|---|---|---|
| 保留当前锁 | 取/放实例锁、读取 slot、计算边界 | 现有池锁和 live 更新 | 实现已存在；只在验证期间互斥 |
| 固定布局 + Acquire live | checked 算术和范围分支、一次 bitmap word 原子 load、mask；不写共享锁字 | 保留现有池锁、Release bit 发布/清除 | 当前最小候选；没有额外 per-read refcount/CAS；保持当前空间认证，不新增 identity pin |
| 每 slot 短锁 | 算 slot、取/放命中 slot 锁、验证 | 全局→slot 的固定锁序 | 可消除不同 slot 的锁争用，但多一套锁和状态拆分，仍只锁到验证结束 |
| seqcount 快照 | seq load、状态读、seq 复核及可能重试 | writer 代次更新及串行 | 本题没有需要读取的可变几何快照；仍需独立寿命协议 |
| RCU / hazard pointer / Host pin | 读区间或保护发布/验证/清除；具体成本依实现 | 延迟回收或等 pin，可能保留旧代次 | 只在需求升级为动态回收或持续身份保护时考虑，不能宣称免费 |

本地工具链另有一个实际生成汇编的最小示例：[源码](/home/ubuntu/asterinas/.scratch/upcall-stack-research-20261016/atomic_codegen.rs)、[汇编](/home/ubuntu/asterinas/.scratch/upcall-stack-research-20261016/atomic_codegen.s)、[命令和工具链 receipt](/home/ubuntu/asterinas/.scratch/upcall-stack-research-20261016/receipt.json)。它在 Docker 内用 rustc `1.99.0-nightly (87e5904f5)`、LLVM `22.1.8`、x86_64 Linux target、`opt-level=3` 生成：

```asm
# AtomicU64::load(Acquire) & mask != 0
movq (%rdi), %rax
testq %rsi, %rax
setne %al

# AtomicBool::compare_exchange(false, true, Acquire, Relaxed)
lock cmpxchgb %cl, (%rdi)

# AtomicBool::store(false, Release)
movb $0, (%rdi)
```

这证明在该示例与工具链下，Acquire live 读取没有 LOCK 指令或独立 fence，CAS 取锁有 LOCK 前缀。示例省略上表的地址计算、范围分支、循环和完整 OS 调用路径；它不是生产 OSDK ELF 的完整校验函数反汇编，也不是性能测试。不能据此给出纳秒或加速倍数。RCU 在某些配置中的读侧可以无需额外指令；本题不选它的理由是当前不需要目录替换和按 reader 延迟回收的额外协议，而非宣称其读侧必然更慢。

不建议只因这是经典读多写少问题就引入 RCU。先证明本接口需要的层次：若只需现有 membership，固定结构已消除目录回收问题，live 位是剩余的动态输入。若要持续身份保证，则应先定义保护结束点：仅改 trap frame 时结束，还是必须覆盖 IRET、Image stub 甚至整个 Task 执行期。不同结束点对应不同实现。

## 最小候选的必要前提

1. start/end/stride/usable bounds 由 Host 建立且不改变；bitmap 元素数量与地址固定，不从 Guest 发布数据取这些界限。
2. execution resources 保留整个 arena/bitmap 至所有 carrier 固定退出；不能只保持原 Vec 指针而允许容器搬移或 Drop。
3. live 位只能在 mapping 与跨 CPU 可见性完成后发布；失败和 allocating 状态不发布。 跨 vCPU 交接 Task 的现有队列锁/所有权发布还须保留，使分配发布先于接收方执行；Acquire load 本身不承诺读取任意墙钟时刻的最新值，也不授予对象寿命。
4. free 后暂不 unmap，live 更新与分配元数据继续由池锁串行；reader 不访问非原子 slot mutable 字段。
5. 按 `rsp-1` 定位并做 bounds 检查后，才形成 bitmap 元素地址；避免非法 RSP 导致 bitmap OOB。reserve 全范围必须位于一个 usable slot，零、溢出、guard、跨 slot 均拒绝。
6. Image Task Arc/执行权和退栈后释放协议继续提供正常运行时的身份寿命；若要求抵御破坏该协议的 vOSTD，bitmap 与当前短锁都不能充当完整证明。

## 不能从当前证据得出的结论

- 一次 live load 不能证明同一 Task/代次一直有效到 upcall 结束。
- 单独保留物理页和映射不能防止栈内容或对象身份被重用。
- 仅给对象加 generation 不能阻止最后一次校验后回收。
- 局部物理 IRQ 关闭不阻止其他 CPU free/reuse；它也不自动构成跨 Image 的通用 RCU grace period。
- 现有汇编使用 bitmap 不等于已证明 Rust 等价实现的所有端点、内存序和寿命。
- 尚无本项 performance measurement；没有依据给出百分比收益或“一个指令完成全部校验”。

## 实施前及实施后的验证计划

- 把当前锁版布尔检查作为空间语义参考，在稳定状态逐项比较 bitmap 候选：boot/普通/末 slot、合法空栈 top、top+1、底界、zero、checked-sub 下溢、跨 slot、未分配、allocating、free 后、reuse 后。
- 在真实两个 CPU 上控制分配发布：完成 mapping/ack 前位为零，发布后合法；同步 free 之后位清除；不同 slot 的位更新不能互相覆盖。测试须明确并发交错覆盖范围。
- 在保持 execution resources 引用时测试 validation 与 free/reuse 交错，验证空间结果允许旧/新瞬时状态；另用代次断言展示 live bit 本身不能拒绝 ABA，避免把它误测成 identity 保护。
- 用真实 Image Task 创建、退出、迁移、bootstrap 退休和 destroy 压力验证原 owner 协议及整体资源寿命；这类测试与 Host-only pool membership 测试分开报告。
- 复查 Host service 汇编与 Rust 校验端点一致性；空栈 top 特别处理。普通 Host 路径不应增加新检查或共享写入。
- 对最终 release ELF 检查重定向校验不再调用池锁、保留所有 reject 分支，再测正常 upcall/yield 和同时 create/free 情况下的开销。记录 source/build/QEMU 身份、时间边界及统计，不把源码操作计数写成速度结果。

调研阶段只交付本文，其时所有候选未实施。后续实现状态以所链接决策记录为准。
