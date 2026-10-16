<!-- SPDX-License-Identifier: MPL-2.0 -->

# 在 carrier 边界维护普通 Host 地址空间缓存

决策状态：已接受并实现，2026-10-16。选择 B，直接修改 `kernelet-host`，不新增开关。

## 原因与范围

普通 Host 的 `VmSpace::activate()` 原本在 CPU-local 地址空间指针匹配时直接
返回。开启 Host 支持后，该路径还会读取 CR3 并比较页表根，用于防御 carrier
临时切换硬件页表后仍保留普通地址空间软件记录的情况。

carrier 暂停、进入可调度服务及固定退出已经调用 `VmSpace::deactivate()`。
但首次进入 Image 前没有统一执行该边界；特别是早期停止和故障入口，可以从
普通 Host 地址空间直接进入固定汇编，并由汇编改写 CR3。

现在 `host_run::enter()` 在所有可失败的资源准备完成之后、发布 carrier 指针
及执行固定入口之前，调用已有 `state.install_host_root()`。该边界在物理 IRQ
关闭时安装永久内核页表，释放 CPU 持有的旧普通 `VmSpace` 引用及活跃 CPU 位，
并清除 carrier 的根恢复标志。

因此普通 Host 缓存命中恢复为指针比较后直接返回，无需读取 CR3。Image 内部
Task 的缓存和硬件页表复核保留，因为其 Task 缓存仍可能跨越临时换根。

## 安全约束

- 首次进入：清理普通地址空间后才发布 carrier 并开放物理 IRQ。
- Image 根准备及 user_run：保留根注册、有效性验证、活跃 CPU 预约和代次处理。
  预约与最终 CR3 提交之间保持物理 IRQ 关闭；普通地址空间缓存不会留在该路径。
- carrier 暂停及可调度服务：先安装 Host 根，再移出注册根的活跃集合。恢复时
  由原有 post-schedule handler 激活 carrier 地址空间。
- 固定正常、故障和停止退出：汇编恢复 Host 根后，Rust 清理注册根预约与软件
  记录，最后撤销 carrier 身份。该清理仍可处理保守保留的活跃 CPU 位。

`MANAGED_ROOT_PADDR` 及 Host 原生页表 Frame 引用管理保留；不能将注册的 Image
根当成 Host Frame 释放。远程 TLB 确认和旧页面回收顺序保持原实现。

## 开销边界

本次只删除普通 Host 缓存命中时额外的硬件页表根读取及比较。carrier 首次进入
增加一次已有清理边界调用；真实页表转换是否发生由已有页表激活逻辑决定。
`VmSpace` 的 carrier 类型判断、局部中断保护和底层原生根引用管理仍保留。
没有将静态指令减少换算成未测量的性能收益。

## 验证

新增真实汇编入口在第一次服务调用之前验证永久 Host 页表已经安装。正常进入、
早期停止、无效栈、栈保护页、编译器大栈帧及中断停止夹具均从普通 Host 地址空间
开始，退出后验证引用释放，并重新激活同一普通地址空间。

普通地址空间重复激活与引用回收的测试现在同时运行于 Native 和 Host 配置。
原来直接改写 CR3 却保留普通缓存的模拟，改为经过真实清理边界；注册根借用、
代次、失效和回收的独立测试保留。实际验证记录见父 checkout 的
`.scratch/native-vmspace-fastpath-20261016/VERIFICATION.md`。
