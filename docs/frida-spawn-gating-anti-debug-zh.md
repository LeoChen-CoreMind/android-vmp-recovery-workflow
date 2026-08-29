# Frida Spawn-Gating 反检测工作流

本文记录框架当前使用并已在真实 ARM64 设备流程中验证的 Frida 启动方式。它解决的是常见的服务名检测、旧服务冲突和 late-attach 时序问题，并保证 agent 在目标应用用户代码继续执行前加载。

这不是一个通用的“关闭所有反调试”补丁。框架没有默认修改 `ptrace`、`TracerPid`、Frida 协议特征、默认传输端口或应用自己的完整性校验。结论应写成“避开当前目标触发的常见 Frida/late-attach 检测”，不能扩展为对任意应用都有效。

## 实现组成

### 1. 固定并验证 Frida 服务端

真实设备 profile 固定以下属性：

- 本地文件：`tools/frida/media-server`
- 设备路径：`/data/local/tmp/media-server`
- Frida 版本：`17.9.1`
- SHA-256：`129278B9DCC817B20BED6B0BBC91208435D19D284401B841E70C17659B15D5B3`

`scripts/device/prepare_frida_server.py` 在每次设备运行前执行：

1. 验证 ADB 在线和 root shell。
2. 验证本地服务端 SHA-256。
3. 验证主机 Frida 客户端版本。
4. 停止 `frida-server`、`frida-server-17.9.1`、`fs1791` 和 `media-server`，并清理残留 PID。
5. 重新推送服务端并设置 `0755` 权限。
6. 在设备端重新计算 SHA-256，并与本地文件比较。
7. 验证设备服务端版本。
8. 以 root 启动唯一一个 `media-server` 实例。
9. 使用 `frida-ps -U` 验证主机到设备的连接。

改名可以避开只检查常见 `frida-server` 进程名的实现；哈希和版本固定用于保证可重复性，不是隐藏技术本身。

### 2. 只使用 spawn-gating

`scripts/dump/so/run_gating.py` 的顺序是：

```text
prepare/verify media-server
-> device.enable_spawn_gating()
-> force-stop target package
-> launch target package
-> receive spawn-added
-> attach spawned PID
-> create and load agent
-> resume spawned PID
```

关键点是 agent 在 `resume()` 前完成加载。应用不会先运行到自己的 Java/JNI 反调试初始化，再被 Frida late attach。

某些 Frida 17.9.1 `spawn-added` 事件最初会给出空 `identifier`。框架使用相同 PID 查询 `enumerate_pending_spawn()`，在有界重试内补全包标识；只有补全后的标识匹配目标包才 attach。每个事件都会写入 `spawn-events.json`，记录原始/解析标识、PID、是否命中目标、attach 和 resume 结果。

### 3. 在目标 JNI 初始化前取证

`scripts/dump/so/dump_linker.js` 不做 late-attach fallback。agent 通过系统 loader 观察外层加固模块装载，然后验证当前构建的 loader 签名和 exact dump 指令，再安装经过案件证据确认的 pre-`JNI_OnLoad` hook。

该 hook 的用途是让私有 linker 的 `soinfo`、`loadStart`、`loadSize`、program headers 和动态表处于可采集状态，同时避免目标 `JNI_OnLoad` 继续改变状态。偏移和指令签名必须来自当前案件，不能成为跨 APK 默认值。

## 重启后的恢复契约

手机重启会终止 root 服务端，因此不能复用之前的 Frida 会话。每次重启后必须重新执行完整准备步骤，而不是只检查文件是否还在：

```powershell
py -3 .\scripts\device\prepare_frida_server.py `
  --server .\tools\frida\media-server `
  --remote-server /data/local/tmp/media-server `
  --expected-version 17.9.1 `
  --expected-sha256 129278B9DCC817B20BED6B0BBC91208435D19D284401B841E70C17659B15D5B3 `
  --device <serial> `
  --log <case-log-dir>\frida-prepare.json
```

正常 SO dump 不需要单独运行该命令，因为 `run_gating.py` 默认会调用它。只有明确完成同一轮验证时才允许使用 `--no-prepare-server`。

## 证据和失败处理

每次运行至少保留：

- `frida-prepare.json`
- `frida-prepare.stdout.txt` / `frida-prepare.stderr.txt`
- `spawn-events.json`
- `frida-agent-events.json`
- `launcher.txt`
- 失败时的 `logcat.txt`、`exit-info.txt`、`processes.txt` 和 `frida-server-log.txt`

遇到白屏、超时或进程退出时，先确认只有一个 `media-server`，再检查 spawn 事件是否完成 attach/resume，以及 agent 是否在目标 JNI 初始化前输出预期事件。不要改成 late attach 作为兜底。

## 已知限制：私有手工映射代码区

真实设备取证表明，对私有 linker 的手工映射 dispatcher 代码直接执行 `Interceptor.attach()`，即使只挂一个入口，也可能改变页面/代码执行条件并导致 ART 在 `DexFileLoader::Open` 附近出现 `SIGSEGV`、`SEGV_ACCERR`。

因此框架采用以下边界：

- 外层已验证 loader 和 pre-`JNI_OnLoad` 位置可以按案件配置 hook。
- 私有手工映射区默认只做只读内存、指针和代码采集。
- dispatcher 表使用 exact fixed SO 的 IDA 分析，并由 Unicorn 对同一 SO 二次确认。
- 不能把“Frida 成功启动”解释为“任意私有代码地址都可安全 inline hook”。

这一限制必须保留在案件记录中；不能通过增加重试或换一个相邻地址来掩盖崩溃证据。
