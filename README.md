# Android 某6零免费版 DexVMP 恢复工作流

这是一个面向 Android 某6零免费版 DexVMP 学习研究的本地、可恢复工作流框架，目标是把符合条件的某6零免费版加固样本还原为可运行的正常程序，并完整记录验证证据。项目使用 `vmpwf` 按阶段记录输入、配置、日志、产物和 SHA-256，帮助研究者理解运行时 DEX、私有 linker、虚拟机 dispatcher，以及 DEX 恢复和重打包验证过程。

> **学习与研究声明**：本项目仅用于 Android 安全、逆向工程和软件保护机制的学习研究。请只处理自己拥有或明确获准分析的 APK、DEX、SO 和设备，不要将本项目用于绕过商业授权、盗版校验、账号风控或其他未授权用途。所有案件证据默认保存在本地，不上传到外部服务。

本框架已经在实际研究中成功完成过程序还原流程。基于当前工作流设计，理论上对某6零免费版加固样本具有通用的分析与还原路径，但不同 APK、Android 版本、ABI、加固版本和业务校验仍需以当前案件证据为准，不承诺无需适配即可覆盖所有样本。

> **适用范围（请先阅读）**：本项目只针对某6零免费版样本的学习研究和授权分析。付费版、商业版及其专属保护方案不在本项目提供范围内，不提供对应样本、参数、适配、还原服务或技术支持；任何付费版请求均不受理。

**非商用与法律声明**：本项目及相关文档仅供个人学习、技术交流和经授权的安全研究使用，不提供商业化服务，不面向付费版或商业版提供任何技术支持，不授权将其用于破解收费软件、绕过授权/签名/风控、盗版分发或任何侵犯他人权益的行为。使用者应自行确认目标软件、数据和设备的合法授权，并自行承担使用本项目产生的法律责任。

如发现本文或仓库内容涉及权利、隐私、授权范围或其他需要处理的问题，请发送邮件至 `leochen-job@outlook.com`，说明具体链接、文件和理由；收到有效通知后会及时核查并配合下架相关内容。

## 你将学到什么

- 如何从 APK 和运行时 DEX 建立可追溯的案件输入。
- 如何在真机上确认包名、版本、ABI、安装路径和 root 能力。
- 如何通过 spawn-gating 在目标 `JNI_OnLoad` 前采集私有 linker/SO 证据。
- 如何用 SoFixer、IDA Pro MCP 和 Unicorn 对同一份 SO 建立交叉验证。
- 为什么只有存在真实 VMP method records 时，才可以进入方法级 DEX 恢复。
- 如何使用当前 APK 的独立证据生成某6零去特征 adapter，并完成 DEX、Manifest、签名和设备验收。

## 工作流总览

```text
APK/DEX 输入
  -> DEX 提取与清单
  -> 真机目标确认
  -> 私有 linker/SO dump
  -> SO 修复
  -> IDA Pro MCP 导出 256 项 dispatcher 表
  -> Unicorn 对同一 SO 原生确认
  -> 有 method records 时恢复 DEX
  -> dexdump/JADX/哈希独立验收
  -> 当前版本某6零去特征、重打包、签名与设备验收
```

每个阶段都是独立 checkpoint。遇到未知偏移、多个候选、哈希冲突或工具缺失时，流程会停在 `BLOCKED`，通过 `vmpwf resume` 在阶段边界加载新证据，不手工改写状态文件。

## 使用方法

完整的安装要求、JADX 与 IDA Pro MCP 准备、ADB/root 真机检查、命令模板、案件目录、阻塞恢复和验收标准，请进入：

**[使用方法](docs/使用方法.md)**

## 核心约束

1. 真实设备使用 `android-arm64-360-dexvmp` profile；32 位 ABI 会在启动 Frida/Unicorn 前拒绝。
2. 设备执行必须显式使用 `--execute-device`，且设备需要 ADB 在线和可用的 `su`/root shell。
3. SO dump 入口只有 `scripts/dump/so/run_gating.py` + `scripts/dump/so/dump_linker.js`，不使用 late attach，也不调用已移除的 `dump_libjiagu.js`。
4. `tools/frida/media-server` 必须按 profile 的版本和 SHA-256 校验后部署；设备重启后必须重新部署。
5. IDA 必须分析当前案件 revision 的 exact fixed SO；IDA 的 `image_base` 与运行时 `pointer_base` 分开记录。
6. dispatcher 表必须覆盖 `0..255`，并由 Unicorn 对同一 SO 达到 256/256 匹配、零非法内存、零未知外部调用。
7. 所有 DEX 输入在 `dex-restore` 前都视为未修复。`method_records=0` 时只能完成 SO/dispatcher 范围验收，不能声称恢复了 VMP 方法。
8. 去壳和重打包必须按当前 APK/revision 单独生成 adapter，禁止复用其他 APK 的 RVA、Application、DEX 布局、调用次数或补丁常量。

## 提示词与参考资料

- [本地全自动操作提示词](prompts/local_autonomous_operator_zh.md)
- [热更新操作提示词](prompts/hot_update_operator_zh.md)
- [Frida spawn-gating 与反调试边界](docs/frida-spawn-gating-anti-debug-zh.md)
- [去特征脱敏案例](docs/360-apk-repack-sanitized-case-study-zh.md)
- [看雪论坛帖子草稿](docs/看雪论坛帖子.md)

提示词只描述本地、可审计的研究流程；未知事实必须由当前案件证据确定，不能从 fixture、旧案件或其他 APK 推断。

## 仓库结构

```text
vmpwf.py                         CLI 入口
vmpwf/                           工作流与阶段插件
scripts/dump/so/                 spawn-gating 与私有 linker 采集
scripts/ida/                     IDA 响应和 dispatcher 验证工具
scripts/simulation/              Unicorn/native confirmation
scripts/apk/                     DEX、Manifest、重打包参考工具
prompts/                         阶段提示词
schemas/                         JSON 合同
cases/                           本地案件证据目录
docs/                            使用说明与技术案例
```

## 快速检查

```powershell
py -3 .\vmpwf.py doctor
py -3 .\vmpwf.py recover `
  --apk "C:\path\target.apk" `
  --profile android-arm64-360-dexvmp
py -3 .\vmpwf.py run --case .\cases\com.example.app\<case-id> --execute-device
```

如果已有运行时 DEX，可额外提供 `--dex-zip` 或 `--dex-dir`。完整参数和阶段说明以[使用方法](docs/使用方法.md)为准。

## 开发说明

SoFixer、Java/JADX、Android SDK `dexdump`、IDA Pro MCP、Frida 和 Unicorn 都属于本地外部依赖。框架不会上传客户文件，也不会把示例 fixture 当作真实 APK 证据。
