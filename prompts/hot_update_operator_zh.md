# VMP Workflow 热更新操作提示词

此提示词用于已有案件进入 `BLOCKED`、配置需要修正、框架问题已修复后恢复执行的场景。它只保存在仓库中，不要求安装 Skill。

```text
你现在负责对 Android VMP Recovery Workflow 的已有案件执行有证据约束的热更新和恢复。

框架目录：
C:\Users\Rabe\Desktop\360\vmp-recovery-workflow

案件目录：
<填写 cases\package\case-id 的绝对路径>

问题 ID：
<填写 q-xxxx；如果未知，先读取 questions.json 找唯一 open 问题>

作者提供的新信息：
<填写 offset、配置 JSON、DEX 路径、IDA response、simulation config 或框架补丁说明；没有则写 null>

必须先确认热更新边界：

- 热更新只在阶段边界重新加载 `case.json`、`workflow/*.json` 和 profile 配置。
- 不得向正在运行的 Frida hook、spawn-gating 会话或 Unicorn 实例强制注入新配置。
- 所有更新必须通过 `vmpwf resume` 应用；不要手工修改 `checkpoint.json`、`questions.json`、`events.jsonl` 或 stage records。
- 每次 resume 必须使 `config_revision` 递增，归档失效阶段到 `stage_history`，保留旧 revision 产物和 artifact ledger。

执行步骤：

1. 运行 `py -3 .\vmpwf.py doctor`，然后读取案件的 `case.json`、`checkpoint.json`、`questions.json`、`events.jsonl` 和 `artifacts.json`。
2. 确认问题 ID 仍为 `open`，记录 blocked stage、message、evidence、expected fields 和当前 `config_revision`。
3. 打开问题引用的证据文件，复现或验证失败。不能只根据问题 message 生成答案。
4. 判断新信息解决的是当前阶段，还是证明更早阶段的产物无效。`invalidate_from` 必须选择最早真正受影响的阶段，不能为了少重跑而选择过晚阶段，也不能无依据扩大重跑范围。
5. 只使用框架允许的 answer 字段：`commands`、`ida`、`simulation`、`artifacts`、`profile`、`device_serial`、`dex_inputs`、`dex_dir`、`dex_zip`、`apk`、`tools`、`command_timeout`、`target_confirmed`、`execute_device`、`so_dump_config`、`apk_repack`、`invalidate_from`。
6. 在案件 `answers/` 下创建最小 answer JSON。答案只能包含已由作者提供或由本地证据唯一确定的值。
7. 执行：
   `py -3 .\vmpwf.py resume --case <case-dir> --question <q-id> --answer <answer.json>`
8. resume 后立即检查：问题是否 answered、revision 是否递增、旧阶段是否进入 `stage_history`、下游阶段是否按依赖失效、旧产物是否仍存在、新事件是否写入、流程是否继续到下一个阶段或新的 BLOCKED。
9. 如果出现新的 BLOCKED，重新从证据分析开始，不要连续提交猜测答案。
10. 如果修改了框架代码，先写最小回归测试，运行完整 pytest、`git diff --check` 和 doctor；测试通过后再让案件从阶段边界恢复。

常见失效起点：

- APK 或 DEX 输入发生变化：`dex-extract`，必要时更早到 `apk-ingest`。
- 设备目标、ABI 或包身份错误：`target-confirm`。
- dump offset、soinfo 布局、Frida 时机或 dump 产物错误：`so-dump`。
- SoFixer 参数或 ELF 修复产物错误：`so-repair`。
- dispatcher root、pointer base、IDA response 或 handler 表错误：`ida-export`。
- VM width/opcode/reference 或 method stream 错误：`vm-static`。
- Unicorn PLT、重定位、内存映射或原生结果错误：`native-sim`。
- DEX 回写、class_data 长度或 repair manifest 错误：`dex-restore`。
- dexdump/JADX/哈希验收配置错误：`independent-validate`。
- 当前版本去壳 adapter、Manifest/DEX 映射、精确删除项、bridge、签名或设备验收错误：`apk-unpack-repack`。

必须向作者提问的情况：

- 新 offset、RVA、handler width、opcode 语义或 DEX 来源无法由证据唯一确定。
- 多个候选都能通过部分检查。
- 作者提供的信息与当前二进制 SHA-256、设备版本或案件 revision 不匹配。
- 需要决定是否更换 APK/DEX、接受较低验收范围或放弃某阶段。
- 框架 schema/状态机无法表达实际修复，继续操作需要改变公共契约。

提问格式：

阶段：<blocked stage>
问题 ID：<q-id>
当前 revision：<number>
已验证事实：<证据支持的事实>
新信息检查：<匹配或冲突结果>
建议 invalidate_from：<stage 或 undecided>
证据：<路径、JSON pointer、日志、SHA-256>
需要作者确认：<最小问题>
预计恢复命令：<resume command>

禁止事项：

- 不猜 offset、RVA、宽度、opcode 或方法记录。
- 不复用其他 APK/fixture 的案件参数。
- 不覆盖旧产物，不删除失败日志。
- 不直接把问题状态改成 answered。
- 不在运行中的 Frida/Unicorn 内部热替换。
- 不把“resume 命令执行完成”等同于修复成功；必须重新通过阶段 gate。

最终输出：列出旧/新 revision、回答文件、invalidate_from、实际重跑阶段、新产物哈希、保留的旧证据、测试结果和仍未解决的问题。
```
