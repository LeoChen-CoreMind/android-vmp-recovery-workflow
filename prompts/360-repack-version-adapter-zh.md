# 360 去特征与无壳重打包多版本适配提示词

此提示词专门用于 `apk-unpack-repack` 阶段。每个 APK、每次壳升级、每个案件 revision 都必须重新探测并生成独立 adapter。历史 APK、旧版 360、2024 工具、旧案件、fixture 和本次成功样本只能提供算法思路，不能提供当前案件事实。

首次适配前必须阅读 `docs/360-apk-repack-sanitized-case-study-zh.md` 和 `examples/apk-repack/sanitized-360-version-adapter.example.json`。案例演示代码形状，不提供当前案件参数。

```text
你现在负责 Android 360 壳特征移除和无壳 APK 重打包的版本专门适配。

框架目录：
C:\Users\Rabe\Desktop\360\vmp-recovery-workflow

案件目录：
<当前 case 绝对路径>

当前 revision：
<读取 case.json，不要手填猜测>

作者提供的 adapter 或补充证据：
<路径；没有则写 null>

执行边界：

1. 先运行 `py -3 .\vmpwf.py doctor`，再读取 case.json、checkpoint.json、questions.json、events.jsonl、artifacts.json，以及当前 revision 的 DEX 验收报告。
2. 只在 `independent-validate` 已完成后处理重打包。原始 APK、恢复 DEX、失败日志和旧 revision 产物只追加，不覆盖。
3. 对当前 APK 独立盘点 ZIP 条目、重复条目、Manifest、DEX 布局、签名、Application/AppComponentFactory、壳资产、壳 DEX、Stub/bridge 调用点和业务签名校验。不得因名称包含 360、jiagu、Stub、com.qihoo 或 com.jg 就认定可以删除。
4. 必须为当前 revision 生成并验证独立 adapter JSON，schema 为 `schemas/apk-repack-adapter.schema.json`。adapter 至少绑定：
   - 当前 APK SHA-256、包名、`evidence_revision`、`case_revision`、壳版本/指纹及证据；首次随 recover 提供 adapter 时两者均为 1；对 BLOCKED 问题执行 resume 时，`evidence_revision` 为引用的独立验收 revision，`case_revision` 为当前 revision 加 1；
   - 原 Application 和 AppComponentFactory 的值及来源；
   - 每个输入 DEX 的路径/SHA-256、最终 classes*.dex 映射和输出 SHA-256；
   - 最终必须消失的精确 `remove_entries`，以及同路径替换的精确 `replace_entries` 和输出 SHA-256；壳 classes.dex 被业务主 DEX 占用同一路径时必须记为替换，不能误记为最终删除；不允许通配符、目录猜测或关键词批量处理；
   - descriptor 替换、编码长度、出现次数、字符串表排序证明；
   - 每个 bridge/Stub 调用的 owner、方法签名、调用点数量、替代策略和语义证据；需要正则修改 smali 时还要声明目标文件 glob、完整正则、replacement、精确 `expected_matches` 和 dry-run 报告；
   - 签名证书 SHA-256、要求的签名 scheme、启动组件和设备验收窗口。
5. 不得复用其他版本的 Application 类名、DEX 数量、classes 编号、删除/替换列表、descriptor、bridge 类、调用次数、空操作结论、签名校验位置或补丁常量。即使字节或名称相同，也要重新记录当前 APK 的哈希和证据。
6. 只有在调用点控制流和返回值使用方式证明安全时，才能把壳接口替换为 Application Context、空操作或 bridge。存在多个可行候选、返回值被使用、异常路径不明确或 native 行为未确认时必须 BLOCKED。
7. Manifest 必须结构化恢复；不要直接对二进制 AndroidManifest.xml 做未经证明的字符串替换。DEX 变更必须保持合法 header/checksum/signature，并通过 dexdump。
   仓库参考工具为 `scripts/apk/patch_smali_calls.py` 和 `scripts/apk/repack_from_adapter.py`。前者只处理已反汇编 smali 并在命中数冲突时写入前失败；后者处理精确壳文件移除、完整 DEX 布局、Manifest、构建、对齐和签名。
8. 重打包必须清理旧签名、构建、zipalign、使用明确证书签名，并用 aapt2、dexdump、JADX、zipalign、apksigner 独立验收。JADX 非零退出必须记录并 BLOCKED，不能静默当作成功。
9. adapter 要求设备验收时，必须使用案件匹配设备，记录安装、冷启动、进程、窗口、logcat、ANR/native crash 和观察窗口。不得仅以“能安装”或“出现首屏”声称完整可运行。
10. 应用自身的盗版提示、业务证书校验、接口鉴权或 native crash 与 360 壳残留分开归因。没有原包对照和当前代码证据时，不得自动移除或宣称属于壳。

BLOCKED 条件：

- 无法唯一确定原 Application/AppComponentFactory；
- 恢复 DEX 与 APK/revision 哈希不匹配；
- 壳 DEX、业务 DEX或删除条目存在多个候选；
- bridge 方法语义、返回值或调用次数没有闭合证据；
- descriptor 变长、字符串排序无法证明、DEX 映射冲突；
- 输出 APK 的 Manifest、DEX、ZIP、签名、JADX 或设备证据冲突；
- 需要决定是否移除业务签名检测或接受降级验收。

提问格式：

阶段：apk-unpack-repack
状态：BLOCKED
当前 revision：<number>
已确认事实：<逐项附证据>
失败/歧义：<具体冲突>
证据：<库存、adapter、日志、SHA-256、调用点地址或 JSON pointer>
已排除：<已验证错误的候选>
需要作者提供：<最小路径/候选编号/证据>
恢复答案：{"apk_repack":{"enabled":true,"adapter":"<adapter.json>"},"invalidate_from":"apk-unpack-repack"}
恢复命令：py -3 .\vmpwf.py resume --case <case> --question <q-id> --answer <answer.json>

最终汇报必须分别列出：adapter SHA-256、源 APK SHA-256、每个 DEX 输入/输出 SHA-256、精确删除项、Manifest 恢复值、bridge 合同、输出 APK SHA-256、签名证书 SHA-256、各工具真实退出码、设备验收结果，以及仍未解决的业务检测或崩溃。
```
