# 某6零去特征与重打包脱敏案例

此案例用于教 AI 如何把当前版本证据转成 adapter 和执行步骤。案例包名、哈希、数量和类名均为脱敏示例，不能作为任何真实 APK 的默认值。完整 JSON 位于 `examples/apk-repack/sanitized-360-version-adapter.example.json`。

## 旧工具中可借鉴与不可复用的部分

2024 工具包含三类有价值的算法意图：枚举 `Lcom/stub/StubApp;` 调用、移除已确认的 `assets/libjiagu*.so`/`.jgapp`、恢复 Manifest Application。它同时存在不能复用的宽松条件：

```java
declaringClass.equals("Lcom/stub/StubApp;")
    || methodName.equals("getOrigApplicationContext")
    || returnType.equals("Landroid/content/Context;")
```

这个 `||` 会误删其他类中同名方法或所有返回 Context 的静态调用。新版适配必须同时匹配 owner、方法名、完整 descriptor、调用形式、目标文件范围和当前版本的精确调用点数量。

旧工具还会直接删除第一个 DEX、把最后一个 DEX 改名为 `classes.dex`，并对全部 StubApp 调用删指令。这些都只能视为历史思路，当前 adapter 必须声明完整最终 DEX 布局和每个输出哈希。

## 示例一：精确识别并移除壳 SO/资产

先从当前 APK inventory 证明条目存在，再写入 adapter：

```json
"remove_entries": [
  "assets/.jgapp",
  "assets/libjiagu.so",
  "assets/libjiagu_a64.so"
]
```

不使用 `libjiagu*.so` 通配符。每个版本重新盘点，x86/x64 或其他名称只有实际存在且被证明属于壳时才加入。

壳 `classes.dex` 被业务主 DEX占用同一路径时，不写入 `remove_entries`，而写入：

```json
"replace_entries": [{
  "name": "classes.dex",
  "output_sha256": "<最终业务主 DEX SHA-256>",
  "evidence": ["<壳主 DEX 与恢复业务主 DEX 的分类证据>"]
}]
```

## 示例二：结构化恢复 Manifest

adapter 从 runtime dump 或原始构建证据记录真实值：

```json
"manifest": {
  "application": {
    "value": "com.example.target.RealApplication",
    "evidence": ["runtime-metadata.json#/application"]
  },
  "app_component_factory": {
    "value": "android.app.AppComponentFactory",
    "evidence": ["runtime-metadata.json#/appComponentFactory"]
  }
}
```

`scripts/apk/repack_from_adapter.py` 用 XML parser 修改 apktool 解码后的 Manifest，不对二进制 AXML 或全文做字符串替换。值为 `null` 表示有证据要求删除该属性。

## 示例三：StubApp 指令正则

正则只用于已经反汇编的 smali 树，不直接作用于 DEX 二进制。每条规则必须限制文件 glob，并给出精确 `expected_matches`。

Context wrapper 示例：

```json
{
  "id": "context-wrapper-to-framework-context",
  "files": ["smali*/com/example/**/*.smali"],
  "pattern": "^(?P<indent>[ \\t]*)invoke-static \\{(?P<register>[vp][0-9]+)\\}, Lcom/stub/StubApp;->getOrigApplicationContext\\(Landroid/content/Context;\\)Landroid/content/Context;[ \\t]*(?P<eol>\\r?)$",
  "replacement": "\\g<indent>invoke-virtual {\\g<register>}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;\\g<eol>",
  "expected_matches": 12,
  "flags": ["MULTILINE"]
}
```

返回 `void` 且调用点控制流已证明可为空操作的 marker 示例：

```json
{
  "id": "confirmed-void-shell-markers-to-nop",
  "files": ["smali*/com/example/**/*.smali"],
  "pattern": "^(?P<indent>[ \\t]*)invoke-static(?:/range)? \\{[^}]*\\}, Lcom/stub/StubApp;->(?:interface11|interface22|interface24|mark)\\([^)]*\\)V[ \\t]*(?P<eol>\\r?)$",
  "replacement": "\\g<indent>nop\\g<eol>",
  "expected_matches": 4,
  "flags": ["MULTILINE"]
}
```

执行时先 dry-run：

```powershell
py -3 .\scripts\apk\patch_smali_calls.py `
  --smali-root <反汇编目录> `
  --adapter <当前版本adapter.json> `
  --report <案件目录>\repack\adapter\smali-patch-dry-run.json `
  --dry-run
```

命中数不等于 adapter 声明值时，脚本在写文件前失败。dry-run 通过后去掉 `--dry-run`，重新组装 DEX、修复/验证 checksum，并把新 DEX 路径和 SHA-256 写入 `dex_layout`。不要把 smali 正则直接交给最终 APK executor；最终 executor消费的是已经验证并哈希绑定的 DEX。

## 示例四：等长 descriptor bridge

当业务 DEX仍引用 StubApp，而当前版本调用语义已证明可由 bridge 承担时，可以声明等长替换：

```json
{
  "old": "Lcom/stub/StubApp;",
  "new": "Lcom/ref/AppPatch;",
  "same_length": true,
  "expected_occurrences": 1,
  "targets": ["classes.dex", "classes2.dex"],
  "ordering_evidence": ["dex-string-order-proof.json"]
}
```

参考 executor 会检查每个目标的精确出现次数，替换后重算 DEX SHA-1 和 Adler-32。bridge 类本身必须已经存在于 adapter 声明的最终 DEX 中；框架不会凭案例自动生成某个固定 bridge。

## 示例五：完整重打包命令

adapter 的 executor 可以调用仓库参考实现：

```json
"executor": {
  "command": [
    "{python}", "{repo}/scripts/apk/repack_from_adapter.py",
    "--source-apk", "{source_apk}",
    "--adapter", "{adapter}",
    "--schema", "{repo}/schemas/apk-repack-adapter.schema.json",
    "--output", "{output}",
    "--work-dir", "{output_dir}/work",
    "--report", "{output_dir}/reference-executor-report.json",
    "--keystore", "{case}/secrets/local-repack.jks",
    "--key-alias", "local-repack"
  ],
  "output_apk": "target-unpacked-signed.apk"
}
```

签名密码只通过本地环境变量 `APK_REPACK_KS_PASS` 和 `APK_REPACK_KEY_PASS` 提供，不写入 adapter、日志或 Git。参考 executor 执行 apktool `-s` 解码、精确删除壳文件、清理旧签名、注入完整 DEX 布局、恢复 Manifest、构建、zipalign 和 apksigner。随后工作流插件仍会独立运行 aapt2、dexdump、JADX、zipalign 和 apksigner 验收。

## AI 使用顺序

1. 复制示例 JSON 到案件 answer 工作区，不直接修改示例文件。
2. 用当前 APK/revision 的真实路径、SHA-256、数量和证据替换全部示例值。
3. 对 Stub 调用先做结构化调用点 inventory，再决定使用 bridge、Context 改写或精确 no-op；不能先写正则再找证据。
4. dry-run 正则并核对所有命中地址；生成已修补 DEX后更新 `dex_layout` 哈希。
5. schema 验证 adapter，通过 `vmpwf resume` 激活，最后由 `apk-unpack-repack` 执行和验收。
