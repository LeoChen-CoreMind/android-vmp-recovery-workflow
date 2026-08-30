# 360 去特征与无壳重打包多版本适配

用于 `apk-unpack-repack` 阶段。每个 APK、360 壳版本和案件 revision 都必须创建独立 adapter；历史样本和旧工具只能作为算法参考。

首次适配或修改 StubApp 指令策略前，先读取 `references/case-studies/sanitized-360-repack.md`。

1. 先核对 case/checkpoint/questions/events/artifacts 和当前 revision 的 APK、DEX、验收报告哈希。
2. 独立盘点 Manifest、DEX 布局、ZIP 条目、签名、壳指纹和所有 Stub/bridge 调用点。禁止按 360、jiagu、Stub、com.qihoo、com.jg 等关键词盲删。
3. 按 `schemas/apk-repack-adapter.schema.json` 提供 adapter，绑定 APK/DEX 哈希、`evidence_revision`、生效 `case_revision`、壳指纹、Application/AppComponentFactory、最终消失的精确删除项、同路径替换项及输出哈希、最终 DEX 映射、descriptor 长度/排序证据、bridge 调用语义、smali 正则目标范围/精确命中数、签名和设备验收。壳 classes.dex 被业务 DEX 占用同一路径时属于替换。BLOCKED 后 resume 时，生效 revision 是当前 revision 加 1。
4. 不复用其他版本的类名、DEX 数量、classes 编号、删除列表、descriptor、bridge、调用次数、no-op 结论或业务签名补丁。
5. 任何候选冲突、返回值语义未闭合、DEX 映射不唯一、哈希不匹配或工具验收失败都必须 BLOCKED。
6. 完成需要 aapt2、dexdump、JADX、zipalign、apksigner 全部真实通过；adapter 要求设备验收时还需记录安装、冷启动、进程、窗口和 crash/ANR。
7. 业务盗版提示、签名校验和 native crash 与 360 壳残留分开归因，没有当前版本证据时不得自动移除。

恢复答案使用：

```json
{"apk_repack":{"enabled":true,"adapter":"<adapter.json>"},"invalidate_from":"apk-unpack-repack"}
```
