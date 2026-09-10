# 视频保存的分组提交与 PHP 8 输入合同

日期：2026-09-11。基于 `fc8c07ce` 的真实安装 MySQL、TP8 ORM 和 PHP 8.3.33 / 8.4.25，普通输入已复现最小新增缺 ID、字符串播放源 join TypeError、缺 server/note 警告；只改名称或简介时会清空播放与下载组，单独更新播放组也会清空下载组。完整表单数组与显式空数组是对照。

## 本批行为

`VodSaveInput` 在调用 PHP 字符串函数和数据库前规范化输入。正文允许字符串/整数/null，规范为字符串；创建显式补齐正文及 URL 列，空或零 ID 从 INSERT 中删除。ID/type_id/复选框验证真实类型与范围；Vod 的安装 type_id 是 signed SMALLINT，不与 Art/Manga 的 unsigned SMALLINT 混用。

分组合同：

- 模型更新没有提供某组字段，也没有该组表单标记时，保留原组。省略正文保留原正文和摘要。
- 更新某组必须携带对应 from；只提供 URL/server/note 受控拒绝。server/note 可省略，缺项按空字符串处理。
- from 可为表单扁平数组或已按 `$$$` 连接的字符串。只接受有实际标识符的分组，拒绝多出的伴随分组，防止内容默默丢失。
- 显式空 from / 空数组可以清空该组。后台完整表单在可删除分组容器之外提交 `vod_play_present=1` / `vod_down_present=1`；因此删除全部播放或下载项仍能明确清空。标记在规范化后移除，不写数据列。
- 更新一个组不影响另一个组。自定义完整表单若省略全部分组字段，需要发送对应标记或显式空 from 来表达清空。
- CRLF、LF、CR 都转换成单个集数分隔符，避免只删除 LF 后把相邻集数连接起来。

在 join 前限制片段数及原始字节，join 后限制实际分隔符。每组最多 256 个输入片段/来源段，URL 最多 8 MiB、20,000 个逻辑集数（含空段）；from/server/note 先限 4 KiB 原始字节，再按实际文本过滤后的 255 字符存储上限检查，避免 `formatDataBeforeDb` 静默裁剪分组字段。实际可容纳来源数同时受这 255 字符限制。简介最多 1 MiB，文本要求有效 UTF-8；这不替代数据库字符集升级和其它字段的验证。

## 验证

- `tests/framework_audit_vod_save_input.php`：两版各 148 项，加入默认 models 清单；包括字符串/数组等价、标记清空、缺省保留、换行、坏形状、字节/字符/集数边界及编码过滤后的分组变化。
- `tests/framework_audit_vod_save.php`：两版各 438 项，实际安装 Vod/Type/VodSearch DDL、PDO 与真实 saveData，覆盖非严格、NO_AUTO_VALUE_ON_ZERO、STRICT_ALL_TABLES + NO_AUTO_VALUE_ON_ZERO 三种模式。拒绝输入同时验证资源表和重复目录未变；正常数据经实际 `mac_play_list` 核对 source/episode 对应关系。
- 组合容量采用正常结构的分集 URL，播放和下载各 8 MiB，加 1 MiB 简介实际落库完整；测试 PHP 分配峰值 93.04 MiB，运行限制 128 MiB。这是保存夹具的观测，不代表全站或并发容量。
- 专项 MySQL 运行器 `tests/run_vod_save_audit.py` 启动独立、禁用网络的 MySQL，通过 Unix socket 运行；加入 PHP 矩阵 CI。搜索同步关闭，自动标签未勾选，没有请求外部服务。

```sh
php tests/framework_audit_vod_save_input.php
python3 tests/run_vod_save_audit.py <php83-image> <php84-image>
```

较早容量夹具曾把目标 420 字节的单集长度算错，夹具自检主动失败；已改为由实际前缀长度构造后重跑，未把该失败计作产品缺陷或标成成功。

## 后续合同

重复目录的旧名称捕获错误、每次保存累加重复目录行、写后目录更新异常与隐式 DDL 另行修复，本批不改变这部分逻辑。分类当前主库/所属模块、全字段长度/数值/字符集与裁剪策略、并发编辑/零影响行/提交不明、标签来源、附件绑定和删除仍未完成。

本提交没有重构 `vod_content` 的富文本净化与输出链；该路径仍需独立安全复审。CSV/XLSX 接收对象、通用导入的 ID 强转/拆分/空值语义、批次一致性和控制器返回仍待修复。只修保存输入不代表导入入口可用。
