# 内容导入行准备（I1a）

日期：2026-09-11，基于 `3962133e`。先修复行数据合同，TP8 上传接收和返回结果另列 I1b，尚未在本批打通。

固定源通过三个实际 saveData 模型和安装 MySQL 确认：`7ordinary` 被准备器强转为 7 并更新该行，分类 `1ordinary` 也被改成 1；Art/Manga 的明确空正文被删除，实际保留旧正文；视频明确空播放来源被删除，实际仍保留旧来源/地址。两版 PHP 各 13 条普通观察，未把普通非空正文保存成功误报为兼容故障。

BulkTableIo::prepareGenericForSave 仅支持当前三处调用者 Art/Manga/Vod，按各模型既有规则校验行数、ID、分类和 0/1 标志。缺省/空/零新建 ID 保持自增；非法 ID 不再先变成合法数值。正文、标题、备注和视频来源组保留原始已连接值，不提前 explode，也不删除明确空值；模型自己的字节、页数和组数限制负责有界规范化。省略字段仍保持省略。

PHP 8.3.33 / 8.4.25 各完成：改动 PHP 编译；Art SQLite 191 / 三模式 MySQL 573 项；Manga SQLite 158 / 三模式 MySQL 474 项；Vod 三模式 MySQL 507 项。每个真实模型增加导入准备后实际保存/拒绝检查，非法身份和标志不修改现有行；空/null/零/省略正文及视频空来源语义正确，零 ID 正常创建。Manga 的有界普通描述保留 1100 个字面分隔符，不被预先展开成超出模型表单片段数量的数组。CSV 原读写 3 项、实际下载/导入往返 40 项继续通过。

各 MySQL 模式为默认非严格、NO_AUTO_VALUE_ON_ZERO、STRICT_ALL_TABLES 与 NO_AUTO_VALUE_ON_ZERO 组合。原组合容量峰值仍为 Art 64.02 MiB、Vod 93.04 MiB（128M 夹具）；这不是完整上传页面的容量保证。

持久回归位于三份 `tests/framework_audit_*_save.php`。原始证据 `/tmp/maccms-audit-20260910/import-followups/source.json`、`prepare-{art,manga,vod}-{83,84}.log`、`prepare-check1.log` 与验证树文件。

同时对实际锁定 UploadedFile 复核：rule、validate、getInfo 均不存在，调用抛 Error；Art/Manga/Vod importData 的成功/失败 base_import 返回值均丢失为 null。后续 I1b 需使用实际上传接口、限定单文件及类型/容量、逐行受控错误和正确响应传播；不能把本批准备器通过当作导入链已恢复。CSV 重复列/多余列、完整行原子性与未知保存结果、其它配置/采集导入仍需独立审计。
