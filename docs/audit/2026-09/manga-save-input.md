# 漫画普通保存的 PHP 8 输入合同

日期：2026-09-11。范围是 `Manga::saveData` 的普通新增、编辑、可选字段和简介规范化。不是整个漫画写入、一致性或富文本安全审计的完成声明。

## 复现与修复

在固定源 `059fc491`、真实 TP8 ORM 和隔离 SQLite 中，PHP 8.3.33 / 8.4.25 的 `E_ALL` 普通数据复现相同：最小新增读取不存在的 `manga_id`；纯文本简介读取不存在的 `manga_title`；补上旧 title/note 后又读取不存在的首图下标；null 简介传给 `strip_tags` 产生弃用诊断。空简介编辑和带普通图片的简介是可成功落库的对照。

初次图片对照失败来自测试应用未配置 Log 通道。补全测试 Log 配置后，两版原代码图片对照成功，未把该夹具问题计入产品缺陷。原始记录保留在 `manga-save-survey/before-with-log83.log` / `before-with-log84.log`。

安装表中 `manga_content` 是简介，章节使用 `manga_chapter_from` / `manga_chapter_url`；当前表没有 `manga_title` / `manga_note`。保存不再要求这些不存在的伴随字段。提供的旧扁平文本数组仍按 `$$$` 合并，然后由真实 schema 过滤；不把简介改造成章节列表。

- 缺省、null、空字符串或零创建 ID 从 INSERT 中移除，实际自增 ID 不依赖 MySQL 是否启用 `NO_AUTO_VALUE_ON_ZERO`。其余 ID 验证为 unsigned INT；type_id 验证为非零 unsigned SMALLINT。
- 未勾选的 uptime / uptag 默认为 0；提供时只接受字符串或整数 0/1。
- 省略简介的编辑保留原简介、摘要、章节、封面。明确提交空值简介则规范化为空字符串，并按既有规则生成空摘要；字符串 `0` 不丢失。
- 仅当实际匹配到图片时访问首图；已有明确封面优先，普通图片的协议规范化和既有净化函数仍执行。
- 简介及可选旧文本字段在 join 和 HTML 处理前检查：每字段最多 1 MiB（含连接分隔符）、最多 1024 个扁平片段；顶层最多 256 个字段。嵌套数组、对象及其它非标量字段返回参数错误。拒绝输入不写数据库。
- 非空分类缓存中找不到所选分类、父分类形状错误或溢出时受控拒绝。这里只修读取形状，未改变 `Type::getCache` 的来源和缓存重建机制。

## 验证

`tests/framework_audit_manga_save.php` 加入默认 models 清单，使用实际 Model / Validator / DbManager / PDO / 安装 schema 字段。SQLite 默认运行；MySQL 使用专属 `maccms_audit_manga_save` 数据库、安装原始 Manga/Type DDL，并分别覆盖默认非严格模式、`NO_AUTO_VALUE_ON_ZERO`、`STRICT_ALL_TABLES,NO_AUTO_VALUE_ON_ZERO`。

示例：

```sh
php tests/framework_audit_manga_save.php
FRAMEWORK_AUDIT_MYSQL=1 FRAMEWORK_AUDIT_HOST=<isolated-host> FRAMEWORK_AUDIT_PASSWORD=<fixture-password> php tests/framework_audit_manga_save.php
```

测试读取实际落库值，覆盖正常创建 ID、缺省编辑字段、空/null/零/中文简介、旧片段、普通富文本与图片、边界字节/数量、非法形状和坏分类缓存；所有 PHP 诊断均作为失败。测试不访问外部服务，Meilisearch 关闭、自动标签保持未勾选。

## 仍需单独处理

- 分类的当前主库来源、实际模块与父子关系；共享缓存键和写后失效。
- 全字段的 schema 长度/数值边界、UTF-8 与非严格 SQL 截断；章节写入容量与格式合同。
- 更新零影响行、并发修改、异常或提交结果不明、附件引用原子绑定和删除。
- `uptag=1` 的旧远程关键词链、来源治理和失败结果；当前工作区另有尚未冻结的本地化改动，本提交不借用。
- 其它模型同类错误以及 TP8 导入对象、重复表头/多列、逐行处理和控制器响应。

简介字节上限只约束此入口的文本处理，不是完整请求、整个导入批次或生产并发容量证明；现有富文本净化器没有在本批重新作执行型安全验证。
