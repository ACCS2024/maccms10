# 文章普通保存与分页输入

日期：2026-09-11。此批只处理 `Art::saveData` 的普通表单/预连接字符串、可选字段和进入正文处理前的容量合同。

## 原代码实际结果

隔离固定源、真实 TP8 ORM、PDO SQLite、PHP 8.3.33 / 8.4.25 的普通数据复现一致：

- 最小新增读取不存在的 `art_id`。
- 普通字符串正文被直接交给 `join`，触发 TypeError。
- 正常表单的正文/标题/备注数组遇到无图片正文，访问不存在的首图下标。
- 缺省标题/备注数组被直接读取；null 正文触发 `strip_tags` 弃用诊断。
- 空正文编辑和包含普通图片的完整数组是成功对照。

原始证据为 `art-save-survey/source.txt`、`before83.log`、`before84.log`。没有将静态候选直接计作实际漏洞。

## 保存合同

正文既接受表单扁平数组，也接受已按 `$$$` 连接的字符串。标题、备注各自可选；缺少某页 metadata 时实际读取器继续给空字符串。省略正文的编辑保留正文及摘要，省略标题/备注也保留原列；显式空值规范化为空字符串。

创建时显式补齐 `art_content`、`art_title`、`art_note` 的空字符串。安装表这三个 MEDIUMTEXT 列均 NOT NULL 且没有默认值，不能仅依赖非严格 MySQL 自动补值。空/零创建 ID 从 INSERT 删除，保留真正自增 ID；ID、type_id、复选框和坏字段形状按受控参数错误处理。

在 join 前累计字节及输入片段数：正文最多 8 MiB、标题/备注各 1 MiB，每字段最多 1024 个片段。join 后也计算真实 `$$$` 分隔符，限制每字段至 1024 页，覆盖字符串中嵌入分隔符以及多个片段拼接形成连续美元符号的情况。正文经过现有 HTML 处理后再核对字节/页数，避免普通标签被移除后形成新分隔符。错误输入不写数据库。

只在匹配到实际图片时取首图，明确封面优先。既有协议替换、净化函数和摘要生成继续执行；无图片不再产生 PHP 诊断。

## 验证

`tests/framework_audit_art_save.php` 使用实际 Model、Validator、DbManager、PDO、安装表字段和实际 `ContentResource::artPages`。默认 SQLite；`FRAMEWORK_AUDIT_MYSQL=1` 使用专属 `maccms_audit_art_save` 数据库和原始 Art/Type 安装 DDL，覆盖非严格、`NO_AUTO_VALUE_ON_ZERO`、`STRICT_ALL_TABLES,NO_AUTO_VALUE_ON_ZERO` 三种模式。例：

```sh
php tests/framework_audit_art_save.php
FRAMEWORK_AUDIT_MYSQL=1 FRAMEWORK_AUDIT_HOST=<isolated-host> FRAMEWORK_AUDIT_PASSWORD=<fixture-password> php tests/framework_audit_art_save.php
```

测试将全部 PHP 诊断作为失败，读取实际行验证省略、清空、零、中文、多页、空尾页、普通图片和 metadata 对齐；验证 8 MiB 正文 + 两个 1 MiB metadata 的组合落库、页数/字节边界与拒绝零写入。关闭搜索同步，自动标签未勾选，不请求外部服务。

## 未覆盖的独立问题

与漫画保存一样，当前分类缓存来源、所属模块与父子关系、写后缓存失效、全字段数值/长度/字符集和数据库截断、并发编辑/零影响行/提交结果不明仍需处理。此批没有重构富文本净化器，没有宣称所有 HTML/PCRE 输入都已验证。已有超限文章、直接采集和其它写入口以及读取器自身的预算也需要独立处理，不能借此保存入口的上限作全站保证。

CSV/XLSX 接收对象和批量逐行保存、附件引用与删除、旧远程关键词调用尚不在本提交范围。没有借用工作区尚未冻结的配置/关键词本地化修改。
