# Ulog 用户名回填范围（2026-09-10）

`common/model/Ulog::listData` 收集当前页日志的 user_id 后，把条件错误写回日志的 `$where`，却把空的 `$where2` 传给 User::listData。实际执行全用户 COUNT 和按 user_id 降序取最新 999 位用户；当前日志用户可能不在这 999 位中，姓名映射会产生未定义数组键并在 PHP 8 严格模式下返回 500。查询还无必要地读取完整用户字段。

改为根据当前页去重后的正 user_id，一次查询 user_id/user_name 并按 ID 回填。不再依赖 User::listData 的计数和 999 条截断。空日志、越过末页、仅访客日志不查询用户表；混合页中已经删除的账号及访客姓名使用空字符串。日志原来的筛选、分页及内容模型回填保持不变。

`tests/framework_audit_ulog_users.php` 使用真实 Ulog、Topic 模型和数据库表，只有 URL 展示与翻译函数被隔离。两名日志用户外另有 1,005 名较新的无关用户；原代码稳定复现 `Undefined array key 1`。测试通过 ORM SQL listener 取得实际 SQL，并重新执行用户 SELECT 确认返回行只含当前页账号、字段只有 user_id/user_name；覆盖多用户内容与姓名对应、分页后的查询范围、重复用户、已删除账号、访客、空结果、越界页和超过 999 位不同账号的大页。

PHP 8.3.33 / 8.4.25 × SQLite / MySQL 各 26 项通过。MySQL 仅使用 `maccms_audit_http` 的 `audit_ulog_user`、`audit_ulog_ulog`、`audit_ulog_topic` 三张专用表，结束后删除。原 `framework_audit_user_lists.php` 两个 PHP 版本各 43 项仍通过。

实际单用户 SQL：

```sql
SELECT `user_name`,`user_id` FROM `audit_ulog_user` WHERE `user_id` = 1
```
