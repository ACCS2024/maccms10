# 账变与提现列表的用户名查询

由 Ulog 同类扩查定位 Plog/Cash：两者取当前页账号后又调用完整 User::listData，额外计数且最多取 999 名用户。Plog 在账号已删除时直接读不存在映射，PHP 8 E_ALL 下稳定复现 `Undefined array key 99`；较大页面还会漏姓名。Cash 虽有空串回退，但仍有截断和多余全字段查询。

两个只读列表统一改为当前页去重正用户 ID 的一次 `column(user_name,user_id)` 查询。删号/混合访客姓名回退空串，空页/纯访客不读用户表；不改变余额、提现或账变数据。

`tests/framework_audit_ledger_usernames.php` 用实际 Plog/Cash 模型和 ORM SQL listener，重新执行捕获的 SQL 检查字段投影/账号范围。PHP 8.3/8.4 × SQLite/MySQL 各 24 项，包含删号、分页、混合用户、重复用户、空页和 1001 位不同账号的大页。MySQL 使用并清理 `maccms_audit_models.audit_ledger_names_*` 三张专用表；原提现/会员列表回归同时运行。
