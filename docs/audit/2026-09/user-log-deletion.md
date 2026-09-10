# 会员日志删除条件

旧 `User::ulog_del/plog_del` 使用 TP5 的 `['id'=>['in', $ids]]` 条件；当前 ORM 将嵌套数组作为绑定值，真实 SQLite 请求稳定触发 `Array to string conversion`。缺少 ids/type/all 或数组输入也会产生 PHP 8 诊断。

改用 TP8 三元条件，始终附加已登录用户 ID；Ulog 另附加类型 1–5。仅接受 POST。未传 all 视为选择删除，只有明确 `all=1` 才清空当前用户范围；ID 仅接受有效 UINT32 正整数，允许逗号分隔、空格与去重，每次最多 1000 项。负数不再被 abs 转成另一个有效 ID，空/非法列表不会退化为清空操作。表单现有的批量删除与收藏取消调用均为 POST。

`tests/security_audit_user_log_delete.php` 执行实际控制器、Request 和 ORM，隔离身份初始化及渲染。PHP 8.3/8.4 × SQLite/MySQL 各 39 项覆盖单选/多选、他人日志、类型隔离、明确清空、省略可选参数、畸形/超界输入、重复项及 GET 拒绝。MySQL 只操作 `maccms_audit_models.audit_log_delete_*` 两张专用表并清理。

本组保留既有 Plog 删除功能。它不提供不可删除的财务留存体系；商用部署还需明确账务留存规则，不能将可由用户或后台删除的展示账变当作唯一对账依据。
