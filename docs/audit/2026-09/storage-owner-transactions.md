# 独立存储意图的事务收尾

`StorageIntent::prepare/claim/finish` 原来在异常处理外执行 BEGIN，并在提交或回滚抛错时直接返回普通失败。准备意图的异常会被上层当成可继续的本地回退，丢失了“提交可能已成功”与“已确认回滚”的区别。

三个阶段现使用原 PDO 事务机制，BEGIN 也纳入有限清理。只有确认提交后才返回有效阶段结果。无法确定提交或回滚结果时产生 `StorageOutcomeUnknown`，携带阶段、意图 ID、核查编号和 `retryable=false`，并阻止同请求后续事务。`claim` 未确认不会调用存储服务；`finish` 未确认不会登记业务引用。

远端附件流程保留该异常，不能改成普通本地成功。私有清单记录 `storage_outcome_unknown` 和阶段身份，全部新源文件及衍生图留存。上传接口保留不可重试状态和核查编号；AI 封面继续使用自己的恢复清单响应。该机制覆盖共用流程的头像、普通附件、下载图片及封面。它不自动重试远端写入、不删除未知远端对象，也不替代跨请求对账。

`framework_audit_storage_owner.php` 在实际 SQLite/MySQL 上验证 prepare/claim/finish 的 ORM/PDO BEGIN、ROLLBACK、COMMIT 前后故障、回滚无法确认和外层事务保全，并通过第二连接检查实际可见值。`framework_audit_storage_attachment.php` 使用 17 个独立 SQLite 进程验证三个阶段的提交丢确认及回滚不明：存储服务调用次数、无业务引用、全套文件与清单保留、原头像不变和后续请求内操作阻止。两者已纳入默认及 MySQL storage 套件；原有存储、上传、下载和封面测试继续覆盖正常路径。
