# 会员会话输入与 PHP 8 诊断

真实 HTTP 回归访问未登录的 `/api.php/user/get_plog` 时，在严格 PHP 模式下收到 500；日志指向 `User::checkLogin()` 对缺失 Cookie 执行 `trim(null)`。数组 Cookie 也可触发 TypeError。此前隔离控制器测试替换了认证边界，未覆盖这一实际组合。

现在先验证三项 Cookie 的标量类型和长度，再规范用户 ID 和校验摘要格式。缺失或畸形凭据返回未登录，不执行无效字符串转换。保留有效历史 Cookie 编码、数据库中的账号状态/会话随机数验证，以及已启用 JWT 的优先级；无效 Bearer 不会回退为 Cookie 成功。

`framework_audit_member_session.php` 使用实际 User/JWT/ORM 和隔离用户表，验证缺失、数组/对象/布尔等异常类型、过长输入、合法会话、账号禁用/改名/会话失效、删除账号以及 Bearer 与 Cookie 的组合。两版 PHP 的 SQLite/MySQL 矩阵验证；真实未登录 API 另外纳入账变 HTTP 套件。
