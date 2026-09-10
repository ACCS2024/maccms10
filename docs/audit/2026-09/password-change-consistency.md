# 正常密码修改与资料保存契约

本批统一现有账号的四条改密路径：前台 `User::info`、API `update_info`、密保问题找回 `findpass`、后台经 `saveData` 修改已有账号。注册、OAuth 建号、邮箱/手机绑定消费不属于本批。

## 修复

- API 旧实现只能用 MD5 对比旧口令并继续写 MD5，已经使用 bcrypt 的账号无法正常改密。API 与前台资料表单现在共用真实模型更新方法，支持原始 MD5/bcrypt 校验，并为真实 32 位十六进制 MD5 记录保留历史 `htmlspecialchars(urldecode(password))` 格式。标准密码登录 `common/User::login` 与改密现在共用同一匹配方法；历史账号登录成功后，按原始口令透明升级为现代哈希。现代哈希不开放编码别名。
- 新密码保留原始字符，只按既有登录约定去除两端空白；统一要求 6～72 字节并拒绝 NUL，防止 bcrypt 超长截断。密保找回不再重复 URL 解码密码。
- 所有改密路径在同一个数据库 UPDATE 中修改 `user_pwd` 与随机生成的 32 字符 `user_random`。已登录改密同时匹配已经验证过的旧哈希，拒绝覆盖期间发生的另一轮改密。
- 默认前台资料模板的密码表单未提交密保问题/答案，旧模型仍直接读取。现在只更新实际提交的资料字段，密码单独修改不再清空旧密保、QQ 或昵称；资料单独修改保持口令与会话状态。API 继续保留已有资料字段行为，增加 POST 正文读取、字段类型、UTF-8 与数据库长度校验。URL 查询参数不能补充或覆盖密码、资料字段。
- 后台修改现有账号的密码也撤销旧会话；空密码保持原有哈希。数据库失败返回受控错误，不把密码更新失败当作成功。

## 回归证据

PHP **8.3.33 / 8.4.25** 上，四条改密路径在 SQLite、非严格 MySQL 各 **163 项**通过；加强后的消息重置各 **64 / 66 项**通过（MySQL 额外验证两张非事务表）。原有表单 **288 项**、消息参数与状态 **94 项**、OAuth 身份边界 **24 项**继续通过。

`tests/framework_audit_password_changes.php` 通过真实 User 模型、真实 API/前台动作、SQLite 和非严格 MySQL 的安装表结构进行验证。基础控制器页面响应、会员组元数据以及消息发送属于明确 fixture；登录凭证使用真实 JwtService 签名和真实 User::checkLogin 验证。

覆盖 MD5/bcrypt 两类旧账号、四条正常改密路径、原始密码字符、字段缺省与错误类型、字段长度、旧密码错误、GET/未认证请求、条件更新的并发时序，以及数据库写入失败时口令/随机数/资料均保持原值。每次正常改密先证明旧 JWT 可以登录，改密后明确要求随机数不匹配错误。

核对源码时确认旧 `info` 曾使用历史格式回退，但此前 `login` 虽计算 formatted 变量，实际密码匹配只使用原值；本批补齐二者的一致性，并增加真实历史账号登录→改密回归，不能把存在格式化变量当成登录已有兼容的证据。

本批还加强了此前消息重置测试的会话撤销证据：真实安装 DDL 的 `user_status` 默认是 0，而早期 MySQL fixture 未显式启用账号，单纯断言旧 JWT 被拒绝可能只证明账号未启用。现在 fixture 显式启用账号；`framework_audit_password_reset.php` 先验证旧 JWT 可以真实登录，重置后要求明确的会话随机数不匹配错误（1003），避免此类误通过。

运行方式：

```sh
php -d error_reporting=E_ALL tests/framework_audit_password_changes.php
php -d error_reporting=E_ALL tests/framework_audit_password_reset.php
FRAMEWORK_AUDIT_MYSQL=1 FRAMEWORK_AUDIT_HOST=isolated-db FRAMEWORK_AUDIT_PASSWORD=fixture-password php tests/framework_audit_password_changes.php
```

MySQL 测试固定使用独立数据库 `maccms_audit_user_messages`，重建该库内 `audit_user`、`audit_msg`，不应指向业务数据库。没有真实短信、邮件或外部认证调用。

## 保留的后续范围

API 资料更新直接修改邮箱/手机的既有行为尚未在本批改成验证码绑定流程；邮箱/手机绑定、解绑和注册验证码消费仍需独立审查。本批没有为这些路径补充授权，也不把它们标记为安全审计完成。

`loginOrRegister` 合并登录注册入口仍需在后续组统一核对历史口令格式与账户写入原子性；标准登录的透明密码升级也需要补充并发更新审查。本批未把这些入口标记为已经完成。
