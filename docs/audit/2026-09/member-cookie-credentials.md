# 会员 Cookie 凭据与原生传输边界

旧账号的 `user_random` 安装默认值为空。旧 Cookie 校验只重算摘要，没有拒绝这个不具备会话秘密的状态；同时重复 URL 解码和 HTML 编码 PHP 已解析的 Cookie，令包含加号、百分号或实体文字的正常用户名无法原样认证。用户名直接进入旧 utf8mb3 表的字符串比较，也可能让有效 UTF-8 的四字节未匹配输入触发数据库字符集异常。

本组仅修改 `User::checkLogin()` 和两个私有输入检查方法。Cookie 使用 PHP 已解析的原始值，不再 trim、urldecode 或 htmlspecialchars。账户 ID 必须为正整数或规范十进制字符串，最大 4294967295；用户名必须为非空、无 ASCII 控制字符的有效 UTF-8，最多 30 字符、120 字节；摘要必须为 32 位小写十六进制。两条 Cookie/JWT 凭据查询都明确使用 `master()`，避免读写分离中的旧从库状态继续认证；按 ID 与启用状态查账号，再精确比较原始用户名，既避免数据库排序规则的大小写和尾空格别名，也避免把不可存入旧字符集的未匹配用户名传入 SQL 字符串条件。

数据库随机数必须为恰好 32 位 ASCII 字母或数字。历史大写字母/数字格式仍可用，新登录与改密生成的 32 位十六进制值也可用。空值、短值、超长值、控制字符和非 ASCII 随机数均拒绝。拒绝认证不自动迁移账号、不旋转随机数、不写过期会员组；该账号完成正常密码登录后，由既有登录流程生成新随机数并恢复 Cookie 使用。格式检查不能证明历史随机数的熵来源，本组没有批量重置历史账号。

已启用 JWT 时，错误类型的 Authorization 和明确 Bearer 形式但无效的 token 均受控拒绝，不能回退为 Cookie 成功；有效 JWT 同样要求合法 ID、合法随机数与数据库精确匹配。未知 Basic 认证方案保留原有 Cookie 行为，JWT 被明确禁用时继续保持已提交的 Cookie/CSRF 合同。购买写授权仍由原 MemberWrite/SessionCsrf 控制，本组没有修改 CSRF 规则。

已成功认证的旧调用者仍保留默认会员过期组写回行为；已有 `checkLogin(false)` 继续只返回有效普通组而不写库。新边界只提前拒绝无效凭据，没有放宽身份、账号启用状态或随机数撤销要求。

## 验证

`framework_audit_member_cookie.php` 使用真实 User/Group 安装 DDL、生产 User/JwtService、实际 app\Request 与 think Cookie。隔离 HTTP 服务调用真实密码登录，原生 `setcookie` 由 libcurl Cookie jar 保存，再通过真实 PHP Cookie 解析请求认证；测试不自行 URL 解码 Cookie。覆盖加号、百分号、实体文字、30 字符中文，以及明确 utf8mb4 升级后的 emoji 用户名。MySQL 先保持安装 utf8mb3 DDL；四字节未匹配 Cookie 在原表上受控拒绝，之后明确转换测试表验证升级兼容。超长随机数只在单独标明的旧宽字段夹具中测试，随后恢复安装宽度。

测试还覆盖缺字段、数组/对象/布尔等类型错误、ID 和字符串上下限、旧默认空随机数、正常旧格式随机数、过期账号拒绝零写、禁用/改名/随机数变化、合法 JWT、无效 Bearer 不回退，以及真实重复登录后旧 Cookie jar 失效。每个受控失败都核对完整账号状态与 SQL 写入计数；原生 HTTP 断言服务端零写计数。HTTP 单次编码由 PHP 解析后可用，双重编码不会由模型再次解码。

现有内容身份/视频/文章/静态页、上传、评论、会员表单与消息测试的短假随机数同步为确定的合法 32 位测试值；原断言和业务流程保留。原会员会话与内容身份测试中直接提供已经解析的 `%31` 改为拒绝，真实一次 HTTP 解码兼容性由新 HTTP 测试验证。

运行：

```sh
php tests/framework_audit_member_cookie.php
MEMBER_COOKIE_MYSQL=1 php tests/framework_audit_member_cookie.php
```

MySQL 仅使用专用 `maccms_audit_member_cookie` 数据库，连接由 `FRAMEWORK_AUDIT_HOST` / `FRAMEWORK_AUDIT_PASSWORD` 指定；同库测试须互斥。SQLite 和 HTTP 服务位于随机临时目录，HTTP 只监听本机随机端口并在 finally 终止本次进程。没有真实账号、外发消息或第三方请求。

本组验证结果（两个 PHP 版本均通过）：

| 测试 | PHP 8.3 | PHP 8.4 |
| --- | --- | --- |
| 新 Cookie 边界与原生 HTTP，SQLite / MySQL 非严格模式 | 240 / 270 | 240 / 270 |
| 会员会话 / 表单 / 消息，SQLite | 43 / 288 / 94 | 43 / 288 / 94 |
| 密码重置 / 改密 / 联系方式绑定，SQLite | 64 / 163 / 173 | 64 / 163 / 173 |
| 上传身份 / 上传 CSRF / 评论，SQLite | 205 / 56 / 112 | 205 / 56 / 112 |
| 内容身份与私有缓存，MySQL index / API | 247 / 191 | 247 / 191 |
| 视频实际资源权限，MySQL | 3018 | 3018 |
| 文章实际权限，MySQL 根目录 / 子目录 | 714 / 714 | 714 / 714 |
| 静态视频，MySQL 根目录 / 子目录 | 1057 / 1057 | 1057 / 1057 |

内容、文章和静态视频 runner 同时验证实际本地前端脚本与渲染结果（分别 38、41、336 项）。内容回归及最终 Cookie 矩阵从独立已提交基线树仅覆盖本组精确修改、使用干净 vendor 执行，避免借用并行中的其它功能代码。18 个本组 PHP 文件在 PHP 8.3/8.4 均无语法诊断。

```sh
python3 tests/run_content_identity_cache_audit.py maccms-audit-image83:20260910 maccms-audit-image84:20260910
python3 tests/run_vod_access_audit.py maccms-audit-image83:20260910 maccms-audit-image84:20260910
python3 tests/run_art_resource_audit.py maccms-audit-image83:20260910 maccms-audit-image84:20260910
python3 tests/run_static_vod_audit.py maccms-audit-image83:20260910 maccms-audit-image84:20260910
```

这些内容 runner 各自建立随机独立 MySQL 容器、Unix socket 和专用数据库，并仅清理自身创建的资源。

## 主从延迟下的会话撤销

MySQL 专项使用同一隔离容器内的 `maccms_audit_member_cookie` 与 `maccms_audit_member_cookie_read` 两个数据库，通过真实 ORM `deploy/rw_separate/master_num/slave_no` 配置分别作为写库和读库，并断言 `SELECT DATABASE()` 及默认 ORM 查询确实命中不同状态。它验证查询路由，不模拟或声称运行了真实复制进程。

从库保留原有效账号时，主库随机数旋转、禁用、删除、随机数清空均让 Cookie 和 JWT 拒绝，且两库全账号状态与写入计数保持不变；主库改名让原 Cookie 拒绝。JWT 的身份合同为 UID/随机数，未声称仅改用户名会撤销未旋转的 JWT。反向场景中，从库仍是旧用户名/无效随机数/禁用状态，而主库有效，两种渠道均按主库正常认证并返回当前主库身份。此组不改变 Group 权限缓存。

新增 `tests/fixtures/member_cookie_replica.php` 仅由新 Cookie 测试的 MySQL 分支加载；结束恢复原数据库管理器并删除本次专用读库。原单库 240 项保留，主从专项增加 30 项。

补齐主库查询后，PHP 8.3/8.4 的 SQLite240 / MySQL270 全部重跑通过，会员会话43 / Auth JWT128 的 SQLite窄回归两版通过。此前四个大型内容 runner 的验证记录保留，本次仅认证读连接改为主库，未再次重复该矩阵。
