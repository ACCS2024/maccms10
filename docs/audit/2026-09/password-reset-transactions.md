# 验证码重置密码的原子更新

承接验证码收件人匹配组，本批限定 `User::findpass_reset`，密保找回、已登录改密、绑定与注册消费另行分组。

同一次重置使用同一收件人：`to` 是必填，旧 `user_email` 别名可省略或与其相同，冲突则拒绝。口令与确认值保留原始字节，只按现有登录契约 trim，拒绝 NUL、少于6字节和超过72字节的输入，避免 bcrypt 截断。

重置先核验事务能力，旧 MySQL 的 user/msg 任一非 InnoDB 都受控拒绝。验证记录、唯一匹配账号行和未消费状态在事务中处理：先以条件更新消费验证码，再以账号ID与收件人一起更新口令哈希和32字符会话随机数。重复账号须先修复数据，不能一次重置多个账号。数据库错误、验证码已消费或账号更新失败会回滚；未找到账号不消费验证码。旧 Cookie/JWT 随随机数轮换失效。

两版 PHP 8.3.33 / 8.4.25：SQLite各62项、非严格MySQL8.0各64项通过，采用实际安装User/Msg DDL、真实ORM、独立数据库 `maccms_audit_user_messages`；验证正常邮箱/手机找回、重复调用、缺参/类型、重复账号、真实SQL写失败回滚、旧JWT拒绝与两张旧MyISAM表分别拒绝。验证码匹配94项同时在两数据库回归，普通表单288项继续通过。没有真实短信、邮件或生产账号操作。

运行：`php tests/framework_audit_password_reset.php`；MySQL以 `FRAMEWORK_AUDIT_MYSQL=1`、`FRAMEWORK_AUDIT_HOST`、`FRAMEWORK_AUDIT_PASSWORD` 选择专用库。测试清单models和CI已接入。旧表引擎转换需要备份及维护窗口，本次没有自动改动任何站点数据库。
