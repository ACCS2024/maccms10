# 公开评论创建的身份与字段边界

范围：index `Comment::saveData`、API `Comment::submit` 和新增专用 `CommentSubmission`；后台评论编辑、公共模型的后台保存接口以及其他评论读写动作未改。

## 确认问题

- index 入口把整个请求参数传给 `Comment::saveData`。客户端 `comment_id` 可选择已有评论进入更新分支；匿名请求中的 `user_id` 也可能直接落库。计数、时间等非创建输入字段同样可被覆盖。
- API 在未要求登录时直接把 cookie `user_id` 作为评论归属，并读取该用户昵称；只知道用户编号即可伪装成员评论。index 匿名开放时也存在直接信任身份 cookie 的相同问题。
- API 原来将字符串 IP 写入安装表的无符号整数 IP 字段；两入口对审核、验证码等发布规则并不一致。

## 修复与业务行为

两个公开入口复用专用提交工具，且只接受 POST body。持久化字段显式构造，永远走新建分支；客户端提供的评论编号、用户编号、状态、时间、IP、计数不能进入写入数据。

用户归属来自真实 `User::checkLogin` 的成功结果，包括 Cookie 校验和 JWT 校验。无效、不完整或数组 Cookie 不会作为已登录身份；允许匿名评论时写 `user_id=0`，要求登录时拒绝。已登录昵称从服务端用户行读取；保留 API 匿名昵称和 index 默认访客昵称。

审核状态、时间和整数 IP 由服务器确定。两个入口共同执行现有关闭开关、验证码、IP 限流、时间间隔及黑名单配置。评论目标必须存在、启用且不在回收站（Vod/Art/Manga 的实际 recycle_time 字段），回复父评论必须属于同一目标并已审核。输入类型及安装字段长度被检查；超长编码内容受控拒绝，不依赖非严格 SQL 静默截断。index 的模块名称及 mid/rid 历史别名保持可用；规范字段为空字符串、0 或 null 时仍回退别名，数组不会回退，空父评论编号仍表示新评论。

仓内 default/demo/m1938pc3/vozy 和 `static/js/home.js` 已使用 POST 表单提交，无需客户端修改。非法对象/数组请求、拒绝发布和数据库失败均不写评论，数据库失败不设置“发布成功”的节流 Cookie。

## 验证

`tests/security_audit_comment_submission.php`：112 项 × PHP 8.3.33/8.4.25 × SQLite/MySQL 8.0 非严格模式，四矩阵通过。Fixture 使用真实 Think Request、User 登录校验、JWT、Comment 模型及真实 MySQL 安装 DDL；验证码、限流和内容过滤辅助函数采用受控 fixture，本测试不覆盖这些辅助模块的内部算法。

覆盖任意评论更新、伪造归属、缺失/数组/失效 Cookie、停用账号、有效及已撤销 JWT、审核绕过、服务器时间/IP/计数、GET/PUT/DELETE/HEAD 拒绝、GET 参数覆盖 POST、无效字段类型和长度、缺失/未发布目标、错误父评论、验证码和黑名单政策，以及注入数据库失败的受控返回。

日志：`/tmp/maccms-audit-20260910/comment-submission-{sqlite,mysql}-php{83,84}.log`。MySQL 只使用 `maccms_audit_membership` 的 `audit_*` 测试表，与其他 MEMBERSHIP 套件串行。

## 后续边界

旧评论的身份、时间可能已被此前入口污染，不应自动作为资金奖励凭据。后续任务资格组拟使用默认 0 的明确可信创建标记；只由安全创建路径设置，历史记录不自动回填，后台编辑不能伪造标记。缺迁移时仍允许普通评论，但不能将未标记记录纳入奖励。公开评论举报/顶踩方法及前台整体 CSRF 协议不属于本次创建权限提交。
