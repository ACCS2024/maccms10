# 内容购买的 Cookie / Bearer 写入边界

前台 `user/ajax_buy_popedom` 和 API `payment/buy_popedom` 均要求原始 HTTP 方法与框架有效方法为 POST，只从 POST 正文读取资源坐标。查询串不能补齐缺少的必填参数，也不能覆盖正文选择。调用共享购买事务时，只使用真实认证返回的 user_id。

`MemberWrite` 先通过现有 User Cookie/JWT 认证。仅当已启用 JWT、当前 Bearer 已被实际校验后，才免除浏览器 CSRF；禁用 JWT 时附带 Bearer 字样不能让 Cookie 用户免校验，坏 Bearer 也不能回退到另一组 Cookie 身份。Cookie 写请求必须提交当前服务器会话令牌，优先读取 X-CSRF-Token；显式坏头部不会回退到正文。URL、Cookie、Origin 都不是令牌来源。`SessionCsrf` 和原上传 `UploadCsrf` 共用同一校验实现。

`GET user/write_token` 只向真实登录用户返回 `{code:1, info:{csrf_token:...}}`。响应设置 private/no-store、Pragma、Vary 和 nosniff；令牌由真实 SessionInit 持久化，既有上传令牌可复用，畸形会话值会重新生成。客户端从安装目录构造同源路径，每次明确购买尝试先取令牌，再提交 POST。

认证过程的会员过期维护原先会写入 User。新增默认兼容的 `checkLogin(false)` 只计算有效会员组，不更新账户或 Cookie。两个购买控制器和令牌入口在祖先构造加载身份前就选择此模式，避免拒绝请求先产生会员组写入。其他现有调用仍保留默认维护行为。

两入口继续沿用已提交的购买协调事务，检查账本与推荐奖励写入结果，并在用户行锁及当前读下去重已购买凭证。此组不改变文章/漫画/视频价格查询政策，也不把现有资源存在性、发布状态、密码/组权限及价格变更处理认作已审计完成；视频资源解析与购买的接入另作下一组提交。

验收包括真实控制器构造、TP8 路由、Cookie/JWT、SessionInit 和 User/Plog/Ulog 数据库写入；覆盖来源混淆、方法覆盖、伪造/失效身份、错误会话令牌、过期会员拒绝零写及正常一次扣费。浏览器另外加载六份实际购买方法与真实会员门，连接隔离 PHP HTTP 服务验证取令牌到实际账本持久化的完整顺序。资源元数据与无关页面装饰在该夹具中作窄替换，实际资源权限由独立视频访问回归验证。
