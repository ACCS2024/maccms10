# 内容购买的真实身份、会话与 HTTP 回归

本组验证购买写入前的实际访问边界，生产修复由主任务维护。`tests/framework_audit_purchase_csrf.php` 使用生产 `app\Request`、TP8 路由分派、Cookie、文件 Session/SessionInit、JWT 签名验证、两个真实购买控制器及其祖先构造和 `All::label_user`。只有页面装饰渲染和视频/文章/漫画元数据读取使用窄夹具；User、Group、Plog、Ulog、购买扣费和推荐积分均走真实 ORM 与安装 DDL。SQLite 额外映射安装表的默认值和整数范围，MySQL 使用专用 `maccms_audit_purchase_csrf` 库及非严格模式，不读取站点运行配置。

正常 Cookie 请求先访问 `user/write_token`，真实 SessionInit 保存会话，再用同一会话的令牌 POST 购买。测试验证实际余额、购买者及推荐人账本、资源访问凭证，以及同一购买重复提交时全部金融状态不变。URL 不能补齐或覆盖正文里的资源参数与令牌；用户 ID 和价格附加字段不能改变经过认证的购买者或服务器价格。

拒绝矩阵覆盖缺失或错误令牌、仅查询串/Cookie 提供令牌、错误或空请求头不得回退正文、正文数组/错误类型、无会话的旧令牌、伪展示 Cookie、错误登录摘要、禁用或失效 Bearer、失效旧登录、未启用账号，以及原始方法和覆盖后的方法。启用且验证通过的 Bearer 可以免浏览器 CSRF，JWT 关闭后合法 Cookie 仍需有效令牌；有效请求头优先于正文。生产 Request 会将结构化方法覆盖输入转换为 HTTP 400 JSON，合法字符串覆盖保持原框架语义，但购买仍同时要求原始和有效方法为 POST。

过期会员专门保留三项对照：令牌获取与拒绝购买不能先持久化会员降级；只读认证返回实际有效的普通会员组而不修改账户；没有选择只读模式的旧调用者仍按原契约更新过期用户组。拒绝请求检查全部 User/Plog/Ulog 行完全不变，且没有进入资源元数据读取。令牌响应及拒绝响应的私有缓存头、SessionInit 跨请求恢复、损坏的持久会话令牌更新也得到检查。

新增 `tests/browser/purchase_csrf_php.cjs` 让真实 Chromium 的全部六套购买方法连接本机 PHP HTTP 服务。脚本使用仓库 jQuery 和实际购买方法；会员门由真实模板引擎渲染。验证取令牌的请求不写账户、POST 实际扣减 20 积分、产生四笔购买/推荐账本及一个正确归属的访问凭证，并确认实际 HTTP 重试不会重复扣费。HTTP 表单数组、仅 URL 提供令牌、坏请求头与方法覆盖也进行真实请求验证。

该浏览器回归还证实一个前后端兼容问题：index 购买入口的余额不足返回原有 `code=2002`，API 为 `1005`。会员门现在同时识别两种状态码；使用实际英文语言包返回的提示同样能打开充值弹窗，余额和账本保持不变。此修正仅更新已授权会员门判断与相关前端回归，不改变已有入口状态码。

最终矩阵：PHP 8.3/8.4 × SQLite/MySQL 各 492 项路由检查；真实 PHP HTTP/Chromium 在 PHP 8.3/8.4 各 61 项检查。此前独立前端回归更新为 Node VM 254 项、隔离合同 HTTP/Chromium 173 项。资源上下架、分类权限和元数据完整性仍由下一组 ContentResource 审计覆盖，当前夹具不据此声称资源授权已闭合。

执行方式：

```sh
# 在对应 PHP 8.3/8.4 环境运行，默认使用隔离 SQLite。
php tests/framework_audit_purchase_csrf.php

# MySQL 仅使用硬编码的专用测试库；主机和口令通过隔离环境提供。
PURCHASE_CSRF_MYSQL=1 php tests/framework_audit_purchase_csrf.php

# 使用 tests/browser/package-lock.json 安装到独立临时目录的工具依赖。
PHP_BINARY=php NODE_PATH=/tmp/maccms-purchase-browser-tools/node_modules node tests/browser/purchase_csrf_php.cjs
PURCHASE_AUDIT_PHP_IMAGE=maccms-audit-image84:20260910 NODE_PATH=/tmp/maccms-purchase-browser-tools/node_modules node tests/browser/purchase_csrf_php.cjs
```

HTTP 工具默认使用 `PHP_BINARY` 或本机 `php` 启动隔离 CLI-server，因此 CI 直接复用已安装的 PHP 8.3/8.4；只有明确设置 `PURCHASE_AUDIT_PHP_IMAGE` 时才使用 Docker。两种模式均只绑定随机 loopback 端口，SQLite/会话位于独立临时目录。本机模式使用有界 SIGTERM/SIGKILL 关闭进程；Docker 模式分配本次专用随机容器名，结束时仅停止并移除该容器。浏览器拦截并拒绝外站请求；没有调用生产账号、真实邮件短信或第三方支付，测试结束清理临时数据库和会话。
