# A2a：可信内容身份与会话缓存边界

本组完成 `All::label_user()` 的 Cookie/Bearer 身份对齐和相关缓存边界。**尚未完成资源授权闭环**：视频四类资源出口、文章/漫画正文与密码、购买写入归属继续按 `api-content-access-plan.md` 中 A2b/A3 实施。本组不修改 User 模型、内容积分规则、密码作用域或资源 DTO。

## 根因与变更

`All::label_user()` 原来只有三项登录 Cookie 齐全才调用 `User::checkLogin()`，因此实际模型认可的纯 Bearer 用户仍被内容控制器当作游客。现在任何登录凭据都经过原模型验证；保留有效且已启用 Bearer 优先、错误 Bearer 不回退到有效 Cookie、JWT 关闭时沿用 Cookie 的原合同。完整游客增加权限分支使用的 `user_points=0`，无凭据游客不排队清理 Cookie。VIP 展示只来自验证后的用户组，客户端 `is_member` 不再点亮徽标；模板继续去掉 user_pwd/user_random。畸形 Cookie 或非字符串 Authorization 在该入口受控成为游客。

`mac_page_cache_eligible()` 原来只读取 `user_id` Cookie，既无法排除纯 Bearer 用户，也无法识别输入了内容密码的游客。新 `ContentCachePolicy` 只允许确定匿名、没有任何会话状态的公开目录进入共享整页缓存：前台 Index/index 和七种内容控制器的 index/type/show；未核对的动作、正文、播放/下载、密码、详情、用户入口保守排除。携带 Authorization、登录/组展示 Cookie、配置的会话 Cookie 或会话参数，以及任何非空真实 Session，都不能共享缓存。使用真实 Request 的原始和最终 HTTP 方法，只有 GET 可进入。

共享页面缓存键增加 `public-v2_`，从而不再读取旧命名空间下可能混入身份内容的页面。这只隔离本应用的整页缓存，不删除未知缓存，不改变模型数据缓存或站点配置。

## HTTP 会话运输层

实际中间件顺序现在为 MultiApp → SecurityHeaders → SessionInit → AppInit → RequestSecurity → Begin → CsrfGuard → AntiScrape → AdminAudit。当前仓库没有额外的子应用 middleware.php。SecurityHeaders 在 SessionInit 外层，能在响应返回时看见后者排队的 Cookie，并识别其他登录 Cookie、响应显式 Set-Cookie、授权/会话上下文和私有动作。任何这些副作用都产生 `Cache-Control: private, no-store`，优先于旧公共缓存标记及已有 public 响应头；显式 private/no-store 也不再被公共标记覆盖。请求开始时清掉上一请求的公共标记。

TP8 SessionInit 原样保留，仍负责初始化、保存会话和排队 Session Cookie。它对没有登录的首次请求也排队 Cookie，因此普通 PHP 生成页面会保守使用 private/no-store；静态文件不经过这一流程，内部确定匿名的目录缓存也仍可使用。这个性能取舍是明确的：本组不让 CDN 共享带会话 Cookie 的 HTML，不依赖部署者碰巧配置了忽略 Cookie 的缓存规则。

`All::load_page_cache()` 的缓存命中通过 echo/exit 直接输出，无法等待外层中间件返回，因此该路径也单独发出 private/no-store。真实无 Accept 请求另外复现了 `str_contains(null)` 的 PHP 8 Deprecated 正文污染；现在先确认 Accept 为字符串。E_ALL 的 HTTP 回归覆盖这个正常缓存命中请求。

上线仍应清除先前在 CDN/代理中缓存的相关动态页面。应用内换键和新响应头不能追溯撤销外部已有副本；本次测试没有操作线上缓存。

## 验证

运行 `python3 tests/run_content_identity_cache_audit.py`，可在命令后传入两个 PHP 镜像名。脚本自行创建隔离 MySQL，经 Unix socket 连接，PHP/MySQL 容器没有外网；只使用合成用户和配置。All、User、JWT、Request、Cookie、Session、ORM、SessionInit、SecurityHeaders 为实际代码。缓存存储和页面正文渲染使用可观察夹具，避免加载站点主题/配置；HTTP 缓存命中使用独立 loopback PHP 服务执行真实 echo/exit。

PHP 8.3.33 与 8.4.25 每版均通过：

- 前台入口 244 项、API 入口 188 项身份/缓存检查：Cookie 历史编码、纯 Bearer、双凭据优先级、禁用/撤销/过期组、多组、伪造徽标、畸形凭据、游客字段、模板秘密字段剥离。
- 真实 SessionInit Cookie 队列、会话保存与跨请求恢复；真实 Request 对恢复后的 CSRF token 接受正确值、拒绝错误值与重复提交。密码会话只是合成既有验证状态，不代表密码校验动作已修复。
- 私有页面对共享缓存零读写、公开目录可继续写新键、旧键秘密哨兵不被访问、两次独立请求身份/公共标记隔离；本地 HTTP 直接缓存命中不输出 public 头及 PHP 诊断。
- 既有独立 CSRF 回归 13 项；A1 的实际 PHP/MySQL/模板回归 600 项和默认 JavaScript 回归 13 项继续通过。

全部变更 PHP 文件两版语法检查通过。测试没有执行真实购买、扣积分或对外发送请求。

## 未闭合的依赖

`api/Vod::get_play_info/get_down_info` 仍需检查对应实际资源的组/积分/密码；前台整个下载列表、next URL、试看播放器和旧主题文章正文也是独立出口。文章/漫画 API 与前台阅读必须同时合并密码检查并先归一实际资源坐标。修复内容身份不会自动修正 `index/User::ajax_buy_popedom()` 与 `Ulog::saveData()` 的购买坐标和 Cookie 覆盖可信 user_id 问题；这些发现已持久化在完整访问计划中，必须由后续组继续处理。
