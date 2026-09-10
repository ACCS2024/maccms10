# Actor / Topic 详情路由审计（2026-09-10）

严格错误模式的真实 HTTP fixture 中，actor/topic 详情请求返回 HTTP 200，却没有详情标题与 `data-detail-id`。反射请求显示 `/actor/detail/id/1.html` 与 `/actordetail-1.html` 都被分派到 Actor::index，`/topic/detail/id/1.html` 与 `/topicdetail-1.html` 都被分派到 Topic::index；不是缺失数据库记录，也不是仅仅需要执行前端 JavaScript。

根因是 `application/index/route/web.php` 中更早注册的 `actor-<page?>`、`topic-<page?>` 首页分页规则。TP8 默认 `route_complete_match=false`；当页码与分隔符可选时，这些规则可以只匹配 actor/topic 前缀，截获后续详情和搜索请求。已有 `actor$` / `topic$` 规则无法补救，因为前一条已经命中。

仅给这两条可选分页规则增加 `completeMatch()`，使首页/页码规则在完整匹配后才生效。详情短链继续使用已注册的 `actordetail-<id>` / `topicdetail-<id>`；传统 controller/action 及 API 返回的 `/actor/detail.html?id=1` 按既有自动路由正确分派。没有改全局匹配开关、URL 生成规则或业务控制器。

验证：

- `tests/framework_audit_detail_routes.php` 使用真实 TP8 Router 和完整应用路由表，隔离 HelpCfg 配置读取。49 项在 PHP 8.3.33 / 8.4.25 通过，含原规则负控；首页、分页、详情短链、路径参数、查询参数、搜索、legacy_pathinfo_url 两种设置，及保持短链生成格式。
- 专用 MySQL HTTP fixture 两版各 10 条 HTTP 用例通过；每版 6 种详情 URL 均明确断言 `data-detail-id="1"`，另检查 4 种首页/分页响应。真实详情请求的 action 为 detail、id 为 1，并恢复 CI Actor / CI Topic 页面标题。
- `/vod/type/id/6.html` 是另一种情况：实际分类 ID 正确，默认模板的列表通过 JavaScript 加载，初始 HTML 应断言 `data-type-id="6"`，内容由对应 API 的种子标题断言覆盖。
