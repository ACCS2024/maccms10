# TP8 Request 输入清洗失效

`RequestSecurity` 原来仅修改 `$_GET` / `$_POST`。锁定的 TP8 版本在 `Request::__make()` 时已复制这两组数据，并解析 JSON 请求体；因此控制器读取 `Request::get()` / `post()` / `param()` 时仍得到清洗前内容。真实 Request 的复现同时覆盖中间件之前是否已调用 `param()`，两种情况下旧代码都会失败。

修复从当前 Request 的未过滤 GET/POST 副本清洗，并通过 `withGet()` / `withPost()` 写回同一实例。框架这两个公开方法不会使合并参数缓存失效，所以调用 `setRoute([])`：该方法将空更新与现有 route 合并并重置合并标志。回归实际验证原有路由参数保留，重合键仍按 route → GET → POST 的原框架顺序覆盖，已缓存和未缓存场景一致。旧代码直接访问的 GET/POST 超全局也继续清洗。

保留总开关、安装入口跳过、后台默认跳过且需单独开启，以及 JSON 默认跳过正文的约定。JSON 判断依据当前 Request 捕获的 Content-Type，包含 TP8 会解析的 `+json` 媒体类型。总开关/后台开关是数组等错误配置时不会产生强转诊断；错误的 JSON 跳过配置保守地保持跳过正文。

原始 body 字节、Cookie 和路由参数保持不变；JSON 开启正文清洗时只修改已解析 POST，原始 body 仍可用于签名校验。输入清洗是既有可选功能的兼容修复，不能替代输出位置所需编码、富文本净化和 CSP。本组保持原有 GET/POST 范围；PUT/PATCH/DELETE 的解析体、`Request::request()` / `$_REQUEST` 不在该策略内，不宣称覆盖这些接口。

验证：`php -d error_reporting=-1 tests/framework_audit_request_security.php`。PHP 8.3.33 / 8.4.25 各 300 项断言通过，`E_ALL` 诊断转换为异常。32 个独立进程使用真实 `Request::__make()` 与中间件，覆盖缓存预读、请求实例身份、输入来源优先级、开关与安装/后台入口、JSON 默认/显式跳过/启用、媒体类型、嵌套输入和零值、原始 body 字节保留。测试没有调用应用初始化、没有读取站点 `.env` 或执行数据库/网络操作。
