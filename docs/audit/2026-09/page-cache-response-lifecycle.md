# 页面缓存命中与 404 响应

整页缓存命中以 HttpResponseException 返回 HTML/JSON 响应，保留明确的 private/no-store，通过 SessionInit 与 SecurityHeaders 完成 Cookie、CSP、nosniff 等收尾。缓存值必须是字符串；空串和 `0` 仍是有效缓存，错误类型按未命中处理。保持原有命中时 Accept/显式 json 的编码行为，未将片段渲染合同扩大到所有旧 AJAX 入口。

404 渲染绕过正常页面缓存的读写，配置模板、jump 降级和最小 HTML 降级统一返回状态 404 与私有响应。直接渲染错误模板，避免缓存分支抛出默认 200 响应覆盖缺失资源状态。

`framework_audit_page_responses.php` 使用真实 All、Middleware、SessionInit、安全中间件与回环 HTTP，验证 70 项，包括实际 JSON MIME、Cookie、安全头和 404 缓存隔离。原身份/私有缓存 MySQL 回归改用同一正常响应传输夹具；HTTP 头按允许的冒号空白解析，不依赖手写 header 的格式。

锁持有者标识、渲染失败后的释放、缓存服务器故障、私有资源其它直接输出和缓存未命中时的旧 JSON 片段合同仍需独立处理。本批不把整个缓存系统标为审计完成。
