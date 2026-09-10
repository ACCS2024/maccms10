# Qiniu HTTP 响应解析

日期：2026-09-10。本组只修改 `extend/qiniu/src/Qiniu/Http/Response.php` 和 `Http/Client.php`，不修改上传管理器或业务适配器，不调用真实云服务。

## 复现与修复

在 PHP 8.3.33、8.4.25，开启 E_ALL 并将未抑制的警告转为异常，修复前各复现 10 项：未知错误码缺少状态文本；错误 JSON 缺少 `error`、为列表或字符串；读取缺失的三种诊断头；小写 Content-Type 丢失合法 JSON；503 不被识别为可重试；前一 HTTP 响应块的 Content-Type/请求 ID 混入最终响应。

- 未知且无内容的失败响应提供 `HTTP status N`；已知状态保留原状态文本。仅非空字符串 `error` 作为错误消息，其他 JSON 形状继续通过 SDK Error 返回原始响应内容，不再访问不存在的数组键或字符串偏移。
- 字段名和 JSON 媒体类型大小写无关，识别精确 `application/json` 及其参数，避免把 `application/jsonp` 当 JSON。公开 `headers` 保留最终响应字段的拼写和值；缺失的诊断头返回 null，保留 X-Via → X-Px → Fw-Via 优先级。
- HTTP JSON 使用原生严格解码；声明 JSON 的空字符串/损坏 JSON 在 2xx 时也作为解析失败。合法的 `0`、false、null、列表、字符串保持真实解码值，修正旧 SDK helper 把 `0` 当空输入的行为。无 body 的成功状态仍合法，响应具体业务结构仍由调用方验证。
- Client 按 HTTP 状态行分隔连续头块，只保留最终响应，覆盖 100 Continue、代理 CONNECT 和已跟随重定向的返回头；重复字段继续采用最终值，比较字段名时忽略大小写。此组不改变是否跟随重定向的策略。
- `needRetry()` 明确返回布尔值，识别负状态、500–599（排除原有 579）、996；不增加其他状态重试，不在 multipart 上传层增加发送次数。保留 `CURLOPT_SSL_VERIFYPEER=true`、`CURLOPT_SSL_VERIFYHOST=2`。

HTTP 字段名及媒体类型的大小写规则依据 [RFC 9110 §5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1)、[§8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1)。七牛说明 579 与上传后的回调失败有关，故保留 SDK 既有排除语义，见[七牛回调与鉴权](https://developer.qiniu.com/kodo/kb/1409/seven-cattle-callback-and-callback-authentication)。

## 验证

新增 `tests/extensions_audit_qiniu_response.php`，两版 PHP 各通过 95 项。测试使用真实 Response、Client、UploadManager、FormUploader 和 multipart 编码；仅以命名空间 cURL stub 替换传输，容器关闭网络，无真实域名访问或云端上传。

覆盖不同 JSON 形状、状态/重试边界、大小写/参数/缺失/重复响应头、连续 HTTP 头块、multipart 成功与失败、发送次数不增加、TLS 参数和传输失败返回契约。现有 SDK 测试 3 项、上传测试 20 项在两版重跑通过；两个修改文件及新测试在两版 lint 通过，两个修改文件的 PHP 8.4 PHPStan 校准扫描为零诊断。

```bash
docker run --rm --network none -v "$PWD:/app:ro" -w /app --entrypoint php \
  maccms10-migration-check:latest tests/extensions_audit_qiniu_response.php
docker run --rm --network none -v "$PWD:/app:ro" -w /app --entrypoint php \
  maccms-audit-php84:20260910 tests/extensions_audit_qiniu_response.php
```

测试中的 `baseline` 参数仅用于修复前代码复现，不在修复后执行。真实云端的错误载荷、代理配置、重定向目的地限制、响应长度/超时以及其他 SDK 的响应解析尚未由本组全面验证；原始错误消息保留于 SDK 内部，向最终用户展示前仍应由业务层脱敏。
