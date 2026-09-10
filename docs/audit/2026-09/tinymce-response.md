# TinyMCE 上传失败响应（2026-09）

## 已确认问题

`application/common/extend/editor/Tinymce.php::back()` 原来无视 `$status`，始终读取 `$data['file']` 并输出 `location`。`Upload::upload_return()` 在缺少文件、扩展名拒绝、图片处理失败等分支会以 status=0 和空 data 调用它，PHP 8 因此产生未定义字段警告；失败同时沿用了成功 JSON 的外形和 HTTP 200。

TinyMCE 的上传协议以成功响应中的字符串 `location` 更新图片地址，非 2xx 状态触发失败；官方 PHP 示例也明确把上传失败响应设为错误 HTTP 状态。见 [TinyMCE 5 上传配置](https://www.tiny.cloud/docs/tinymce/5/file-image-upload/) 与 [官方 PHP 上传处理器示例](https://www.tiny.cloud/docs/tinymce/latest/php-upload-handler/)。本组仅采用其响应契约，不复制示例的上传鉴权或文件安全策略。

## 修改

仅修改 TinyMCE 适配器，保留既有 echo + exit 调用方式：

- `status` 为整数 1 或字符串 `"1"`，并且 `data.file` 为非空、有效 UTF-8、无控制字符且不超过 8192 字节的字符串时，返回 HTTP 200 与原样 `location`。相对路径、Unicode 路径和远端签名 URL 均保留。
- 明确失败状态 0/`"0"`/false 返回 HTTP 400 与 JSON `error.message`，不返回 `location`。此接口没有细分错误码，400 表示本次上传被拒绝；不凭翻译后的消息推断更具体原因。
- 畸形内部状态或“成功”却没有有效文件地址，返回受控 HTTP 500。数组、对象、数字、空值不会被强转成文件地址，也不会读取错误容器。
- JSON 响应显式设置 Content-Type 和 nosniff。错误消息保留有效字符串，非法 UTF-8 用 JSON 替代字符编码；非字符串或超过 4096 字节则使用固定错误消息，避免对象转换和空响应。

上传身份/CSRF/实际图片处理沿用前组，不改变存储顺序、客户端配置、语言或依赖。

## 验证

`php tests/security_audit_tinymce.php` 在 PHP 8.3.33、8.4.25 各 **104 项通过**。

- 27 个独立子进程覆盖成功、显式失败仍带 file、缺字段、畸形数据容器/字段/状态、二进制及超长字符串，检查实际 exit 输出、HTTP 状态和无 PHP warning。
- 临时目录中的真实 PHP CLI-server 验证 HTTP 状态、JSON Content-Type、nosniff 及成功/失败 JSON。
- 同一 HTTP fixture 使用真实 Request/multipart/UploadedFile、Admin 模型鉴权、CSRF、图片写入和 SQLite Annex 元数据，验证正常 TinyMCE 上传 200，缺文件/拒绝扩展名 400，后两者没有文件或数据库变化。

仅连接 loopback，使用临时图片与 SQLite fixture；不启动项目入口、不读取本地业务配置、不接生产。执行依赖当前 Composer 锁文件及项目 PHP 扩展，沿用 `tests/fixtures/security_audit_upload_identity_db.php` 的隔离身份环境；不修改该已提交共享 fixture。日志：`/tmp/maccms-audit-20260910/tinymce/{83,84}.log`。

仓库仍缺少模板引用的 TinyMCE 浏览器资源，本组未声称真实 TinyMCE 浏览器可用，恢复资源与上传 CSRF 客户端接线仍需后续依赖批次。已移动文件之后的后续处理或数据库错误是否遗留文件，属于跨资源一致性调查；本组的“失败零写入”证据仅针对上述缺文件/扩展名拒绝两个真实用例。
