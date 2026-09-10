# 上传 Cookie 会话 CSRF 闭环（2026-09）

本组依赖上传身份组 `8209907` 和图片处理组 `1a36cb4`，只处理现有上传请求的令牌与浏览器接线。没有新增公开 API 上传入口，也不把可被 PHP 内部调用的 Upload 模型当作匿名公网路由。

## 已确认问题与处理

- 后台历史 `security_csrf_admin_exempt=upload/*` 使上传缺少强制令牌，关闭全局后台 CSRF 时也一样。`CsrfGuard` 现对后台 `upload/upload` 的 POST 强制验证上传令牌，在可选总开关与豁免列表之前执行。示例配置取消该豁免；保留旧配置的部署也受到模型与中间件校验。
- Cookie 登录头像上传和后台上传统一复用 `mac_csrf_token()` 已有的 session `__csrf_token__`。新增 `UploadCsrf` 仅接受显式 `X-CSRF-Token`，无 header 时才接受 **POST body** 的 `csrf_token`。显式错误、空或非字符串 header 不回退；query、自动携带的 Cookie、Origin/Referer 不能代替令牌。校验在文件处理和附件/用户元数据写入之前。
- 只有同一次真实 `User::checkLogin()` 已验证通过、且 JWT 功能启用的 Bearer 身份可以免 Cookie CSRF；无效 Bearer 不回退 Cookie，关闭 JWT 时不能靠 Bearer 外观绕过。后台凭管理员 Cookie/session 授权，即便额外带合法会员 Bearer，也仍要求令牌。
- 后台 UEditor/UMeditor 的只读 config GET 保留，仍通过现有服务器身份/RBAC 校验；GET 不会执行上传。
- 新 `static/js/upload_csrf.js` 只向同源 `upload/upload` 和 `user/portrait` URL 加令牌。它分别接入窗口 jQuery、layui 的 jQuery、实际表单 submit；不全局替换 fetch/XHR，不把令牌写入 URL。支持子目录及 `.html` 路由。
- 三个当前会员主题加入相同令牌桥接。默认/旧主题头像插件实际以隐藏 iframe + submit button 提交，已确认并通过浏览器检查真实 multipart 隐藏字段。默认主题延迟加载的头像 Ajax 也覆盖。
- demo 的原生 fetch 显式使用同源 header。该文件同时修正只接受 `url` 而不接受服务器正常 `file` 成功响应的问题，真实成功上传已验证。
- 后台公共 head 接线覆盖 layui 上传；原生上传表单显式带隐藏 token，并明确 `input=file1` 与现有文件字段一致；UEditorPlus 实例通过实际模板的 `serverHeaders` 带 token，真实图片对话框 WebUploader 已验证。

## 已验证及边界

| 检查 | 环境 | 结果 |
| --- | --- | --- |
| 新上传 CSRF 模型/真实 ORM/UploadedFile 回归 | PHP 8.3.33、8.4.25 × SQLite、MySQL 非严格模式 × index/admin 返回格式 | 每进程 56 项通过 |
| 既有上传身份回归 | 同上 | 每进程 203 项通过 |
| 既有图片上传、图片处理 | 两版 PHP + Imagick 3.8.1 | 38、111 项通过 |
| 实际浏览器与 HTTP | Chromium 151.0.7922.108；两版 PHP CLI-server + SQLite | 每版 73 项通过；自动启动入口另含 1 项启动检查 |

浏览器执行实际库：三个 iframe 插件副本、demo fetch、默认主题 deferred Ajax、layui、原生表单，以及 UEditorPlus 实际 `insertimage` 对话框。会员页只渲染上传相关依赖片段，后台使用真实 head/原生 form/UEditor 模板；这不是整站所有页面的 UI 验收。

HTTP 使用真正 `think\Request` 解析浏览器 multipart 和真正 HTTP `UploadedFile`，不设置 CLI file test 标记。隔离 fixture 只提供测试会话状态/固定测试令牌与 Cookie，由真正 User/Admin 模型和 SQLite 复核身份；会话存储后端不在本测试覆盖范围。未经过应用原入口，数据库、图片目录均是每请求独立的临时资源。中间件在 `cli-server` 下运行，避免把其普通 CLI 跳过分支误当成 HTTP 验证。

浏览器检查成功请求确实写入真实图片与 1 条 Annex，实际 token 位于 header 或 multipart body，URL 不含 token；缺失/错误/数组 body/header 优先级/query-only/cookie-only等请求零文件、零 DB 变更。实际 UE 对话框和原生 form 分别另测缺失与错误 token 均 HTTP 403；即使 fixture 设定全局后台 CSRF 关闭、保留旧 `upload/*` 豁免也不能绕过。Cookie 头像拒绝保持现有 code=0 JSON 协议。

## 可复现入口

模型套件（安装当前 Composer 锁依赖及项目要求扩展后）：

```sh
php tests/security_audit_upload_csrf.php
php tests/security_audit_upload_csrf.php admin
```

MySQL 仅连接测试库 `maccms_audit_upload`，使用 `upload_audit_` 前缀并重建 User/Group/Admin/Annex 测试表。设 `UPLOAD_AUDIT_MYSQL=1`，可另设 `UPLOAD_AUDIT_HOST`、`UPLOAD_AUDIT_PASSWORD`；不要指向生产。MySQL 本组与既有上传身份套件串行运行。

浏览器工具是独立测试依赖，固定 `playwright-core` **1.58.2**，官方 registry URL 与 SHA-512 integrity 存于 `tests/browser/package-lock.json`。不会下载安装浏览器，也不改变应用依赖：

```sh
npm ci --prefix tests/browser --ignore-scripts --no-audit --no-fund
CHROMIUM_BINARY=/usr/bin/chromium PHP_BINARY=php node tests/browser/upload_csrf.cjs
```

Node >=18，系统 Chromium，PHP 需当前项目依赖与 GD/Imagick/PDO SQLite。脚本只启动临时目录中的 PHP CLI-server fixture，动态选择 loopback 端口，退出清理。可用 `UPLOAD_AUDIT_BASE_URL=http://127.0.0.1:18494` 接入外部启动的同一 fixture；仅接受 loopback 地址。浏览器阻止非 fixture origin 网络。CI 在现有两 PHP 任务加入上述独立 npm ci 与 Node 入口即可，不需要改变生产 Docker 镜像/扩展。

本地复现运行器为 `maccms-audit-image83:20260910`、`maccms-audit-image84:20260910`，只读挂源代码、`-w /tmp`，显式 CLI-server router `tests/fixtures/security_audit_upload_http.php`。MySQL 使用独立测试容器的专用 `maccms_audit_upload`。日志在 `/tmp/maccms-audit-20260910/upload-csrf/`；本地测试工具目录 `/tmp/maccms-audit-20260910/upload-browser-tools`。

## 明确未宣称完成

- CKEditor、KindEditor、UMeditor、TinyMCE 虽有模板和服务端适配器，仓库缺少其模板引用的 `editor/...` 浏览器资源。本组不补来源/版本未锁定的库，也不把模板协议接线当作浏览器可用。若之后恢复这些资源，必须同时补各自上传令牌协议和真实浏览器回归；当前服务端会拒绝缺令牌请求。尤其 [UMeditor 官方旧图片插件](https://github.com/fex-team/umeditor/blob/master/dialogs/image/image.js) 直接调用原生 `form.submit()`，另有独立拖拽 XHR，不能假定本组 submit 事件桥接能覆盖它。
- 自定义主题或外部 Cookie 客户端需要同步提交 header 或 POST body 令牌；仅同源 Origin、仅 POST 或旧上传豁免均不会获准。第三方主题不在本仓库回归覆盖内。
- 当前 UI 没有发起 base64 头像请求；模型保留该格式并用真实图片验证 token 允许/拒绝契约，没有新增 UI。
- Tinymce 失败响应契约与文件替换/数据库写入的跨资源一致性留待各自独立批次。本组不重构上传生命周期，不自动删除历史文件。
