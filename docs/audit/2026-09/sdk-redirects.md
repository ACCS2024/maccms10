# 云 SDK 出站重定向

日期：2026-09-10。范围为七牛 Http Client、又拍云 Rest/Form/Pretreat/SyncVideo/purge 的重定向行为。本组不修改云接口成功载荷结构、上传协议或依赖版本。

## 真实本地复现

`tests/run_sdk_redirect_audit.py` 启动一个支持 HTTP/TLS 的临时 Unix socket 服务。容器 `--network none`，不访问 DNS 或真实云服务；仅把真实 cURL 请求连接到这个 socket，并使用临时 CA，保持 SDK 自己的跟随重定向和 TLS 验证设置。证书包含假源站/接收站和需测试的 SDK 固定主机名，私钥仅存在临时目录。

修复前两版 PHP 各通过 16 项基线断言，确认 Qiniu multipart、Upyun REST、Upyun multipart 收到 307 后均会向不同主机重放上传正文；HTTPS 到 HTTP 也能发生。两个 multipart 路径的凭证表单字段随正文发送。复现只用人工凭证与 `PRIVATE_UPLOAD_FIXTURE`，并不代表生产凭证已经泄露。

这与 [libcurl FOLLOWLOCATION 行为](https://curl.se/libcurl/c/CURLOPT_FOLLOWLOCATION.html)及 [Guzzle allow_redirects 默认设置](https://docs.guzzlephp.org/en/stable/request-options.html#allow-redirects)一致。移除跨主机 Authorization 请求头不能防止正文中凭证或用户上传数据跟随 307。

## 修改与兼容

- 七牛显式禁止自动跟随；3xx 返回带原状态码的 SDK Error，消息固定为 `Unexpected redirect from Qiniu API`，不拼入远端 Location 或原始响应内容。
- 又拍云各独立 Guzzle Client 均禁止跟随。Rest、异步/同步处理及 purge 通过同一精确 3xx 检查抛 RuntimeException，防止不被 Guzzle http_errors 拒绝的 3xx 被当作成功；Form 保留既有非 200 返回 false 的契约。
- TLS 证书及主机名验证保留。没有增加跨主机、同主机或 HTTPS 降级重定向例外；直接请求配置中的区域备用上传域名及有界错误重试保留，不根据 Location 选择重试目标。
- [七牛 303 文档](https://developer.qiniu.com/kodo/1652/redirect)说明其 returnUrl 主要面向浏览器上传后跳转。本项目服务端上传配置使用 returnBody，未设置 returnUrl；外部插件若设置 returnUrl，现在收到受控错误，应改用直接成功响应。收到拒绝不证明云端尚未保存文件，不能据此宣称可无条件安全重试。

## 回归

新增 PHP 测试使用真实 SDK/multipart、Guzzle、libcurl 和 TLS，覆盖 301/302/303/307/308、跨主机 HTTPS 与 HTTP 目的地、实际发送次数、直接上传成功、错误证书/主机名在 HTTP 请求前被拒，以及真实业务 Upyun 适配器在重定向失败后保留本地文件和原路径。

两版 PHP 新回归各 53 项通过；原 Qiniu 响应 95、区域/分块 65、上传 20、SDK 3 项及 Upyun 根依赖优先/内嵌依赖优先各 11 项均通过。六个修改 PHP 文件及新 PHP 测试两版 lint 通过；六文件 PHP 8.4 校准 PHPStan 零诊断，Python 语法检查通过。

```bash
python3 tests/run_sdk_redirect_audit.py \
  maccms10-migration-check:latest maccms-audit-php84:20260910
```

`--baseline` 仅用于本组修复前代码。运行器使用 socket 连接替换及临时 CA，不能验证真实云服务可达性或生产证书状态。

单独遗留：Upyun purge 仍引用官方仅文档化为 HTTP 的旧端点，本组只阻止它继续跟随重定向；其首次明文签名请求的兼容决策由下一极小组处理，未猜测 HTTPS 替代地址。其他显式 HTTP/自定义主机配置的可信性也不由本组自动验证。
