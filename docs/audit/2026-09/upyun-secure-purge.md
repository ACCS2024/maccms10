# Upyun 默认安全配置下的旧 purge 接口

日期：2026-09-10。独立范围仅 `Upyun.php::purge` 的传输前检查，不改变刷新 API 的签名算法、请求体、成功响应字段或端点。

已确认：SDK 默认 `useSsl=true`，但 purge 始终使用硬编码 HTTP 地址，会静默把签名发送到明文接口。[又拍云官方接口文档](https://docs.upyun.com/api/purge/)及[官方 SDK Config 源码](https://github.com/upyun/php-sdk/blob/master/src/Upyun/Config.php)仍列出 `http://purge.upyun.com/purge/`；本轮未找到足以确认 HTTPS 替代端点的官方证据，未尝试真实刷新请求。

修改后，除非调用方明确设置 `useSsl=false`，purge 在创建 HTTP Client 前抛出 `RuntimeException: Secure purge endpoint is not supported by this SDK`。不给出虚构 HTTPS 地址，也不把不能发送的请求当成功。显式 false 保留历史 HTTP 契约，用于兼容外部调用；此模式不符合本项目默认安全部署要求。当前仓库业务没有 purge 调用。

`tests/extensions_audit_upyun_secure_purge.php` 使用真实 SDK 签名/返回处理，仅把 Guzzle HTTP Client 替换成本地响应 stub。修复前在两版 PHP 复现默认 true 仍选择 HTTP；修复后验证默认/非显式 false 零 Client/零请求、明确错误，以及显式 false 保持端点、请求体、签名头、返回数组和禁止重定向设置。没有真实凭证或请求外送。

PHP 8.3.33、8.4.25 新回归各 8 项通过，既有真实 HTTP/TLS 重定向回归各 53 项通过；修改文件和测试两版 lint 通过，Upyun.php 的 PHP 8.4 校准 PHPStan 零诊断。

```bash
docker run --rm --network none -v "$PWD:/app:ro" -w /app --entrypoint php \
  maccms10-migration-check:latest tests/extensions_audit_upyun_secure_purge.php
docker run --rm --network none -v "$PWD:/app:ro" -w /app --entrypoint php \
  maccms-audit-php84:20260910 tests/extensions_audit_upyun_secure_purge.php
```

未来如需恢复默认安全模式下的缓存刷新，应先确认官方 HTTPS API、认证及返回契约，再独立迁移；不能仅替换协议字符串并据此宣称生产可用。
