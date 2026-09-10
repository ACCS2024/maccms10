# Upyun 顺序分块上传

日期：2026-09-10。独立修改 `extend/upyun/src/Upyun/Uploader.php`，不替换依赖或改业务上传适配器。通过无外网容器内真实回环 HTTP 验证 Upyun、Guzzle 和 PSR stream；使用临时文件及假凭证，测试服务不记录 Authorization 值。

## 已确认与修复

修复前，两版 PHP 各 6 项基线断言通过（含服务启动检查）：缺少 UUID/下一片 ID 会触发 strict PHP 错误；提前返回 -1 会丢弃余下数据并报告完成；重复片号会读至 EOF 后继续发送空块，测试服务在第七个请求受控中断以避免失控；合并请求复用了上一片正文。

修复保持顺序分块协议和业务返回值：

- 分块模式要求明确的正整数流长度；验证初始化 UUID 非空且符合可安全传递的字符格式，若提供起始片号则须为 0。校验后续响应中提供的 UUID 与本次任务一致。
- 循环次数由本地文件长度和固定 1 MiB 块大小决定。每次读取足够字节再发送，正常短读持续累积；提前 EOF 抛出 RuntimeException，不上传不完整块。
- 每片响应的下一片 ID 必须等于预期顺序位置，最后一片必须为 -1。缺失、非数字、重复、倒退/跳跃或提前结束均抛出明确协议异常，不再发送下一片或合并。
- 每个请求使用新的 Rest 对象，初始化与合并不携带分片正文，合并也不沿用旧分片 ID。远端 HTTP 错误继续通过原异常机制传出，不额外增加重试。

依据又拍云的[顺序断点续传协议](https://docs.upyun.com/api/rest_api/)：分块大小固定为 1 MiB，片号从 0 开始，按响应的下一片序号顺序上传，全部完成时返回 -1，最后执行 complete。现有 SDK 未启用并行模式，本组不改变协议模式。

## 验证

`tests/extensions_audit_upyun_blocks.php` 验证真实 HTTP 的响应缺字段、非法序号、任务改变、EOF、短读、上传字节和完成阶段正文；实际 30 MiB 文件触发默认 AUTO 阈值并完成 30 片上传，含初始化/合并共 32 个请求。测试对异常路径检查发送次数和无 complete，确认源文件不被删除；保留 PSR stream 既有生命周期行为，其析构可能关闭包装的 resource。

PHP 8.3.33、8.4.25 新回归各 47 项通过；现有 Upyun 依赖回归按根依赖优先、内嵌依赖优先两种顺序分别 11 项通过。修改文件/测试两版 lint 通过；Uploader 的 PHP 8.4 校准 PHPStan 零诊断。

```bash
docker run --rm --network none -v "$PWD:/app:ro" -w /app --entrypoint php \
  maccms10-migration-check:latest tests/extensions_audit_upyun_blocks.php
docker run --rm --network none -v "$PWD:/app:ro" -w /app --entrypoint php \
  maccms-audit-php84:20260910 tests/extensions_audit_upyun_blocks.php
```

测试只在回环服务显式启用 HTTP，生产配置继续默认 HTTPS。`baseline` 参数仅用于修复前代码复现。未进行真实云上传、断点任务清理或跨进程续传验证，异常退出不等于远端数据已清除；网络重定向、响应长度上限和其他 SDK 功能另行审计。
