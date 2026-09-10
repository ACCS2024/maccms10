# Qiniu 区域发现与分块协议

日期：2026-09-10。范围：Zone、Config、ResumeUploader，以及必要的 `functions.php::explodeUpToken`；不修改 UploadManager、Response、Client 或云端接口版本。本组所有请求使用隔离 cURL stub，容器无网络，仅使用假 token 和临时文件。

## 已确认与处理

修复前，PHP 8.3.33/8.4.25 各复现 6 项：区域 JSON 缺字段触发警告；区域 HTTP 错误元组被当作 Zone 属性访问；块缺 `ctx` 触发警告；token 缺 `scope` 触发警告；短读仍发送不足声明长度的块并调用 mkfile；401 被重复发送。

- 区域查询保留成功返回 Zone、失败返回 `[null, Qiniu\Http\Error]` 的既有契约。检查所需主/备用域名列表及主机名格式，再构造对象；损坏结构返回明确协议错误。查询参数正确编码。域名校验仅验证格式，不等于官方域名白名单或网络目标隔离。
- Config 的 hostname getter 遇到失败元组抛出明确 RuntimeException，不访问错误类型的属性、不缓存失败。下一次查询仍可恢复，成功结果继续缓存。现有业务上传适配器捕获 Throwable 并保留源文件。
- token 解析验证字符串、三段结构、URL-safe Base64、JSON 和非空 scope，格式错误统一返回 `[null, null, 'invalid uptoken']`，不输出 token 或解码内容。保留带对象 key 的 scope 只提取 bucket 的语义。这只是格式解析，不承担签名真实性验证。
- ResumeUploader 拒绝以无效 token、stream 或 size 构造半初始化对象；逐次读取直至当前块完整，读失败或提前 EOF 在发送前抛出 RuntimeException。正常短读只要仍有进展就继续累积。
- 每个成功块必须具备匹配的 CRC32、非空 opaque ctx 和完整块 offset，之后才推进上传字节及加入 mkfile 上下文；不对 ctx 做解码/修改。损坏结构与校验失败最多重试一次，失败返回 SDK Error；永久 HTTP 失败不因缺少 CRC 而重复发送。传输失败保留现有配置备用域名的一次重试，mkfile 重试同样有界。
- 块与合并请求明确使用 `application/octet-stream`；保持 4 MiB 块大小、最后一块大小、上下文顺序和 UploadManager 的 finally 关闭流行为。

协议依据：[七牛分片上传 v1 指南](https://developer.qiniu.com/kodo/1650/chunked-upload)、[创建块](https://developer.qiniu.com/kodo/1286/mkblk)、[创建文件](https://developer.qiniu.com/kodo/1287/mkfile)。本库采用每块一次上传的已有实现，因此返回 offset 必须等于该块完整长度。七牛当前已将 v1 标为不推荐，并建议迁移 v2，见[当前 v1 说明](https://developer.qiniu.com/kodo/7443/shard-to-upload)；本组未擅自更换协议或推断 v1 已停止服务。

## 回归与边界

`tests/extensions_audit_qiniu_blocks.php` 在两版 PHP 验证畸形 token、查询结构、失败缓存恢复、固定区域、短读/EOF、块 schema/CRC/offset、备用域名、401/579/503 重试边界、重复失败终止。大文件测试通过真实 UploadManager→ResumeUploader→Client→Response，实际读取 4 MiB 加尾块，验证字节及上下文顺序、失败关闭文件并保留源文件。

新增回归两版各 65 项通过；既有响应 95 项、上传 20 项、SDK 3 项均通过。四个修改文件及新测试两版 lint 通过；四个修改文件 PHP 8.4 校准 PHPStan 零诊断。

```bash
docker run --rm --network none -v "$PWD:/app:ro" -w /app --entrypoint php \
  maccms10-migration-check:latest tests/extensions_audit_qiniu_blocks.php
docker run --rm --network none -v "$PWD:/app:ro" -w /app --entrypoint php \
  maccms-audit-php84:20260910 tests/extensions_audit_qiniu_blocks.php
```

未验证生产云端成功、全区域最新域名、网络中断后的远端清理、跨进程续传或服务端重试幂等性；发送失败不能证明远端没有接收数据。现有自动发现的区域映射和配置备用域名策略保留，后续 SDK 升级应独立评审。出站重定向/HTTPS 降级限制由下一独立组处理。
