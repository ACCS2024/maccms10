# cdc213f 阶段复验与后续批次

这是固定提交版本的阶段记录，审计仍在执行。源码、依赖锁摘要、工具锁摘要与原始报告摘要见 [机器可读记录](phase-verification-cdc213f.json)。验证对象是独立导出的已提交源码和干净锁定依赖，工作区中其它来源尚未隔离审查的改动不在此结论内。

| 检查 | PHP 8.3.33 | PHP 8.4.25 |
| --- | ---: | ---: |
| 已安装树原生编译，包含依赖与归档 | 5,332 文件，0 错误/诊断 | 5,332 文件，0 错误/诊断 |
| 默认 unit/models/financial/upload/storage | 128 独立进程，0 失败 | 128 独立进程，0 失败 |
| IP 配置、Request 与 loopback HTTP | 119 检查 | 119 检查 |
| MySQL 会员会话 / JWT | 43 / 128 检查 | 43 / 128 检查 |

同一源码使用锁定 PHPStan / PHPCompatibility 完成静态重扫：PHPStan **422 条文件诊断、0 全局分析错误**；PHPCompatibility **0 错误、8 警告**。分析器正常完成但存在待分类诊断，运行器因此返回非零。这些数字不是漏洞数量，更不能据原生编译通过认定全部 PHP 8 运行和业务问题已解决。分类与解释见 [静态候选](static-candidate-triage.md)。

近期已经分别提交的修改如下。各报告记录了自己的准确范围、测试与限制，不把相邻批次借入本批验证。

| 提交 | 范围与证据 |
| --- | --- |
| c425926 | [UTF-8 截取](unicode-substring.md)：ASCII/四字节字符、非法参数与安装子目录 |
| 947260e | [远程存储基础](storage-intent-foundation.md)：SQLite 199 / MySQL 218，实际 SDK 25；生产上传接入独立进行 |
| 7420477 | [视频购买](video-purchase-resources.md)：SQLite 1180 / MySQL 1300、并发/锁等待，实际 PHP Chromium 61 |
| ce8813f | [文章读取](art-resource-access.md)：每版根/子目录各 714 PHP / 41 前端检查，静态和 RSS 公开投影 |
| cdc213f | [可信代理 IP](client-ip-trust.md)：默认连接来源、明确代理名单与指定头、无跨请求缓存 |
| b4a5fc0 | [IPv4 输入](ipv4-location-input.md)：上述固定快照之后独立提交，33 检查；18,986 区间结构检查 |
| 7949d4d | [公开目录状态](public-content-list-state.md)：上述固定快照之后独立提交，265 实际 MySQL 检查 |

可复跑入口：

```sh
composer install --no-dev --no-plugins --no-scripts --no-interaction
php tests/php_lint.php --all --json=/tmp/php-installed-lint.json
php tests/run_audit.php
composer --working-dir=tools/audit install --no-plugins --no-scripts --no-interaction
python3 tools/audit/run.py --output=/tmp/maccms-static-report
```

复验固定数字需检出所标注的提交，并分别使用 PHP 8.3/8.4；当前 HEAD 的测试数会随新批次增加。MySQL、浏览器、原生缓存扩展和完整内容链回归还有独立入口，不能用上面默认 SQLite 命令代替；各专项报告与 CI 保留运行配置。

后续继续按根因分批：旧 Cookie 凭据及主库撤销校验、远程上传/头像接入及后续下载/AI 封面、文章购买锁内权限和定价、漫画正文链、搜索建议的 Collection/字段兼容、共享缓存与深分页并发、附件删除引用、配置/更新/前端资源来源审查，以及剩余静态候选。历史生成文件/CDN、真实存储账户和生产数据没有在本轮被操作，也没有进行生产容量或故障演练。临时运行日志仍在执行环境中，仓库保留摘要和复跑入口，不把临时路径当成永久证据库。
