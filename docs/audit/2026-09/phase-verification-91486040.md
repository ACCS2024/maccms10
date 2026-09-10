# 91486040 阶段完整复验

本次固定提交 `91486040`，使用独立导出的已提交源码和干净锁定依赖。源码树、生产/工具锁、工具版本及原始报告摘要见[机器可读记录](phase-verification-91486040.json)。工作区未提交的配置、资源来源、部署等修改没有借入验证。

| 检查 | PHP 8.3.33 | PHP 8.4.25 |
| --- | ---: | ---: |
| 已安装树全量原生编译，包括依赖与归档 | 5,387 文件，0 错误或诊断 | 5,387 文件，0 错误或诊断 |
| 默认回归 | 139 独立进程，0 失败 | 139 独立进程，0 失败 |

默认包含 unit、models、financial、upload、storage、remote_upload。部分专项在子进程中展开故障矩阵；此表统计默认运行器启动的顶层进程，不能与内部断言数混加。默认数据库环境为 SQLite；各批 MySQL、主从、HTTP、浏览器、完整内容读取和容量证据保留在对应专项报告。

PHPStan level 1 为 **423** 条文件诊断，额外 level 5 为 **1,178** 条，两者均无全局分析错误；PHPCompatibility 8.3–8.4 为 **0 错误、8 警告**。存在诊断时工具正常返回非零，未加 baseline 或 ignoreErrors。与旧快照的差额不是漏洞修复数量。

本次完整回归确实发现并处理了一次失败：较早 `6330cd84` 的 138 个默认进程在双版本各失败 1 项。旧漫画视图夹具只给原始路由参数，没有提供新读取流程的授权结果。`756ac6a8` 修正夹具，补查实际授权坐标以及未解析、不可购买、密码未通过时不显示按钮的合同；没有放宽生产授权。随后在本固定快照重跑完整编译与全部默认回归通过。前次失败日志摘要也保留于 JSON，未把失败批次标成通过。

近期独立批次：

| 提交 | 范围与报告 |
| --- | --- |
| c84bc161 | [AI 内部查询的真实 Collection、主库和公开状态](ai-search-resources.md) |
| 40931297 / a2460b94 | [漫画读取](manga-resource-authorization.md)、[锁内购买](manga-purchase-resources.md)及[Group 容量](manga-permission-capacity-followup.md) |
| e71164d3 | [下载图片及完整衍生资产目录](download-asset.md) |
| 9b0006ad | [独立配置数据解析器及分词前预算](data-config-parser.md) |
| f15a1285 | [内容购买 owner 的故障收尾和未知结果](purchase-owner-acknowledgements.md) |
| 6330cd84 | [附件 owner 的故障收尾与证据保留](attachment-owner-acknowledgements.md) |
| 7f31d6b7 / 91486040 | [CSV 往返](csv-roundtrip.md)与[原生分配前预算](csv-import-budgets.md) |
| c5bf8e95 | [XLSX 文本兼容](xlsx-text-compatibility.md)，在固定快照之后独立验证，不计入上表 139 进程 |

复跑入口：

```sh
composer install --no-dev --no-plugins --no-scripts --no-interaction
php tests/php_lint.php --all --json=/tmp/php-installed-lint.json
php tests/run_audit.php
composer --working-dir=tools/audit install --no-plugins --no-scripts --no-interaction
python3 tools/audit/run.py --output=/tmp/maccms-static-report
php tools/audit/vendor/bin/phpstan analyse -c tools/audit/phpstan.neon --level=5 --no-progress --error-format=json --memory-limit=2G
```

固定数字需检出所标提交、使用对应 PHP，并在安装静态工具 vendor 之前统计生产安装树。证据目录 `/tmp/maccms-audit-20260910/phase-91486040/` 属临时执行环境；仓库保留摘要、测试与复跑入口。

[跨模块清单](cross-cutting-followups.md)继续区分已完成、已复现待修和待核实：调用方 SAVEPOINT、其它金融/存储意图收尾、AI 资源绑定、附件删除、共享 Group/公开查询、XLSX 预算及 TP8 导入入口、配置加载与前端来源治理仍未闭环。没有进行生产部署、生产数据修改或完整商业上线验收。
