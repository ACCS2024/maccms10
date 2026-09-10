# fc8c07ce 阶段完整复验

日期：2026-09-11。固定提交 `fc8c07ce`，使用独立导出的已提交源码和干净锁定生产依赖；未借入工作区的配置加载、资源来源、部署等修改。源树、锁文件、工具版本、分类和原始报告摘要见[机器可读记录](phase-verification-fc8c07ce.json)。

| 检查 | PHP 8.3.33 | PHP 8.4.25 |
| --- | ---: | ---: |
| 已安装树全量原生编译（含依赖和归档） | 5,392 文件，0 错误/诊断 | 5,392 文件，0 错误/诊断 |
| 默认回归 | 143 独立进程，0 失败 | 143 独立进程，0 失败 |

默认套件为 unit、models、financial、upload、storage、remote_upload；数据库默认 SQLite。143 是顶层进程数，部分测试还有隔离子进程和故障矩阵，不能与断言数相加。故障夹具产生的预期诊断与未知结果提示不被误报为生产故障，也没有隐藏运行器的失败退出状态。

PHPStan level 1 为 **421** 条文件诊断，level 5 为 **1,190** 条，两档均无全局分析错误。PHPCompatibility 8.3–8.4 为 **0 错误、8 警告**。未增加 baseline / ignoreErrors；计数变化不等于漏洞数量变化。新 XLSXReader 的闭包控制流、未使用捕获及已有防御性类型检查进入分类复审。

相对 [91486040](phase-verification-91486040.md)，新增独立批次：

| 提交 | 变化和专项证据 |
| --- | --- |
| c5bf8e95 | [XLSX 普通共享/内联文本](xlsx-text-compatibility.md)，68 项普通文本矩阵继续保留 |
| 3bc33194 / 059fc491 | [XLSX 目录、XML、编码、坐标与展开预算](xlsx-import-budgets.md)，双版各 449 项 / 58 隔离进程 |
| d899105f | [漫画普通保存](manga-save-input.md)，双版各 136 SQLite / 408 MySQL 三模式断言；另有读取/解析及 940 项 MySQL 购买回归 |
| fc8c07ce | [文章普通保存](art-save-input.md)，双版各 170 SQLite / 510 MySQL 三模式断言；另有读取及 1,273 项 MySQL 购买回归 |

文章组合边界为 8 MiB 正文、标题和备注各 1 MiB，真实落库完整；该专项进程最高 PHP 分配峰值为 SQLite 60.02 MiB、MySQL 64.02 MiB，默认限制 128 MiB。这是特定保存夹具的观测，不是整站并发容量保证。

完整回归没有消除仍待处理的模型合同。固定源的独立普通 MySQL 调查实际观察到 Vod 缺省/字符串/伴随字段错误、未提供播放字段时清空现有播放和下载组、改名后旧重复目录仍在、连续保存无关视频累加目录行。这些属于已复现待修，尚未进入“通过”统计。表单删除全部分组与模型省略字段的含义必须一起核对。

复跑入口：

```sh
composer install --no-dev --no-plugins --no-scripts --no-interaction
php tests/php_lint.php --all --json=/tmp/php-installed-lint.json
php tests/run_audit.php
composer --working-dir=tools/audit install --no-plugins --no-scripts --no-interaction
python3 tools/audit/run.py --output=/tmp/maccms-static-report
php tools/audit/vendor/bin/phpstan analyse -c tools/audit/phpstan.neon --level=5 --no-progress --error-format=json --memory-limit=2G
```

固定数字需检出所标提交并使用对应 PHP，在安装静态工具 vendor 之前统计生产安装树。临时原始证据在 `/tmp/maccms-audit-20260910/phase-fc8c07ce/`，仓库保留摘要和测试入口；更早失败及修复记录仍见旧阶段报告。

继续按[跨模块清单](cross-cutting-followups.md)处理 SAVEPOINT/其它事务收尾、AI/附件资源绑定与删除、共享身份/公开查询、导入接收与保存、配置和资源来源治理。此记录不表示审计结束或商业上线验收通过。
