# 52f70b90 阶段完整复验

本次验证固定提交 `52f70b90`。源码树、生产依赖锁、工具锁、原始报告摘要保存在[机器可读记录](phase-verification-52f70b90.json)。使用独立导出的已提交源码和干净锁定依赖；没有借入工作区中未提交的漫画读取、漫画购买、默认主题建议或其他候选修改。

| 检查 | PHP 8.3.33 | PHP 8.4.25 |
| --- | ---: | ---: |
| 已安装树全量原生编译，包括依赖与归档 | 5,363 文件，0 错误或诊断 | 5,363 文件，0 错误或诊断 |
| 默认回归 | 133 独立进程，0 失败 | 133 独立进程，0 失败 |

默认回归包括 unit、models、financial、upload、storage、remote_upload，使用各脚本自己的隔离环境和 SQLite。故障注入预期产生的私有清单日志不等于测试失败；统计来自运行器最终结果。此默认命令不能代替专项 MySQL、主从路由、HTTP、浏览器或真实扩展检查。

同一源码与工具锁完成 PHPStan level 1 和额外 level 5 检查：分别为 **421**、**1,166** 条文件诊断，均无全局分析错误。PHPCompatibility 8.3–8.4 为 **0 错误、8 警告**。运行器因存在诊断正常返回非零，没有添加 baseline 或 ignoreErrors。级别不同不能直接比较条数；比上一固定快照减少的条目也不能当作漏洞修复数量。

本轮相邻批次已各自通过针对性验收：

| 提交 | 范围 |
| --- | --- |
| 4cecb8b | Cookie 原生解析、精确账号凭据和主库撤销核验 |
| a91d494 | 单模块搜索建议的真实 Collection、公开字段与缓存校验 |
| 5a8ddd0 | 后台 CSV/XLSX 导出的 Collection 合同 |
| 17a09659 | 手工附件/头像的完整衍生文件、持久意图和精确引用 |
| ccb903c7 | 文章购买锁内实际章节、价格和权限 |
| 7967fe99 | 漫画缺少旧版可选字段时的解析兼容 |
| 5c06ce08 | 统一搜索真实结果、主库公开状态和输入边界 |
| 52f70b90 | 四份普通搜索建议的文本显示与选择合同 |

这些提交的 MySQL/浏览器等详细证据分别记录在对应专项报告。完整复验没有在这里重跑或混计其全部断言数量。

复跑入口：

```sh
composer install --no-dev --no-plugins --no-scripts --no-interaction
php tests/php_lint.php --all --json=/tmp/php-installed-lint.json
php tests/run_audit.php
composer --working-dir=tools/audit install --no-plugins --no-scripts --no-interaction
python3 tools/audit/run.py --output=/tmp/maccms-static-report
php tools/audit/vendor/bin/phpstan analyse -c tools/audit/phpstan.neon --level=5 --no-progress --error-format=json --memory-limit=2G
```

固定数字需要检出所标提交，并使用相应 PHP 版本。先做生产依赖全树编译，再安装独立静态工具，可避免把工具自己的 vendor 混入安装树计数。证据目录为 `/tmp/maccms-audit-20260910/phase-52f70b90/`，临时日志不是永久审计档案。

继续处理的范围包括漫画完整读取/购买、Group 与主从一致性、AI 内部资源查询、事务收尾异常、下载和 AI 封面的资源绑定、附件删除、配置及前端来源治理。全量编译通过只证明已扫描文件可编译；尚未完成整个商业部署验收，也没有部署或修改生产数据。
