# f32e4000 阶段完整复验

日期：2026-09-11。固定提交 `f32e4000`，导出已提交源码并挂载干净、锁定的生产依赖；不包含未提交的卡密修复、配置、资源来源和部署改动。完整来源、锁文件、工具版本、分类及报告摘要见[机器可读记录](phase-verification-f32e4000.json)。

| 检查 | PHP 8.3.33 | PHP 8.4.25 |
| --- | ---: | ---: |
| 安装树全量编译（含生产依赖和归档） | 5,412 文件，0 错误/诊断 | 5,412 文件，0 错误/诊断 |
| 默认回归 | 148 独立进程，0 失败 | 148 独立进程，0 失败 |

默认套件为 unit、models、financial、upload、storage、remote_upload，默认数据库为 SQLite。148 为顶层进程数，未与断言或子进程混算；真实 MySQL 故障及并发证据另列专项。

PHPStan level 1 **409**、level 5 **1,178** 条，均无全局分析错误；PHPCompatibility **0 错误、8 警告**。相对 [691eb9ab](phase-verification-691eb9ab.md)，User 两档各减少 1 条、ContentPurchase level 5 减少 1 条。没有新增 baseline 或忽略规则；静态候选不是漏洞数量。

| 独立提交 | 每个 PHP 版本的专项证据 |
| --- | --- |
| de1d1a7d / a478462e | [购买私有保存点](purchase-caller-savepoints.md)及[公共事务机制](financial-transaction-core.md)，保留各批原始验证结果 |
| 251e851b | [返利及会员](reward-membership-transactions.md)：SQLite 192 / MySQL 195；正式 MySQL 视频/文章/漫画购买 1300 / 1273 / 940 |
| 9fd9e21a | [订单 owner 收尾](order-owner-transactions.md)：SQLite 252 / MySQL 255；六渠道及支付业务回归 |
| f32e4000 | [当前订单及存储](order-authority-storage.md)：SQLite 78 / MySQL 80；真实独立进程并发 20 项、4 个工作进程 |

复跑固定提交后执行 `php tests/php_lint.php --all --json=/tmp/php-installed-lint.json`、`php tests/run_audit.php`、`python3 tools/audit/run.py --output=/tmp/maccms-static-report`，以及 PHPStan `--level=5 --error-format=json --memory-limit=2G`。精确计数要求同一提交及锁文件，并在统计安装树时只挂入生产依赖；工具依赖另挂用于静态扫描。MySQL 参数和专项入口见各报告。

词法清点在当前 application 中发现 74 行直接 Db 事务调用、20 个方法，涉及 Card/Cash/SignLog/SignMilestone/TaskLog/Ulog、User 其它账号或奖励方法，以及 AnalyticsAggregator/DbBackup。它不覆盖其它调用形式，也不等于 74 个漏洞。卡密旧方法另有双版双库共 18 条实际观察：BEGIN 遗留、已提交仍报普通失败、rollback 拒绝导致异常/待提交变更、破坏调用方标记，以及非严格台账截断仍成功。卡密修复尚未计入此快照。

原始证据目录 `/tmp/maccms-audit-20260910/phase-f32e4000/`。继续按[跨模块清单](cross-cutting-followups.md)处理其它资金入口、持久核对、目录并发维护、附件引用、输出边界、共享身份、TP8 导入及未提交的配置/来源整合。本记录不表示全量审计完成或上线验收通过。
