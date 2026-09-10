# cc2d60bf 阶段完整复验

日期：2026-09-11。固定提交 `cc2d60bf`，导出已提交源码并挂载干净、锁定的生产依赖；不包含其后 CSV 文本预检，以及工作区尚未审阅的配置、资源来源和部署改动。精确提交、树、锁文件、工具版本、分类和原始报告摘要见[机器可读记录](phase-verification-cc2d60bf.json)。

| 检查 | PHP 8.3.33 | PHP 8.4.25 |
| --- | ---: | ---: |
| 安装树全量编译（含生产依赖和归档） | 5,424 文件，0 错误/诊断 | 5,424 文件，0 错误/诊断 |
| 默认回归 | 155 独立进程，0 失败 | 155 独立进程，0 失败 |

默认套件为 unit、models、financial、upload、storage、remote_upload，默认数据库为 SQLite。155 为顶层进程数，不与断言或嵌套子进程混算；真实 MySQL、并发及故障注入见各专项记录。

PHPStan level 1 **409**、level 5 **1,182** 条，均无全局分析错误；PHPCompatibility **0 错误、8 警告**。相对 [f32e4000](phase-verification-f32e4000.md)，level 1 不变，level 5 净增 4 条：

- Base 的原导入 getTableFields 提示减少 1 条；新的当前 writer 查询产生 2 条 ConnectionInterface 未声明 query 的提示，需明确所支持的 PDO 连接合同。
- Payment::use_card 增加两条返回值提示，来自原有 `@return JSON` 被解释成不存在的命名空间类，而新增真实返回分支触发检查；需修正方法文档。
- BulkTableIo 减少 1 条 null 比较提示。
- XlsxTableReader 新增两条“值恒为空”推导，延续 XMLReader 回调捕获状态的分析问题。真实非空列、未命名列拒绝、稀疏单元格及 449 项容量回归均已执行；仍保留候选，后续明确回调状态合同，不能用默认空值或忽略规则隐藏问题。

| 独立提交 | 每个 PHP 版本的专项证据 |
| --- | --- |
| 0f652bd4 | [卡密事务收尾](card-owner-transactions.md)：SQLite 80 / MySQL 84 |
| 919b6b4c | [卡密逐字节身份](card-credential-identity.md)：SQLite/MySQL 各 40 |
| 3962133e | [卡密控制器输入](card-controller-ingress.md)：SQLite/MySQL 各 212 |
| bd9f6f80 | [导入行准备](import-row-preparation.md)：Art 191 / 573、Manga 158 / 474，Vod MySQL 507 |
| 7778576e | [CSV/XLSX 源行号](import-source-rows.md)：新增 25 项及原容量检查 |
| ed27ba16 | [导入接收及结果](content-import-ingress.md)：真实 multipart 36 项；Art/Manga 每库各 81，Vod MySQL 85 |
| cc2d60bf | [列映射预检](import-column-mapping.md)：解析 81 项；Art/Manga 每库各 102，Vod MySQL 106 |

完整快照之后另行提交 `b1d1b39a` [CSV 文本预检](import-text-encoding.md)：每版新增解析 78 项、20 MiB 文件峰值 22.00 MiB，Art/Manga 每库各 114、Vod MySQL 118 项。此批有独立编译和相关回归，未混入上表固定快照的全量计数。普通编码问题有双版实际控制器及数据库共 30 条观察；既有乱码数据未自动重写。

当前快照的直接 Db 事务调用词法清点为 **69 行、19 个方法**，较 f32e4000 减少 Card::useData 的 5 行。剩余 Cash、签到/里程碑、任务、Ulog、User 其它账号/奖励方法以及备份/统计仍需根据各自事务所有权复核；数量不是漏洞数，也不覆盖其它形式的调用。

复跑固定提交：`php tests/php_lint.php --all --json=/tmp/php-installed-lint.json`、`php tests/run_audit.php`、`python3 tools/audit/run.py --output=/tmp/maccms-static-report`，以及 PHPStan `--level=5 --error-format=json --memory-limit=2G`。生产依赖和审计工具依赖分别挂载；精确计数要求相同提交及锁文件。原始证据目录 `/tmp/maccms-audit-20260910/phase-cc2d60bf/`。

审计继续进行。全量编译和默认回归通过不代表 409/1,182 条静态候选已处理，更不表示全项目安全审计或上线验收完成。下一步按[跨模块清单](cross-cutting-followups.md)处理资金入口、存储/附件一致性、模型实际落库、输出边界、其它旧导入入口及未提交改动的独立审阅。
