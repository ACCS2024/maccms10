# 导入实际连接合同

日期：2026-09-11，跟进 cc2d60bf 完整静态扫描；当前行为基于 b1d1b39a 的文本预检。

Query::getConnection 声明返回 ConnectionInterface，其接口本身没有 query 方法。导入元数据只支持 PDO MySQL/SQLite，因此在使用实际连接前加入 PDOConnection 检查；其它连接在任何行保存前返回受控存储错误。没有扩大支持数据库范围，没有新增忽略规则，也没有改变默认连接配置。

两版 PHP 8.3.33 / 8.4.25 各完成改动文件编译、实际 Art 导入 SQLite/MySQL 各 114 项，前置普通保存 191 SQLite / 三模式 MySQL 573 项。PHPStan level 5 定向扫描 Base 从原 8 条降为 6 条，新增的两处 ConnectionInterface::query 提示已消除；原导出查询和入口常量推导另行保留。这是定向复验，不重写 cc2d60bf 的冻结全量计数。

首次 pdo-check1.log 在 MySQL 回归阶段遇到执行环境根磁盘耗尽，已主动停止该测试，不记为通过。仅删除已完成扫描的可重建 PHPStan 缓存，并在无副本的隔离 MySQL 8.0.46 审计实例中清理当前文件以前的旧 binlog，保留当前日志、表、源码和原始证据；回收约 3 GiB。随后 pdo-check2.log 从重新建立的专用测试表完整通过，静态结果为 pdo-static.json。具体环境处置记录 infra-space-recovery.json，均位于 /tmp/maccms-audit-20260910/import-followups/。
