# 全量修复检查点：c5ae4121

日期：2026-09-11。固定源码树 `bba3d811b943ed3b6c8089aefae4b3fc224b76ba`。本检查点对应 `c5ae4121`，后续提交不能借用此版本的完整扫描结果。工作仍在执行，尚未达到全量修复或商业部署验收完成的状态。

| 检查 | PHP 8.3.33 | PHP 8.4.25 |
| --- | --- | --- |
| 全量原生编译，含干净依赖及归档 | 5,479 文件，0 诊断 | 5,479 文件，0 诊断 |
| 默认独立回归 | 182 进程，0 失败 | 182 进程，0 失败 |
| 提现 API 读取，MySQL | 178 项 | 178 项 |
| 提现后台实际路由及归档模板，MySQL | 230 项 | 230 项 |
| 提现写入实际路由，MySQL | 342 项 | 342 项 |
| 提现模型读取及主库路由，MySQL | 56 项 | 56 项 |
| 账本用户名投影，MySQL | 25 项 | 25 项 |

默认回归主要使用 SQLite；表中的 MySQL 专项是同一冻结版本分别执行的真实数据库测试，不将默认回归描述为完整 MySQL 回归。首轮完整回归发现游客提现记录产生了额外用户名查询，已恢复有效用户编号过滤；旧 1,001 条大页测试也按提现每页 100 条的新边界调整，保留普通账本的大页投影验证。最终两版完整回归均通过。

PHPStan 1 级为 **49 条**、5 级为 **686 条**，均无全局分析错误，未加入 baseline/ignoreErrors。相较较早的 798 条，变化包括 PHPDoc 表述校正与实际代码修改，不能当作“修复了 112 个漏洞”。候选仍涉及分支定义、Collection/模型返回合同、动态方法、输入类型、旧比较条件及注释类型；需继续以真实行为归类。

PHPCompatibility 为 **0 错误、1 告警**。告警仍是 `application/extra/mctheme.php` 配置字符串内的混合换行，保留字面文本，不为消除告警修改配置含义。当前源码与同一份干净生产依赖的来源策略检查无命中，生成 **6,428 个文件哈希**；这是已知特征及策略检查，不能证明无未知漏洞。本次没有重复在线依赖公告查询，依赖公告结论仍引用此前有日期的锁文件检查。

原始编译、完整回归、静态诊断、来源报告及文件清单已存入[证据归档](evidence/checkpoint-c5ae4121.tar.gz)，约 399 KiB，内部只含报告。各报告及归档的 SHA-256、分类统计见[结构化记录](full-repair-checkpoint-c5ae4121.json)，不再只依赖执行环境临时文件。运行时镜像、源码树和命令在记录及仓库检查入口中可追溯。主要复跑入口：

```sh
php tests/php_lint.php --all
php tests/run_audit.php
php tools/audit/vendor/bin/phpstan analyse -c tools/audit/phpstan.neon --level=1 --error-format=json --no-progress --memory-limit=2G
php tools/audit/vendor/bin/phpstan analyse -c tools/audit/phpstan.neon --level=5 --error-format=json --no-progress --memory-limit=2G
```

分别使用目标 PHP 版本、干净依赖和隔离环境。可选 MySQL 测试使用专项文档规定的独立测试数据库，不向生产库切换环境变量。

随后 `fc40a808` 完成公共 API/采集授权入口的框架响应，双版各 183 默认进程通过；`81ad7699` 修复目录尾斜杠导致删除符号链接目标的问题，双版各 35 项通过。这些有各自提交及证据，不计入本检查点的静态总数。接下来继续清理结果传播、公共 API DNS/采集输出、历史收款文本、共享缓存、附件与请求期 DDL 等边界，见[持续复审清单](cross-cutting-followups.md)。生产迁移、外部付款核对、部署、恢复演练及原生 Windows/BSD 验证均未执行。
