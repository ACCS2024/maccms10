# 691eb9ab 阶段完整复验

日期：2026-09-11。固定提交 `691eb9ab`，独立导出已提交源码并挂载干净、锁定的生产依赖。工作区的其它配置、资源来源、部署及后续金融事务修改均不属于此快照。来源、锁文件、工具版本和原始报告摘要见[机器可读记录](phase-verification-691eb9ab.json)。

| 检查 | PHP 8.3.33 | PHP 8.4.25 |
| --- | ---: | ---: |
| 安装树全量编译（含生产依赖和归档） | 5,400 文件，0 错误/诊断 | 5,400 文件，0 错误/诊断 |
| 默认回归 | 144 独立进程，0 失败 | 144 独立进程，0 失败 |

默认套件为 unit、models、financial、upload、storage、remote_upload，默认数据库为 SQLite。144 是顶层进程数，不与断言数或子进程数混算；预期故障日志保留，运行器的失败退出状态不被忽略。

PHPStan level 1 **410** 条、level 5 **1,180** 条，均无全局分析错误；PHPCompatibility **0 错误、8 警告**。未增加 baseline 或忽略规则。相对 [fc8c07ce](phase-verification-fc8c07ce.md)，Vod 模型两档均减少 11 条诊断，新目录工具增加一条 SQL Query 子类的推导候选；数字不是漏洞计数。

| 分批提交 | 本轮专项证据（每个 PHP 版本） |
| --- | --- |
| 331608b3 | [视频保存输入](vod-save-input.md)：148 规范化项、438 真实 MySQL 三模式项，组合容量峰值 93.04 MiB |
| 78ddcf4f / e8776f8d | [普通重名目录](vod-repeat-normal-saves.md)及[维护故障隔离](vod-repeat-maintenance-faults.md)：当前普通目录 120 项、真实故障与后台响应 162 项，三种 MySQL 模式 |
| 691eb9ab | [八个正文编辑框](editor-textarea-boundary.md)：89 个普通数据用例、269 项实际 Chromium 检查；8 MiB 全引号文章峰值 108.01 MiB；购买模板 49 项 |

目录故障测试通过独立 PDO 核对调用方的实际回滚，检查原表附加列和拒写触发器留存。编辑框浏览器关闭页面脚本并阻断请求，未执行脚本载荷。容量数字是各自夹具的观测，不能扩展为完整页面或整站并发保证。

复跑入口：

```sh
composer install --no-dev --no-plugins --no-scripts --no-interaction
php tests/php_lint.php --all --json=/tmp/php-installed-lint.json
php tests/run_audit.php
python3 tests/run_vod_save_audit.py <php83-image> <php84-image>
npm ci --prefix tests/browser --ignore-scripts --no-audit --no-fund
CHROMIUM_BINARY=/usr/bin/chromium PHP_BINARY=php node tests/browser/editor_textarea.cjs
composer --working-dir=tools/audit install --no-plugins --no-scripts --no-interaction
python3 tools/audit/run.py --output=/tmp/maccms-static-report
php tools/audit/vendor/bin/phpstan analyse -c tools/audit/phpstan.neon --level=5 --no-progress --error-format=json --memory-limit=2G
```

精确计数应检出所标提交、使用所标 PHP，并在挂入静态工具依赖前统计生产安装树。原始证据目录为 `/tmp/maccms-audit-20260910/phase-691eb9ab/`；首次静态启动因只读挂载缺少缓存挂载点失败，补齐隔离目录后重跑完成，旧失败记录保留，没有据空报告宣称通过。

[跨模块清单](cross-cutting-followups.md)继续追踪调用方 SAVEPOINT、独立返利和 StorageIntent 收尾、目录原子/并发重建、AI/附件绑定删除、其它输出上下文、共享身份/公开查询、TP8 导入接收，以及未提交的配置和资源来源整合。此记录不表示全量审计完成或商业上线验收通过。
