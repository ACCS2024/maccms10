# 当前代码审计与分批修复

目标：PHP 8.3 为兼容下限，PHP 8.4 为主要运行版本；覆盖安全、兼容性、数据一致性、异常处理和部署可验证性。以当前代码为对象，不遍历 Git 历史。

## 提交约定

- 每个提交围绕一个根因或一组必须同时落地的依赖变更，包含相应回归验证。
- 独立问题分别提交；内嵌依赖升级单独提交，保留锁文件和来源信息。
- 交叉文件按修改块暂存；验证暂存内容构成的版本，避免借用尚未提交的修复获得假通过。
- 每批提交后继续审计和扩查。提交表示该批修改可审阅，不表示全项目审计完成。
- 清理时已处理原先的换行差异，`migration/lbjx9/index.php` 当前与已提交版本一致；没有待合并的用户修改。
- 不执行部署，不访问生产数据库。动态验证使用独立副本、容器网络及测试数据库。

## 基线与证据

初始工作区盘点 3,773 个文件，包含 1,096 个 PHP 类文件（依赖、归档和运行目录也计入）。初始编译检查在 PHP 8.3.33 检出 10 个带诊断的文件，在 PHP 8.4.25 检出 44 个；该计数包含旧框架与第三方代码，不等同于业务漏洞数。

`tests/php_lint.php` 默认检查维护中的源码，并记录排除项；`--all` 包含依赖、归档、上传和运行目录。该工具只编译文件，不加载应用，不加载 php.ini；解析失败、弃用诊断、无法完成的检查及空扫描均以非零状态结束。

阶段原始证据暂存于执行环境 `/tmp/maccms-audit-20260910/`。后续报告应记录复现命令、目标版本、覆盖范围和未验证项；临时路径不是持久化审计档案，最终需要整理可复现的报告和检查配置。

状态：执行中。不得据局部回归通过宣称全量审计完成或生产已安全。

当前运行回归推进到 `a22b2cfd`：PHP 8.3/8.4 各 188 个完整默认进程通过，后台缓存实际路由在 SQLite/MySQL 各 63 项通过，见[后台清理](admin-cache-results.md)。同源静态分析已修正多入口覆盖，未抑制的 level 1 / 5 为 49 / 610，见[对照与归档](static-entrypoint-coverage.md)。下方 c5ae4121 仍是最近一次全项目编译和来源扫描的固定检查点。

阶段分类入口：[框架与运行边界](framework.md)、[安全与账务](security.md)、[静态候选](static-candidate-triage.md)、[跨模块复审](cross-cutting-followups.md)。后续专项报告分别记录对应提交范围与验证限制；以每个提交的测试快照为准。

最新固定扫描为 [`c5ae4121` 检查点](full-repair-checkpoint-c5ae4121.md)：双版本各 5,479 文件全量编译、182 默认回归进程，以及未抑制静态扫描；原始证据已压缩归档进仓库。此前记录见 [`2420aa98`](full-repair-checkpoint-2420aa98.md)。随后公共 API 入口 `fc40a808` 双版各 183 默认进程通过，目录清理 `81ad7699` 双版各 35 项通过，分别见[API 入口](api-access-gates.md)和[目录边界](directory-cleanup-boundary.md)。完整 MySQL 分组基线为 [4a7f90c7 刷新记录](full-repair-baseline-20260911.md)；前端、配置和部署清理见[分批清理记录](workspace-cleanup-20260911.md)。随后封面迁移和事务已独立提交，见[封面报告](ai-cover-transactions.md)。较早固定快照：[cc2d60bf 阶段完整复验](phase-verification-cc2d60bf.md)，含双版本 5,424 文件编译、各 155 默认回归进程，以及未抑制的 level 1 / level 5 静态分类。其后 CSV 文本预检独立提交和验证。较早记录见 [f32e4000](phase-verification-f32e4000.md)、[691eb9ab](phase-verification-691eb9ab.md)、[fc8c07ce](phase-verification-fc8c07ce.md)、[91486040](phase-verification-91486040.md)、[52f70b90](phase-verification-52f70b90.md)、[cdc213f](phase-verification-cdc213f.md) 与 [1a36cb4](phase-verification-1a36cb4.md)。
