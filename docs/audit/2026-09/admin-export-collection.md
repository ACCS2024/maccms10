# 后台导出的 Collection 兼容修复

更严格的 PHPStan level 5 扫描在 `admin/Base::base_export()` 找到 Collection 与数组合同不匹配。双 PHP 实际调用确认：CSV 和 XLSX 都在下载函数入口抛出 `TypeError`，包括空结果。此前 CSV 单元测试直接传入数组，未覆盖控制器的真实 ORM 返回值。

本批只在有行数上限的查询后调用 `select()->toArray()`。继续使用原表字段、筛选条件、主键倒序、默认 5000 行及最高 10000 行；导出器的数组合同、下载后退出行为不变。

新增 `tests/framework_audit_bulk_export.php` 使用实际后台方法、SQLite ORM 和两个真实导出器，每个下载运行在独立进程。CSV 由原生 CSV 解析器读取，XLSX 由 ZIP/DOM 独立读取工作表；没有用待测导入器验证自身输出。覆盖正常、空结果、筛选、显式数量、零值数量、超过最大数量、中文/emoji、引号/换行/反斜线、XML 字符、空值和文本零。

PHP 8.3.33 / 8.4.25 各 **86** 项通过。修复前两个格式在两个版本均复现相同类型错误。既有 CSV 回归 **3** 项继续通过。此批不扩展导出字段、不变更授权流程；CSV 公式单元格策略、XLSX 大单元格资源预算和导入事务仍需要各自的审计证据。

扫描说明：本次 level 5 针对已记录的 `cdc213f` 快照运行，得到 1173 条文件诊断、0 条工具全局错误；这是候选数，不是漏洞数，没有修改仓库的 level 1 配置或添加忽略。另两项候选经实际依赖验证为误报：`session(null)` 被 helper 支持；`View::exists()` 可由 Manager 转发到模板驱动。完整扫描基线和快照范围见[阶段验证记录](phase-verification-cdc213f.md)。
