# 导入源行坐标（I1a 后续）

日期：2026-09-11，基于 bd9f6f80。CSV/XLSX 原先返回过滤空行后的 rows；控制器以数组下标加 2 报错，遇到空行或稀疏 XLSX 即无法对应源表。

三个 BulkTableIo 解析入口和 XlsxTableReader 增加可选 withRowNumbers 参数，默认返回形状完全保持兼容。启用后 row_numbers 与非空数据行逐一对应：CSV 计逻辑记录，包含表头和空记录，多行单元格中的换行不增加记录号；XLSX 保留实际工作表行坐标。空表返回空坐标数组。新导入入口将显式启用该参数。

PHP 8.3.33 / 8.4.25 各通过新增 25 项、原 CSV 3 项、下载往返 40 项、CSV 预算 96 项 / 19 隔离进程、XLSX 普通文本 68 项、XLSX 预算 449 项 / 58 隔离进程，以及全部改动 PHP 编译。新回归覆盖 CR、LF、CRLF、单元格内换行、空行、稀疏工作表、空表和旧返回形状。

持久回归 tests/framework_audit_import_row_numbers.php；验证日志 /tmp/maccms-audit-20260910/import-followups/row-numbers-check1.log。本批只增加定位元数据，上传接收、返回传播和部分成功处理继续列 I1b；不改变重复表头、多余列等尚待处理合同。
