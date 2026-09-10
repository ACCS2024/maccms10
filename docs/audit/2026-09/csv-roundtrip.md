# CSV 导出与导入的反斜线保真

日期：2026-09-10。范围为 `BulkTableIo` 的 CSV 编码合同，不包含整个批量导入安全验收。

实际下载再导入时，名称或备注以反斜线结尾，会把下一条记录并入当前单元格。双 PHP 普通数据复现中，7 条记录只剩 5 条；Windows 路径 `C:\`、带空格的目录和单独反斜线均可触发。此前仅测试路径中间的反斜线，因此正常导出回归没有覆盖这个边界。

读取与写入现在都显式使用空 `escape`：引号按 CSV 双写规则处理，反斜线保持普通字符。保留 BOM、字段顺序、空字符串、零值、中文、引号和单元格换行。PHP 官方明确建议此设置，因为非空转义字符可能产生无法往返的 CSV；同时避免依赖 PHP 8.4 已弃用的默认参数。[PHP fgetcsv 手册](https://www.php.net/manual/en/function.fgetcsv.php)、[PHP fputcsv 手册](https://www.php.net/manual/en/function.fputcsv.php)。

`tests/framework_audit_csv_roundtrip.php` 通过真实下载子进程和真实导入方法验证尾部反斜线、连续反斜线与引号组合、多行单元格、独立提供的标准 CSV。另运行既有 `framework_audit_csv.php` 和实际后台 CSV/XLSX 下载回归。测试不启动电子表格应用，也不执行公式。

旧导出若已把内容编码成歧义文本，不能可靠推断原值，应从源数据重新导出。CSV 公式单元格策略、批量导入的上传 API 兼容性、解析前行数/字节预算及 XLSX 解压/XML 预算仍需独立修复。本批不会把格式保真等同于这些边界已解决。
