# XLSX 共享字符串与富文本兼容

日期：2026-09-10。此批仅修复 `BulkTableIo` 对普通工作表文本的读取合同。

真实 ZipArchive/SimpleXML 复现表明：共享字符串根节点注册的 XPath 前缀不会自动成为每个子节点的查询前缀。旧代码逐条查询 `si` 时产生 Undefined namespace prefix 警告，表头和数据变为空。显式 XML 前缀的合法文档还会因 `if (!$sx)` 的 SimpleXML 布尔转换被误判为解析失败。内联富文本只读直接 `t` 子节点时则会漏掉 `r/t` 中的文本。

修复在执行字符串查询的实际节点注册命名空间；XML 解析成功用严格的 `!== false` 判断。共享字符串和内联字符串使用同一正文提取函数，按文档顺序读取直接 `t` 或 `r/t`，保留 Unicode、空白、换行和零值。`rPh` 注音是独立结构，不能追加进导入正文。Open XML 文档分别定义简单文本、富文本片段和注音片段。[SharedStringItem](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.spreadsheet.sharedstringitem?view=openxml-3.0.1)、[InlineString](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.spreadsheet.inlinestring?view=openxml-3.0.1)

`tests/framework_audit_xlsx_text.php` 构造 12 种普通工作表组合：共享、内联或混合存储，简单文本或富文本，默认命名空间或显式前缀。每版 68 项断言，核对真实压缩文件解析后的表头、文本顺序、重复引用、数值/布尔零、缺失单元格和注音分离；E_ALL 下不产生诊断。另运行现有 CSV 普通与往返检查及实际后台 CSV/XLSX 导出 86 项。

XLSX 的 ZIP 解压、XML 节点、字符串、单元格和行列坐标仍缺少预算。原坐标函数可把极长列名计算为浮点数、把极长行号截成 PHP 整数上限；该静态路径及独立坐标调用已记录，未执行其可能无界的展开循环。该问题必须单独收口。

此批也未升级后台的 TP5 上传对象调用，未改变表头重复/额外列语义、公式策略、工作表选择或逐行数据库保存合同；不能因这些普通文本回归通过认定 XLSX 导入已完成商业部署验收。
