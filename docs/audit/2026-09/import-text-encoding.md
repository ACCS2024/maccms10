# CSV 文本预检（I1d）

日期：2026-09-11，固定问题源 `cc2d60bf`，由完整隔离导出 `/home/dev/phase-audit-cc2d60bf` 运行实际 Art 导入动作、Token、解析器及模型。每个 PHP 版本分别观察 SQLite 5 项、MySQL 非严格/严格模式各 5 项，共 30 项双版普通数据观察。

合法 UTF-8 中文正文在三个环境中一致保存。GBK 和非法 UTF-8 字节在 SQLite 中原样进入文本列；MySQL 的 GBK 样例在首行已保存后失败，非法 UTF-8 样例则返回成功但存储字节改变。NULL 和其它不支持的控制字符在两种数据库均被保存链删除，仍返回成功。上述是实际字节及响应观察，不把所有差异归因于数据库某一具体内部机制。

BulkTableIo 现在在取得最多 20 MiB 的固定原始字节后、解析任何 CSV 行之前，验证整文件为 UTF-8，并拒绝 C0 中除 TAB、LF、CR 外的控制字符。任一后续行包含非法文本都会使整份文件在任何保存前失败。允许可选的开头 UTF-8 BOM、正文中的字面 BOM、正常中文、Emoji 和 CSV 引号中的换行/制表符。不猜测 GBK/UTF-16 等编码并静默转码。XLSX 继续沿用既有 XML 编码和容量验证，本批未改变其编码规则。

专用 ImportTextException 经实际控制器转换为 invalid_text；九种语言明确要求 UTF-8 CSV/TXT 或 XLSX。响应不回显原始文本。TXT 在此入口指使用逗号分隔、与 CSV 同合同的文本；其它类型的 TXT 配置导入仍是独立范围。

PHP 8.3.33 / 8.4.25 各通过：15 个改动 PHP 文件编译；新增文本预检 78 项，含完整 20 MiB 文件末尾非法字节，峰值 22.00 MiB；列映射 81、源行 25、CSV 读写 3、下载往返 40、预算 94 项 / 19 隔离进程、真实 multipart 36 项。实际 Art/Manga 导入各 114 项，分别在 SQLite 和安装 MySQL；Vod MySQL 118 项。前置模型回归继续为 Art 191 / 573、Manga 158 / 474、Vod 507 项。新增实际控制器断言确认有效前缀行尚未保存，未进入模型保存路径。

持续检查 `tests/framework_audit_import_text.php` 及 `tests/framework_audit_content_import.php`。原始 `encoding-proof.php`、生成/执行脚本、`encoding-proof-{83,84}-{False,True}.log`、`text-check1.log` 与验证树位于 `/tmp/maccms-audit-20260910/import-followups/`；False/True 分别指 SQLite/MySQL。原始来源、树和锁摘要可由阶段 cc2d60bf 记录复核。

剩余：合法 UTF-8 内容也可能违反具体数据库列宽、业务含义或历史数据合同，仍需针对字段落库验证。其它保存入口尚无全局文本合同，本批不表示整个数据库的文本/字符集问题已解决；既有乱码记录不自动重写。公式及缓存值、XLSX 导出、模型零影响行、行原子性和持久核对继续单独处理。
