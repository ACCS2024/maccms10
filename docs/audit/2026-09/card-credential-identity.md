# 卡密凭据与数据库排序规则（F3b）

日期：2026-09-11。固定源 `f32e4000`、PHP 8.3.33 / 8.4.25 各运行 SQLite 和安装 MySQL 7 个普通凭据用例。SQLite 只接受原值；MySQL 的安装排序规则将密码 `fixture` 与 `FIXTURE`、`fixturé`、`fixture ` 都匹配为同一卡，卡号的大小写、重音及尾部空格变体也均兑换成功。这是模型依赖 SQL 文本等价规则作为凭据相等判断的实际差异。

Card::useData 在锁定唯一候选后、认领或入账前，对卡号及密码分别使用 hash_equals 核对存储原字节。不同凭据统一返回原 not_found 错误并结束只读事务。仍保留重复候选拒绝，不因新增精确核对而从歧义卡片中任意挑选。没有改库排序规则或重写已有卡密。

两版 PHP 各通过：普通兑换及新增字面凭据合同 SQLite/MySQL 各 40 项；原 owner/实际落库 SQLite 80、MySQL 84 项。新增检查覆盖六种不同字面值拒绝、实际事务结束，以及数据库确实存有的大写、UTF-8 和尾部空格凭据的正确兑换。

测试入口 `tests/security_audit_card_credit.php`；固定源观察为 `/tmp/maccms-audit-20260910/card-followups/credentials-{sqlite,mysql}-{83,84}.log`，修复记录 `credentials-check1.log` 及验证树文件。模型对字面值的正确处理不代表控制器传输已闭环：API 和前台仍有 trim/第二次 URL 解码/HTML 编码，数组参数也需单独验证；输入接收另列 F3c。
