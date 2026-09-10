# API 列表可选参数（2026-09-10）

Gbook、Link、User、Website 的列表只有数据库存在记录时才进入排序分支，该分支直接读取可选 `orderby`。PHP 8 严格错误模式下，不传排序参数的正常请求因此 500；空表测试无法发现。Manga 列表在查询前直接读取可选 page，同样报未定义数组键。

四个列表排序分支改为 `!empty($param['orderby'])`，继续使用原来的默认时间倒序；Manga 采用缺省 page=1，再按原语义保留下限。校验规则、分页上限、已传入排序键和模型查询行为不变。

`tests/framework_audit_api_defaults.php` 使用真实 Validator/Request/Controller，给四种真实 SQLite 表各放入两条时间顺序与 ID 顺序不同的记录。修复前同时复现四处 orderby 与一处 page 异常并退出 1；修复后 PHP 8.3.33、8.4.25 各 21 项通过，覆盖缺省、空字符串、显式排序及 Manga 第 1/3 页。Manga 的大量阅读模型逻辑在单测中隔离，仅记录实际传入页码；严格模式 MySQL HTTP fixture 中五种默认列表均返回成功 JSON。
