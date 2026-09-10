# Type 导航与子分类（2026-09-10）

Type::get_nav_types 把真实 ORM Collection 强制转为 `(array)` 再提取 type_id，得到的不是记录行，导致批量子分类查询遗漏。随后对 Collection 的引用 foreach 修改迭代数据，不能保证写回 Collection 原始记录，因此返回值仍缺少补充字段。get_type_with_children 的子分类循环有相同问题。控制器的多处 `Db::table('mac_type')` 还绕过了配置的表前缀。

修复使需要按引用丰富字段的查询结果先 `toArray()`，导航父 ID 从真实行数组提取；Type 控制器所有直接分类查询统一使用 `Db::name('Type')`，包括原有分类树与基本分类列表。父子排序、扩展 JSON 与 link_flag 的 type/show 行为保留。

导航动作及指定父分类动作使用真实 Type 验证器。导航的 ids 接受原有整数或逗号分隔数字字符串；num/mid/parent 采用明确数值规则；link_flag 保留未知字符串回退 type 的行为。数组参数在 trim/int 转换前返回 code=1001，避免 TypeError/Warning。指定父分类仍要求 type_id，缺失记录仍返回 code=1002。

`tests/framework_audit_type_navigation.php` 用非默认 audit_nav_ 前缀、两个父分类及三个子分类，测试实际 Controller/Request/Validator/ORM。PHP 8.3.33 与 8.4.25 的 SQLite、MySQL 各 34 项通过：排序与子分类归属、扩展信息、ids/mid/parent/num、type/show 链接、空结果、不存在父级、恶意数组、既有分类树和基本分类列表。MySQL 固定只用专用 maccms_audit_http 数据库的 audit_nav_type 表，结束后删除该测试表；SQLite 另有 mac_type 诱饵表验证不会误读默认前缀。恢复旧查询/Collection实现的负控明确失败。

完整严格模式 HTTP fixture 两版均通过导航与指定父级的非空 children 断言，以及 ids[] / link_flag[] 返回受控 code=1001 的反例。
