# API 内容列表 Collection 兼容

本组仅将五个控制器中八个需要修改结果行的查询改为 `select()->toArray()`，恢复图片、链接、时间、专题推荐标记和角色关联视频标题，并使文章/漫画最新列表符合公共辅助函数的数组类型要求。不改变表前缀、权限、筛选、分页、排序或积分规则。

## 根因

TP8 `Db::select()` 返回 `think\Collection`；其 `getIterator()` 创建包含项目数组副本的 `ArrayIterator`。控制器直接按引用遍历 Collection 时，对行的修改发生在迭代器中，最终 JSON 序列化原 Collection，导致加工结果丢失。

`Art::get_latest` 和 `Manga::get_latest` 还把该 Collection 传给 `mac_append_type_is_vip_exclusive_for_rows(array &$list)`，合法和空结果请求都抛 TypeError。必须在修改结果或调用辅助函数前取得数组，而不是放宽公共函数的类型或在测试中替换成无类型函数。

| 控制器 | 动作 | 恢复行为 |
| --- | --- | --- |
| Actor | get_recommend | 图片、详情链接 |
| Art | get_hot / get_latest | 图片、详情链接、日期；最新列表 VIP 标记和完整 JSON |
| Manga | get_hot / get_latest | 图片、详情链接、日期；最新列表 VIP 标记和完整 JSON |
| Topic | get_recommend 默认分支 | 图片、详情链接、topic_empty=0 |
| Role | get_list / get_recommend | 图片、详情链接；列表关联 vod_name |

Topic 指定 ID 分支已经构造数组，本组保持其顺序和占位合同。Vod 的四个首页方法先前已修复，不重复修改。

## 回归

```sh
python3 tests/run_api_prefix_audit.py
```

沿用一次性、无网络 MySQL runner 和真实 Request/控制器/ORM，直接解析实际 Json 响应。扩展前缀组回归，取消对两个最新列表已知 TypeError 的捕获，强制所有动作完整成功；保持辅助函数 `array &` 签名，断言图片、链接、日期、VIP 标记、专题推荐标记和角色关联标题，覆盖正常/空分页及有/无默认 mac_* 表。

修复前新增断言在真实 PHP 8.3/MySQL 下失败：`actor list keeps picture transformation in serialized JSON`。修复后 PHP 8.3.33 / MySQL 与 PHP 8.4.25 / MySQL 均通过 400 项检查，所有内容列表完整序列化成功。前缀组曾允许观察既有最新列表故障，现在不再允许；测试失败应直接中止。

## 范围限制

本组只处理 Collection 返回类型和行加工。公开内容授权、密码及嵌套资源地址泄露、严格参数、旧时间条件、查询成本和缓存命名空间均仍需独立修复，见 [访问控制计划](api-content-access-plan.md)。本报告不声称这些风险已解决。
