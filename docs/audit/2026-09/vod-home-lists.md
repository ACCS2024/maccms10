# 首页视频列表的 TP8 行结果与表前缀

修复 API `get_banner`、`get_hot`、`get_latest_by_type`、`get_rank` 四个首页列表：ORM `select()` 返回 Collection，而逐行修改和 `mac_append_type_is_vip_exclusive_for_rows(array &$list)` 需要数组。四处查询现在明确转为数组，确保封面、链接、时间、排名和分类标记进入最终JSON。列表及最新内容当日计数统一使用连接中配置的表前缀，停止固定查询 `mac_vod`。

`tests/framework_audit_vod_home.php` 通过真实 ORM、Request 与 API 控制器验证非空/空列表、隐藏行排除、分页、分类父子筛选、当日计数、当前用户收藏和序列化后的变更；仅URL和分类辅助服务为明确fixture，并保留真实数组引用参数契约。专用 `audit_home_*` 表不加载站点配置。

本组不代表四个接口的全部参数边界或整个Vod控制器已审计完成。其他固定表前缀、参数结构/额度、收藏内容类型和回收状态过滤继续独立扩查。
