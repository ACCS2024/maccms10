# 会员中心只读列表（2026-09-10）

真实 Request 调用中，ajax_ulog 不传 ac 时先报未定义数组键；plays、downs、favs、ulog、plog、cash 的 GET、reward、orders、cards、invite 不传 page/limit 时同样在 PHP 8 严格模式中止。mid/type/filter/level 还有下一层缺省字段问题。

本批只修这些读取路径的缺省值，保留原来的页码下限、每页数量下限/缺省值和过滤语义：一般页面默认 20，ajax_ulog 默认 10，invite 仍允许显式 limit=1。没有调整收藏/记录删除、充值、支付、提现 POST 等写操作。

登录 HTTP 验证继续发现：页面最后 assign('param', $param) 覆盖 All::label_maccms 已准备的公共参数，默认主题 public/head 读取 param.wd 又产生 500。只读页面输出参数因此合并 mac_param_url() 公共参数后再覆盖页面归一化值，保留公共头部字段与当前分页/筛选值。

验证：

- `tests/framework_audit_user_lists.php` 使用实际 Request、控制器及 Ulog/Plog/Cash/Order/Card/User ORM，内存 SQLite 中有两名独立用户、25 条本人积分记录、另一人的记录、收藏/播放/下载及两层邀请关系。仅隔离模板渲染、内容展示信息和分页 URL 表现。修复前同时复现 11 个缺键异常并退出 1；修复后 PHP 8.3.33 / 8.4.25 各 43 项通过，覆盖默认模板字段、实际分页、过滤、跨用户隔离、奖励敏感字段剔除与邀请层级。
- 专用 MySQL HTTP fixture 临时创建 user_id=91010001，使用真实 Cookie 登录，并在每次请求结束核对实际已登录用户 ID。两版各 10 条真实 HTTP 通过：plays/downs/favs/plog/cash/reward/orders/cards/invite 以各自页面标题确认渲染；ajax_ulog 以 JSON code=1 确认。临时账号与调试文件在验证后删除，未更改生产数据。

单独待处理：默认主题没有 `template/default/html/user/ulog.html`。该动作参数/查询已通过单测，但真实 HTTP 仍因 TemplateNotFoundException 返回 500；本批未创建新页面或把它改向其他业务页面。ulog_del/plog_del/cash_del 的旧 where 写法也未混入只读修复。
