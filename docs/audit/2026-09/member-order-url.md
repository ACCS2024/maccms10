# 会员现金订单支付链接

`API/User::upgrade_order_create()` 的旧实现使用 TP8 不存在的 `think\facade\Url`。改成已有 `url()` 兼容函数后，实际 multi-app URL 生成器仍沿用绑定的 `api.php` 入口，链接会落到 API 用户控制器的错误路径。

现在根据当前入口所在目录，构建明确的 `index.php/user/pay?order_code=...` 前台链接，订单号用 RFC 3986 查询编码。该路径保留子目录部署位置，不依赖伪静态或特定 URL 后缀。

`tests/security_audit_member_order_url.php` 通过共享隔离 fixture 执行真实会员订单创建、实际 Order/Group ORM 和 TP8 Request，核对保存的订单 ID/编号与返回链接。根目录、子目录两种部署路径共 8 项断言，PHP 8.3.33 和 8.4.25 均通过；未运行应用初始化或访问业务数据库。共享 fixture 中只有身份认证为受控替身，URL 兼容函数直接取自当前项目代码。
