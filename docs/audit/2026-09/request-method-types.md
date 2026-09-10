# 请求方法类型边界

已安装 TP8 的 Request::method() 直接对 POST `_method` 调用 strtolower。表单数组或 JSON 非字符串会在控制器参数校验之前触发 PHP 8 TypeError，导致普通坏请求成为 500。

应用 Request 子类在框架字符串处理前验证方法字段类型。通过 application/provider.php 绑定 think\Request，保留 request 服务、Facade、控制器类型注入使用同一个实例；MacApp 无 app 符号链接的部署也会加载该绑定。合法原始方法、表单/头部方法覆盖及原有参数合并语义均沿用当前框架。

无效类型直接返回 HTTP 400、JSON 通用错误和 private/no-store。使用 HttpResponseException，防止全局异常页再次解析坏方法而递归失败。未修改 vendor。

回归使用真实容器、路由和全局异常处理器，先复现原框架 TypeError，再验证合法方法、注入实例、覆盖语义和无效请求不会执行 action。购买接口另外要求原始与有效方法都是 POST，不能利用合法方法覆盖把 GET 变成扣费请求。
