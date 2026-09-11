# 构造函数提前响应与框架收尾

关闭留言/评论、游客跳转、安装入口/安装锁、后台本地完整性校验和自定义 Label 页面，统一以 HttpResponseException 携带 Response 结束分发，保留既有正文、302 跳转和安装 403 状态。取消构造函数中的 echo/send/exit，让框架异常处理返回响应，外层中间件可以继续设置会话和安全响应头，调用方 finally 可以执行。

Label 文件参数在任何字符串/文件操作前检查原始类型、长度、控制字符和路径分隔符。校验失败显式抛出错误响应，解决 AJAX error() 返回 JSON 时被构造函数忽略的问题。正常 Label 渲染和空 action 也明确结束分发。

`framework_audit_constructor_response.php` 使用真实控制器构造函数、共同 All 的 error/assign、ORM User logout、ThinkPHP Middleware/Pipeline/Response/SessionInit 及实际 SecurityHeaders。仅前台站点身份引导与模板展示使用夹具；另有独立未绑定安装入口进程。验证正常/关闭模块、游客跳转、Label 普通渲染与错误、安装锁和后台完整性守卫，以及动作停止、无直接输出、finally、Cookie、CSP、nosniff 与 private/no-store。Unexpected exceptions 直接抛回测试，避免错误页掩盖测试失败。

本批没有声称所有 exit 已消除：前台 Base 的站点/地区/验证码检查、All 的页面缓存与资源权限路径、采集进度输出仍需按各自合同处理；构造中抛异常也不会使未构造成功的对象执行析构。部署入口与 Web 服务器行为继续由既有入口/服务器回归负责。
