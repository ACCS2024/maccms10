<?php
return [
    \think\app\MultiApp::class,
    // TP8 会话初始化:加载/保存 session 并下发 cookie。缺失会导致 session('admin_auth') 等
    // 写入后不被持久化(登录无法保持)、且 request->session 为 null(token 校验失效)。
    \think\middleware\SessionInit::class,
    // \app\middleware\SessionSameSite 已删除:它调的是 session_set_cookie_params(),
    // 只对 PHP 原生 session 有效,而 TP8 全程不调 session_start()(全仓 grep 为 0),
    // 是彻底的死代码。会话 cookie 的 SameSite/HttpOnly 由 config/cookie.php 决定。
    \app\middleware\AppInit::class,
    \app\middleware\RequestSecurity::class,
    \app\middleware\Begin::class,
    \app\middleware\CsrfGuard::class,
    \app\middleware\AntiScrape::class,
    \app\middleware\SecurityHeaders::class,
    \app\middleware\AdminAudit::class,
];
