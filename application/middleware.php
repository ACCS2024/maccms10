<?php
return [
    \think\app\MultiApp::class,
    // TP8 会话初始化:加载/保存 session 并下发 cookie。缺失会导致 session('admin_auth') 等
    // 写入后不被持久化(登录无法保持)、且 request->session 为 null(token 校验失效)。
    \think\middleware\SessionInit::class,
    \app\middleware\SessionSameSite::class,
    \app\middleware\AppInit::class,
    \app\middleware\RequestSecurity::class,
    \app\middleware\Begin::class,
    \app\middleware\CsrfGuard::class,
    \app\middleware\AntiScrape::class,
    \app\middleware\SecurityHeaders::class,
    \app\middleware\AdminAudit::class,
];
