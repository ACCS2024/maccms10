<?php
return [
    \think\app\MultiApp::class,
    \app\middleware\SessionSameSite::class,
    \app\middleware\AppInit::class,
    \app\middleware\RequestSecurity::class,
    \app\middleware\Begin::class,
    \app\middleware\CsrfGuard::class,
    \app\middleware\AntiScrape::class,
    \app\middleware\SecurityHeaders::class,
    \app\middleware\AdminAudit::class,
];
