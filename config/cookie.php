<?php
// +----------------------------------------------------------------------
// | Cookie 设置
// +----------------------------------------------------------------------
//
// 这个文件在 TP8 迁移时【整个丢了】。没有它,think\Cookie 用包内默认值
// (vendor/topthink/framework/src/think/Cookie.php:38-40 httponly=false、samesite='')
// 于是全站每一个 cookie 都不带 HttpOnly、不带 SameSite —— 实测:
//     Set-Cookie: PHPSESSID=...; expires=...; Max-Age=1440; path=/
// 而 PHPSESSID 正是后台登录态(admin/Base.php 的 checkLogin 依赖它)。
// TP5 时代这两项是有的:application/config.php 的 cookie.httponly=true,
// 以及 session 段的 httponly/samesite 经 ini_set 作用于原生 session。
//
// 注意 config/session.php 里的 httponly / secure / samesite 三个键是【说明性的】:
// TP8 的 Session 组件从不读它们(只读 type/name/serialize/var_session_id + 驱动的
// path/expire/prefix),会话 cookie 由 SessionInit.php:62 经 think\Cookie 下发,
// 因此真正决定它属性的就是本文件。改 session.php 不会有任何效果。
//
// —— secure 为什么是动态的 ——
// 写死 true 会让任何一次 HTTP 访问彻底收不到 cookie(登录不上、验证码永远错);
// 写死 false 又白白丢掉 HTTPS 上的保护。所以按当前请求判定,与
// application/middleware/AppInit.php 里 $GLOBALS['http_type'] 的判定口径一致
// (含反代场景的 X-Forwarded-Proto)。
$_https = (($_SERVER['HTTPS'] ?? '') === 'on')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
    || ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443);

return [
    // 0 = 浏览器会话 cookie。保持包内默认值,不要改:
    // 会员登录态那几个 cookie 自己传了 ['expire'=>2592000],
    // 会话 cookie 由 SessionInit 显式传 session.expire,都不受这里影响;
    // 这里一旦给非 0 值,所有没显式指定过期的 cookie 生命周期都会跟着变。
    'expire'   => 0,
    'path'     => '/',
    'domain'   => '',
    'secure'   => $_https,
    // 默认禁止 JS 读取。少数确实要给前端主题读的展示型 cookie(user_id / user_name)
    // 在写入处单独 ['httponly' => false];真正的登录令牌 user_check 保持 HttpOnly。
    'httponly' => true,
    // Lax:同站请求与顶层 GET 导航照常携带,跨站 POST 不带 —— 与 TP5 一致。
    'samesite' => 'Lax',
];
