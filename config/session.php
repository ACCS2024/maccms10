<?php
return [
    'type'     => 'file',
    'expire'   => 1440,
    'prefix'   => 'mac_',
    'httponly' => true,
    'secure'   => false,
    'samesite' => 'Lax',
    'domain'   => '',
    // file 驱动用本项作「session 存储目录」，不是 cookie 路径。
    //
    // 必须显式指定一个【跨应用共享】的绝对目录：留空时 TP8 的
    // think\session\driver\File 会回落到 $app->getRuntimePath()，而多应用模式下
    // 该路径是按应用分的 —— 同一个 PHPSESSID 会写成两份互不可见的文件：
    //     runtime/index/session/mac_/sess_xxx   （前台，验证码答案写在这里）
    //     runtime/admin/session/mac_/sess_xxx   （后台，登录时来这里读）
    // 于是后台登录永远读不到验证码，表现为「验证码不管怎么输都是错的」。
    // 后台鉴权态同理无法跨应用保持。
    //
    // 历史坑：此前曾误设为 '/'（当成 cookie 路径），导致会话写入文件系统根目录，
    // 且 GC 从 / 递归扫描整个磁盘 → 间歇 500。所以既不能留空也不能填 '/'。
    // Cookie 的路径由 cookie 配置决定，默认 '/'，与此项无关。
    'path'     => (defined('RUNTIME_PATH') ? RUNTIME_PATH : __DIR__ . '/../runtime/')
                  . 'session' . DIRECTORY_SEPARATOR,
];

