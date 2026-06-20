<?php
return [
    'type'     => 'file',
    'expire'   => 1440,
    'prefix'   => 'mac_',
    'httponly' => true,
    'secure'   => false,
    'samesite' => 'Lax',
    'domain'   => '',
    // 注意:file 驱动用本项作「session 存储目录」。此前误设为 '/'(cookie 路径之意),
    // 导致会话写入根目录、且会话 GC 从 / 递归扫描整个文件系统(getMTime //etc/... 失败)
    // → 间歇 500 与会话不持久。置空回落到 runtime/session/。Cookie 路径由 cookie 配置默认 /。
    'path'     => '',
];

