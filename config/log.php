<?php
return [
    'default'  => 'file',
    'channels' => [
        'file' => [
            'type'           => 'file',
            'path'           => '',
            'single'         => false,
            'apart_level'    => ['error', 'sql'],
            // 白名单。不声明 level 时 think\log\Channel:69 视为「全放行」,
            // 连框架自己的 sql/info/debug 都落盘。这里只留本仓库真正会写的等级:
            //   error   —— ExceptionHandle 与 11 处 Log::error
            //   warning —— 1 处
            //   notice  —— MacApp 的非致命 PHP 诊断降级、AiSearch 的 Log::record(...,'notice')
            //   log     —— Upload.php:107 的 Log::write(..., 'log')
            //   critical/alert/emergency —— PSR 级别,兜底不丢
            // sql 被排除(与 database.php 的 trigger_sql=false 双保险)。
            'level'          => ['error', 'warning', 'notice', 'log', 'critical', 'alert', 'emergency'],
            // 0 = 从不清理。file_size 到 2MB 只是改名成 DD-<时间戳>.log,旧文件永久堆积,
            // 磁盘占用无上界(最终表现是整站 5xx)。给一个非零值让它自己滚动。
            'max_files'      => 30,
            'file_size'      => 2097152,
            'json'           => false,
            'format'         => '[%s][%s] %s',
            'realtime_write' => false,
        ],
    ],
];
