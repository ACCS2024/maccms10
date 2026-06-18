<?php
return [
    'default'     => 'mysql',
    'connections' => [
        'mysql' => [
            'type'            => 'mysql',
            'hostname'        => env('DB_HOST', '127.0.0.1'),
            'database'        => env('DB_NAME', ''),
            'username'        => env('DB_USER', ''),
            'password'        => env('DB_PASS', ''),
            'hostport'        => '3306',
            'dsn'             => '',
            'params'          => [],
            'charset'         => 'utf8mb4',
            'prefix'          => 'mac_',
            'debug'           => false,
            'deploy'          => 0,
            'rw_separate'     => false,
            'master_num'      => 1,
            'slave_no'        => '',
            'result_type'     => 0,
            'auto_timestamp'  => false,
            'datetime_format' => 'Y-m-d H:i:s',
            'fields_cache'    => false,
        ],
    ],
];
