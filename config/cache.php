<?php
return [
    'default' => 'file',
    'stores'  => [
        'file' => [
            'type'   => 'file',
            'path'   => '',
            'prefix' => '',
            'expire' => 0,
        ],
        'redis' => [
            'type'     => 'redis',
            'host'     => '127.0.0.1',
            'port'     => 6379,
            'password' => '',
            'select'   => 0,
            'timeout'  => 0,
            'expire'   => 0,
            'prefix'   => '',
        ],
    ],
];
