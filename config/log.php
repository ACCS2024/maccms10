<?php
return [
    'default'  => 'file',
    'channels' => [
        'file' => [
            'type'           => 'file',
            'path'           => '',
            'single'         => false,
            'apart_level'    => ['error', 'sql'],
            'max_files'      => 0,
            'file_size'      => 2097152,
            'json'           => false,
            'format'         => '[%s][%s] %s',
            'realtime_write' => false,
        ],
    ],
];
