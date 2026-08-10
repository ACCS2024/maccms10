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
            'hostport'        => env('DB_PORT', '3306'),
            'dsn'             => '',
            'params'          => [],
            'charset'         => env('DB_CHARSET', 'utf8mb4'),
            'prefix'          => env('DB_PREFIX', 'mac_'),
            // 'debug' 在 think-orm 4 里已经没有读取点了(TP5 用它兜住 SQL 监听),
            // 真正的开关是下面这个。包内默认 true(PDOConnection.php:77),于是每条
            // 语句都会被 trigger 给日志通道,而 config/log.php 又没有 level 过滤 ——
            // 结果是「每请求每条 SQL 一行、带拼好的字面量参数」落盘且永不清理,
            // 而 TP5 那边 log.type='test' 是空驱动,一个字节都不写。
            'debug'           => false,
            'trigger_sql'     => false,
            // 关于 fields_strict:TP5 的 application/database.php:18 写的是 false,TP8 这里
            // 不声明则取包内默认 true。但「后台表单带 __token__ 保存会抛 DbException」这个
            // 推论【实测不成立】,故意不加这个键:
            //   · 后台保存一律经 app\common\model\*(extends think\Model),
            //     Model::update()/insert() 会先用 getFields() 得到的真实列名过滤一遍,
            //     __token__ 根本到不了 Builder 的 strict 检查;
            //   · 全仓也没有把请求数组直接交给 Db::name()->update() 的裸写入。
            // 实测(真实 HTTP + 已登录后台,POST type/info 带 __token__):
            //   加 fields_strict=false → 保存成功;不加 → 同样保存成功。
            // 既然拿不出会失败的路径,就不要用一个更宽松的设置去掩盖将来真正的字段名笔误。
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
