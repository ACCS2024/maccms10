<?php
return [
    'app_debug'               => false,
    'app_trace'               => false,
    'default_timezone'        => 'Asia/Shanghai',
    'default_lang'            => 'zh-cn',
    // TP5 遗留键，TP8 框架不读取此值，自定义异常处理器在 application/provider.php 注册。
    'exception_handle'        => '',
    // TP8 内置机制：仅在 app_debug=false 且对应状态码模板不为空时生效。
    // 当前由 ExceptionHandle::render() 统一处理，此处留空。
    'http_exception_template' => [],
];
