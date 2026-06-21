<?php
// TP8 服务绑定：将框架默认异常处理器替换为 maccms 自定义实现。
// 自定义处理器位于 application/ExceptionHandle.php，见该文件顶部注释。
// config/app.php 的 exception_handle 键在 TP8 中无效（TP5 遗留），勿混淆。
return [
    'think\exception\Handle' => \app\ExceptionHandle::class,
];
