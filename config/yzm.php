<?php
/**
 * 转码机入库接口（api/controller/Yzm.php）的配置加载器。
 *
 * 真实配置含基础设施地址（转码机、图床、播放域名），不入版本库。
 * 存放位置按以下顺序解析，第一个存在的生效：
 *
 *   1. .env 里的 YZM_CONFIG 指定的绝对路径 —— 推荐放在 web 根目录之外，
 *      这样既不会被 HTTP 暴露，也不受任何针对站点目录的清理/扫描影响。
 *   2. application/extra/yzm.php（传统位置，仍支持）
 *
 * 找不到时返回空数组，Yzm 控制器会据此拒绝服务并记日志，
 * 而不是用内置默认值兜底（避免某一部署的地址变成所有部署的默认值）。
 */
$paths = [];

// 1) 环境变量（.env 的 YZM_CONFIG 或真实环境变量）。
//    注意不要只依赖它：config 文件在不同 SAPI 下的加载时机可能早于 env 就绪。
$env = getenv('YZM_CONFIG');
if (is_string($env) && $env !== '') {
    $paths[] = $env;
}
if (function_exists('env')) {
    $v = env('YZM_CONFIG', '');
    if (is_string($v) && $v !== '') {
        $paths[] = $v;
    }
}

// 2) 约定路径 /etc/maccms/yzm-<站点目录名>.php —— 不依赖 env 加载时机，
//    且位于 web 根之外：既不会被 HTTP 访问到，也不受针对站点目录的清理影响。
$root = dirname(__DIR__);
$paths[] = '/etc/maccms/yzm-' . basename($root) . '.php';
$paths[] = '/etc/maccms/yzm.php';

// 3) 传统位置（仍支持，但不推荐：它在 web 根内）
$paths[] = $root . '/application/extra/yzm.php';

foreach ($paths as $p) {
    if (is_string($p) && $p !== '' && is_file($p)) {
        $cfg = include $p;
        return is_array($cfg) ? $cfg : [];
    }
}

return [];
