<?php
// +----------------------------------------------------------------------
// | 缓存设置
// +----------------------------------------------------------------------
//
// ⚠ 这些值必须在【配置加载期】就定型,不能靠中间件回填。
//
// TP8 的驱动是懒解析 + 记忆化的,而 file 缓存驱动在 App::initialize() 阶段就被建好了:
//   initializer\BootService → App::boot() → service\ModelService::boot()
//   → Model::setDb($app->db) → Db.php `$db->setCache($cache->store($store))`
// 这一步远早于任何中间件。所以 application/middleware/AppInit.php 里那段
// `$cacheStores['file']['expire'] = cache_time; Config::set(..., 'cache')`
// 写进去了、回读也是新值,但【已经建好的驱动不会重读】——
// 实测生效 expire 一直是 0(= 永不过期),而 TP5 时代是 3600。
// 后果:所有不带 TTL 的 Cache::set(分类树、会员组权限、列表缓存…)变成永久缓存,
// 只能靠后台「清空缓存」才会更新。全程零报错。
//
// 因此这里直接读 application/extra/maccms.php —— 与 config/maccms.php 的加载桩同一套路,
// 在 App::load() 期完成,任何组件实例化之前就是最终值。
$_f    = __DIR__ . '/../application/extra/maccms.php';
$_m    = file_exists($_f) ? (include $_f) : [];
$_app  = (is_array($_m) && isset($_m['app']) && is_array($_m['app'])) ? $_m['app'] : [];

$_type = strtolower(trim((string)($_app['cache_type'] ?? 'file')));
if (!in_array($_type, ['file', 'memcache', 'memcached', 'redis'], true)) {
    $_type = 'file';
}
// 与 TP5 的 behavior/Init.php 同一套兜底:小于 1 视为未配置,给 60 秒下限
$_expire  = (int)($_app['cache_time'] ?? 0);
if ($_expire < 1) {
    $_expire = 60;
}
$_timeout = ((float)($_app['cache_timeout'] ?? 0)) > 0 ? (float)$_app['cache_timeout'] : 1.5;

return [
    'default' => $_type,
    'stores'  => [
        'file' => [
            'type'   => 'file',
            'path'   => '',
            'prefix' => '',
            'expire' => $_expire,
        ],
        'redis' => [
            'type'     => 'redis',
            'host'     => (string)($_app['cache_host']     ?? '127.0.0.1'),
            'port'     => (int)($_app['cache_port']        ?? 6379),
            'username' => (string)($_app['cache_username'] ?? ''),
            'password' => (string)($_app['cache_password'] ?? ''),
            'select'   => (int)($_app['cache_db']          ?? 0),
            'timeout'  => $_timeout,
            'expire'   => $_expire,
            'prefix'   => '',
        ],
        'memcache' => [
            'type'   => 'memcache',
            'host'   => (string)($_app['cache_host'] ?? '127.0.0.1'),
            'port'   => (int)($_app['cache_port']    ?? 11211),
            'expire' => $_expire,
            'prefix' => '',
        ],
        'memcached' => [
            'type'   => 'memcached',
            'host'   => (string)($_app['cache_host'] ?? '127.0.0.1'),
            'port'   => (int)($_app['cache_port']    ?? 11211),
            'expire' => $_expire,
            'prefix' => '',
        ],
    ],
];
