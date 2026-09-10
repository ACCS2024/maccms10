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

// One contract serves production stores and the administrator connection probe.
// Network stores are validated lazily unless selected as the default backend.
return \app\common\util\CacheConnection::configuration($_app);
