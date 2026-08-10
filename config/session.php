<?php
// +----------------------------------------------------------------------
// | Session 设置
// +----------------------------------------------------------------------
//
// ⚠ 与 config/cache.php 同理:必须在【配置加载期】定型。
//
// think\Session 是 Manager 子类,驱动懒解析且记忆化;而 SessionInit 是第 2 个全局中间件,
// 它 handle() 的第一句 `$this->session->getName()` 就触发 getDriver() →
// getDefaultDriver() 读 config('session.type') → 建好 Store + handler 并记住。
// application/middleware/AppInit.php 排在第 4 位,它那段
// `if ($sessionType === 'redis') Config::set([...], 'session')` 跑的时候
// Store 早就建好了。实测:
//     config('session.type') 请求结束时 = 'redis'      ← 配置确实写进去了
//     实际 handler                      = think\session\driver\File   ← 跑的还是文件
// 更糟的是 application/common.php:867 的后台「性能体检」只看配置值,会显示
// 「会话存储:Redis ✓」并撤掉优化建议 —— 零报错、指标还告诉你搞定了。
//
// 另一个坑:TP8【没有】redis session 驱动(vendor/.../think/session/driver/ 下
// 只有 File.php 和 Cache.php)。所以 'type' => 'redis' 一旦真生效反而是
// "class not found" 致命错误。TP8 的正确做法是 type=cache + store=<缓存store>,
// 由 session\driver\Cache 代理到缓存层 —— 这也正是后台那个选项写的
// 「redis(复用上面缓存Redis,去文件锁)」的本意。
$_f   = __DIR__ . '/../application/extra/maccms.php';
$_m   = file_exists($_f) ? (include $_f) : [];
$_app = (is_array($_m) && isset($_m['app']) && is_array($_m['app'])) ? $_m['app'] : [];

$_sessionType = strtolower(trim((string)($_app['session_type'] ?? '')));
$_cacheType   = strtolower(trim((string)($_app['cache_type']   ?? 'file')));

// 三个条件同时满足才走 redis,任何一条不满足都静默回落文件会话:
//   1. 后台确实选了 redis 会话;
//   2. 缓存后端本身就是 redis —— 后台选项写的就是「复用上面缓存Redis」,
//      缓存都没走 redis 时把会话单独指过去,只会把登录态压在一个没人验证过的连接上;
//   3. php-redis 扩展装了 —— 否则 store('redis') 会在每个请求上抛异常,
//      而会话是【每个请求都要读】的东西,等于整站 500。
// 宁可"没按预期启用"也不要"启用了但连不上":前者只是慢,后者是全站不可用。
$_useRedis = ($_sessionType === 'redis') && ($_cacheType === 'redis') && extension_loaded('redis');

return [
    // file  = think\session\driver\File
    // cache = think\session\driver\Cache,再由 store 指向 config/cache.php 里的某个 store
    'type'     => $_useRedis ? 'cache' : 'file',
    'store'    => $_useRedis ? 'redis' : null,
    'expire'   => 1440,
    'prefix'   => 'mac_',

    // 下面这三个键是【说明性的,TP8 的 Session 组件从不读】。
    // 会话 cookie 由 SessionInit.php:62 经 think\Cookie 下发,真正决定其
    // HttpOnly / SameSite / Secure 的是 config/cookie.php。改这里没有任何效果。
    'httponly' => true,
    'secure'   => false,
    'samesite' => 'Lax',

    'domain'   => '',

    // file 驱动用本项作「session 存储目录」，不是 cookie 路径。
    //
    // 必须显式指定一个【跨应用共享】的绝对目录：留空时 TP8 的
    // think\session\driver\File 会回落到 $app->getRuntimePath()，而多应用模式下
    // 该路径是按应用分的 —— 同一个 PHPSESSID 会写成两份互不可见的文件：
    //     runtime/index/session/mac_/sess_xxx   （前台，验证码答案写在这里）
    //     runtime/admin/session/mac_/sess_xxx   （后台，登录时来这里读）
    // 于是后台登录永远读不到验证码，表现为「验证码不管怎么输都是错的」。
    // 后台鉴权态同理无法跨应用保持。
    //
    // 历史坑：此前曾误设为 '/'（当成 cookie 路径），导致会话写入文件系统根目录，
    // 且 GC 从 / 递归扫描整个磁盘 → 间歇 500。所以既不能留空也不能填 '/'。
    // Cookie 的路径由 cookie 配置决定，默认 '/'，与此项无关。
    'path'     => (defined('RUNTIME_PATH') ? RUNTIME_PATH : __DIR__ . '/../runtime/')
                  . 'session' . DIRECTORY_SEPARATOR,
];
