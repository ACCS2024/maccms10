<?php
namespace app\middleware;

use think\facade\Cache;

class AppInit
{
    /**
     * 静态资源版本戳。见 tpl_replace_string 里 __ASSETV__ 的说明。
     * 缓存在静态属性里：一次请求内会被多个模板引用，不必反复 stat。
     */
    private static function assetVersion(): string
    {
        static $v = null;
        if ($v !== null) {
            return $v;
        }
        $stamp = (defined('APP_PATH') ? APP_PATH : __DIR__ . '/../') . 'data/asset_version.txt';
        if (is_file($stamp)) {
            $t = trim((string)@file_get_contents($stamp));
            if ($t !== '' && preg_match('/^[A-Za-z0-9._-]{1,32}$/', $t)) {
                return $v = $t;
            }
        }
        return $v = (string)@filemtime(__FILE__);
    }

    public function handle($request, \Closure $next)
    {
        if (PHP_VERSION_ID < 80000 && function_exists('libxml_disable_entity_loader')) {
            libxml_disable_entity_loader(true);
        }

        $GLOBALS['mctheme'] = config('mctheme') ?: ['theme' => []];

        // ── 恢复 __STATIC__ / __ROOT__ 模板占位符替换 ──────────────────────
        // TP5 的框架在 think\View::__construct() 里内置了这组替换
        // （thinkphp/library/think/View.php:54），迁到 TP8 后框架不再提供，
        // 而后台 41 个模板、前台 3 个主题文件仍在用 __STATIC__。
        // 缺了它，href="__STATIC__/css/x.css" 会被浏览器按当前页面 URL
        // 相对解析 → 打回路由拿到 HTML → 浏览器以 MIME 不符拒绝加载，
        // 表现为整个后台无样式、layui is not defined。
        //
        // static 与 static_new 的取舍：固定取 static_new。
        //
        // 这里原本写的是
        //     $newVersion = $config['site']['new_version'] ?? '';
        //     $staticDir  = ((string)$newVersion === '0') ? '/static' : '/static_new';
        // 但 $config 直到本方法第 60 行附近才由 config('maccms') 赋值 —— 第一行读的是
        // 未定义变量，?? 把它吞成 ''，于是 === '0' 恒为 false，整个分支是死代码，
        // 实际行为一直就是无条件 /static_new。
        //
        // 不把它"修好"成真的读 new_version，是因为那会把一个从未生效过的开关
        // 突然接通：new_version 是【后台皮肤】开关（admin/controller/System.php
        // 的 configVersion 写它），而本仓库只带新版后台视图，其模板引用的
        // static_new/css/tailwindcssOutput.css 在 static/ 下并不存在 ——
        // 任何一个历史上把它设成 0 的站点会在这次上线后整个后台无样式。
        // 所以这里把真实契约写死并写清楚，而不是留一段"看起来能配"的死代码。
        $staticDir = '/static_new';

        $req  = $request;
        $base = method_exists($req, 'root') ? (string)$req->root() : '';
        $root = strpos($base, '.') !== false ? rtrim(dirname($base), '/\\') : rtrim($base, '/');
        if ($root !== '' && $root[0] !== '/') {
            $root = '/' . $root;
        }

        \think\facade\Config::set([
            'tpl_replace_string' => array_merge(
                (array)\think\facade\Config::get('view.tpl_replace_string', []),
                [
                    '__ROOT__'      => $root,
                    'MAC_BASE_PATH' => $root,
                    '__STATIC__'    => $root . $staticDir,
                    '__CSS__'       => $root . $staticDir . '/css',
                    '__JS__'        => $root . $staticDir . '/js',
                    '__IMG__'       => $root . $staticDir . '/images',

                    // 静态资源版本号（缓存击穿）。用法：src="__STATIC__/js/x.js?v=__ASSETV__"
                    //
                    // 之前的写法有三种，都不成立：
                    //   · 43 处【完全没有版本号】—— 改了 JS/CSS 推上去，浏览器还吃旧缓存，
                    //     本轮就因此让站长反复看到「改了没生效」；
                    //   · 14 处用 {$MAC_VERSION} —— 那是 maccms 大版本号(v10)，每次 push 根本不变；
                    //   · 1 处 v={:time()} —— 走到另一个极端，每次请求都变，等于彻底禁用缓存。
                    //
                    // 取值优先级：
                    //   1. application/data/asset_version.txt —— 由 bin/deploy-155.sh 每次部署写入
                    //      （内容是部署时间戳）。这是唯一「每次 push 必变、同一次部署内不变」的来源。
                    //   2. 该文件不存在时（本地开发/未走部署脚本）退回到本文件自身的 mtime，
                    //      保证改了代码就变，不会一直命中旧缓存。
                    '__ASSETV__'    => self::assetVersion(),
                ]
            ),
        ], 'view');

        $config = config('maccms');
        if (!isset($config['meilisearch']) || !is_array($config['meilisearch'])) {
            $config['meilisearch'] = [
                'enabled'       => '0',
                'host'          => 'http://127.0.0.1:7700',
                'api_key'       => '',
                // 仅当 meilisearch 配置块整个缺失时才走到这里(且 enabled=0,不会真去查)。
                // 这里留空而不是写死历史共享名 maccms_contents:那个名字全局共用,
                // 多站共用一台 Meili 会互相覆盖文档,而且本机通常根本没有这个索引,
                // 一旦被人照抄进真实配置就会让 Meili 永远 404、全站静默回落 MySQL
                // (2026-08-26 乐播熔断事故的起点)。留空后由 indexUid() 在真正用到时
                // 惰性派生本站唯一名,不在中间件里引入数据库依赖。
                'index_uid'     => '',
                'timeout'       => '8',
                'sync_on_save'  => '1',
                'search_only_wd' => '1',
            ];
        }
        $domain = config('domain');

        $isMobile = 0;
        $ua       = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
        if (preg_match('/(nokia|sony|ericsson|mot|samsung|sgh|lg|philips|panasonic|alcatel|lenovo|meizu|cldc|midp|iphone|wap|mobile|android)/i', $ua)) {
            $isMobile = 1;
        }

        $isDomain = 0;
        if (is_array($domain) && !empty($domain[$_SERVER['HTTP_HOST'] ?? ''])) {
            $config['site'] = array_merge($config['site'], $domain[$_SERVER['HTTP_HOST']]);
            $isDomain       = 1;
            if (empty($config['site']['mob_template_dir']) || $config['site']['mob_template_dir'] === 'no') {
                $config['site']['mob_template_dir'] = $config['site']['template_dir'];
            }
            $config['site']['site_wapurl']  = $config['site']['site_url'];
            $config['site']['mob_html_dir'] = $config['site']['html_dir'];
            $config['site']['mob_ads_dir']  = $config['site']['ads_dir'];
        }

        $TMP_ISWAP       = 0;
        $TMP_TEMPLATEDIR = $config['site']['template_dir'];
        $TMP_HTMLDIR     = $config['site']['html_dir'];
        $TMP_ADSDIR      = $config['site']['ads_dir'];

        if ($isMobile && $isDomain === 0) {
            if (($config['site']['mob_status'] == 2)
                || ($config['site']['mob_status'] == 1 && ($_SERVER['HTTP_HOST'] ?? '') == $config['site']['site_wapurl'])
                || ($config['site']['mob_status'] == 1 && $isDomain)) {
                $TMP_ISWAP       = 1;
                $TMP_TEMPLATEDIR = $config['site']['mob_template_dir'];
                $TMP_HTMLDIR     = $config['site']['mob_html_dir'];
                $TMP_ADSDIR      = $config['site']['mob_ads_dir'];
            }
        }

        // defined() guard: 在 Swoole/RoadRunner 等持久进程中防止重复 define()
        defined('MAC_URL')               || define('MAC_URL',               'http://www.maccms.la/');
        defined('MAC_NAME')              || define('MAC_NAME',              '苹果CMS');
        defined('MAC_PATH')              || define('MAC_PATH',              $config['site']['install_dir'] . '');
        defined('MAC_MOB')               || define('MAC_MOB',               $TMP_ISWAP);
        defined('MAC_ROOT_TEMPLATE')     || define('MAC_ROOT_TEMPLATE',     ROOT_PATH . 'template/' . $TMP_TEMPLATEDIR . '/' . $TMP_HTMLDIR . '/');
        defined('MAC_PATH_TEMPLATE')     || define('MAC_PATH_TEMPLATE',     MAC_PATH  . 'template/' . $TMP_TEMPLATEDIR . '/');
        defined('MAC_PATH_TPL')          || define('MAC_PATH_TPL',          MAC_PATH_TEMPLATE . $TMP_HTMLDIR . '/');
        defined('MAC_PATH_ADS')          || define('MAC_PATH_ADS',          MAC_PATH_TEMPLATE . $TMP_ADSDIR  . '/');
        defined('MAC_PAGE_SP')           || define('MAC_PAGE_SP',           $config['path']['page_sp'] . '');
        defined('MAC_PLAYER_SORT')       || define('MAC_PLAYER_SORT',       $config['app']['player_sort']);
        defined('MAC_ADDON_PATH')        || define('MAC_ADDON_PATH',        ROOT_PATH . 'addons/');
        defined('MAC_ADDON_PATH_STATIC') || define('MAC_ADDON_PATH_STATIC', ROOT_PATH . 'static/addons/');

        $GLOBALS['MAC_ROOT_TEMPLATE'] = ROOT_PATH . 'template/' . $TMP_TEMPLATEDIR . '/' . $TMP_HTMLDIR . '/';
        $GLOBALS['MAC_PATH_TEMPLATE'] = MAC_PATH . 'template/' . $TMP_TEMPLATEDIR . '/';
        $GLOBALS['MAC_PATH_TPL']      = $GLOBALS['MAC_PATH_TEMPLATE'] . $TMP_HTMLDIR . '/';
        $GLOBALS['MAC_PATH_ADS']      = $GLOBALS['MAC_PATH_TEMPLATE'] . $TMP_ADSDIR  . '/';

        $https = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on')
              || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
        $GLOBALS['http_type'] = $https ? 'https://' : 'http://';

        // view_path — TP8: Config::set(array $config, string $name)
        // 后台始终使用应用自身视图目录(application/admin/view/,view_path 置空由
        // 多应用解析),不套前台主题路径;前台才用主题路径。
        $viewPath = 'template/' . $TMP_TEMPLATEDIR . '/' . $TMP_HTMLDIR . '/';
        if (ENTRANCE === 'admin') {
            \think\facade\Config::set(['view_path' => ''], 'view');
        } else {
            \think\facade\Config::set(['view_path' => $viewPath], 'view');
        }

        if (intval($config['app']['search_len']) < 1) {
            $config['app']['search_len'] = 50;
        }

        if (empty($config['app']['pathinfo_depr'])) {
            $config['app']['pathinfo_depr'] = '/';
        }
        \think\facade\Config::set(['pathinfo_depr' => $config['app']['pathinfo_depr']], 'route');

        // 这两处归一只是为了让 $GLOBALS['config'] 里的值干净(模板与业务代码会读它),
        // 【不再】从这里回写 cache 配置组 —— 缓存驱动在 App::initialize() 的
        // BootService→ModelService 阶段就建好并记忆化了,比任何中间件都早,
        // 这里写多少它都不重读(实测生效 expire 一直是 0 = 永不过期)。
        // 真正的落点已挪到 config/cache.php,在 App::load() 期直接读 extra/maccms.php。
        if (intval($config['app']['cache_time']) < 1) {
            $config['app']['cache_time'] = 60;
        }
        if (!in_array($config['app']['cache_type'], ['file', 'memcache', 'memcached', 'redis'])) {
            $config['app']['cache_type'] = 'file';
        }

        // 后台「系统设置 → 语言」原本写的是 app 组的 default_lang,而 TP8 的 Lang
        // 只读【lang 组】(Lang.php:78 `$config->get('lang')`),config/lang.php 又不存在,
        // 所以那次 Config::set 没有任何消费者 —— 实测:把 maccms.app.lang 设成 en-us 后
        // Lang::getLangSet() 仍是 zh-cn、lang('save_ok') 仍返回中文,仓库里 9 份翻译
        // 一份都选不中。
        // 而且 App::initialize() 的 loadLangPack()(App.php:511-512)早在中间件之前
        // 就按 Lang 自带默认值 zh-cn 装完包了,只改配置也追不回来,必须显式重切。
        if (!empty($config['app']['lang'])) {
            $langSet = (string)$config['app']['lang'];
            // 只在确实存在对应语言包时才切:否则 getLangSet() 会变成一个查不到任何
            // 键的语言,界面直接显示裸键名(比语言不生效更糟)。
            $langFile = APP_PATH . 'lang' . DIRECTORY_SEPARATOR . $langSet . '.php';
            if (is_file($langFile)) {
                \think\facade\Config::set(['default_lang' => $langSet], 'lang');
                if (strtolower((string)\think\facade\Lang::getLangSet()) !== strtolower($langSet)) {
                    // 不能只调 switchLangSet():它按 glob(getAppPath().'lang/...') 找语言包,
                    // 而中间件此刻已在 MultiApp 之后 —— getAppPath() 早被改写成
                    // application/<应用名>/(MultiApp.php:176),那底下没有 lang/ 目录,
                    // 于是只切了语言标记却一个键都没装,界面全部退化成裸键名。
                    // 显式按 APP_PATH 装包。
                    \think\facade\Lang::setLangSet($langSet);
                    \think\facade\Lang::load([$langFile], $langSet);
                }
            }
        }

        // 会话后端的选择已挪到 config/session.php(App::load() 期定型)。
        // 原先这里的 Config::set(..., 'session') 是彻底的空操作:SessionInit 是第 2 个
        // 全局中间件,它在本中间件之前就已经解析并记忆化了 Store + handler;
        // 而且 TP8 根本没有 redis session 驱动,'type'=>'redis' 一旦真生效反而是致命错误。

        $GLOBALS['config'] = $config;

        // 触发 addons 初始化（路由注册 + 钩子加载）
        if (function_exists('addons_boot')) {
            addons_boot();
        }

        return $next($request);
    }
}
