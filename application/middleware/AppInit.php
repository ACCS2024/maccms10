<?php
namespace app\middleware;

use think\facade\Cache;

class AppInit
{
    public function handle($request, \Closure $next)
    {
        if (PHP_VERSION_ID < 80000 && function_exists('libxml_disable_entity_loader')) {
            libxml_disable_entity_loader(true);
        }

        $GLOBALS['mctheme'] = config('mctheme') ?: ['theme' => []];

        $config = config('maccms');
        if (!isset($config['meilisearch']) || !is_array($config['meilisearch'])) {
            $config['meilisearch'] = [
                'enabled'       => '0',
                'host'          => 'http://127.0.0.1:7700',
                'api_key'       => '',
                'index_uid'     => 'maccms_contents',
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

        if (intval($config['app']['cache_time']) < 1) {
            $config['app']['cache_time'] = 60;
        }
        if (!in_array($config['app']['cache_type'], ['file', 'memcache', 'memcached', 'redis'])) {
            $config['app']['cache_type'] = 'file';
        }

        $cacheTimeout = (isset($config['app']['cache_timeout']) && (float)$config['app']['cache_timeout'] > 0)
            ? (float)$config['app']['cache_timeout'] : 1.5;

        // Batch-update cache config in one call (TP8 array_merges at namespace level)
        $cacheStores = \think\facade\Config::get('cache.stores') ?: [];
        $cacheStores['file']['expire'] = (int)$config['app']['cache_time'];
        $cacheStores['redis']['timeout']  = $cacheTimeout;
        $cacheStores['redis']['host']     = $config['app']['cache_host']     ?? '127.0.0.1';
        $cacheStores['redis']['port']     = $config['app']['cache_port']     ?? 6379;
        $cacheStores['redis']['username'] = $config['app']['cache_username'] ?? '';
        $cacheStores['redis']['password'] = $config['app']['cache_password'] ?? '';
        if ($config['app']['cache_type'] === 'redis'
            && isset($config['app']['cache_db'])
            && intval($config['app']['cache_db']) > 0) {
            $cacheStores['redis']['select'] = intval($config['app']['cache_db']);
        }
        \think\facade\Config::set([
            'default' => $config['app']['cache_type'],
            'stores'  => $cacheStores,
        ], 'cache');

        if (!empty($config['app']['lang'])) {
            \think\facade\Config::set(['default_lang' => $config['app']['lang']], 'app');
        }

        $sessionType = isset($config['app']['session_type'])
            ? strtolower(trim((string)$config['app']['session_type'])) : '';
        if ($sessionType === 'redis') {
            \think\facade\Config::set([
                'type'       => 'redis',
                'host'       => $config['app']['cache_host']     ?? '127.0.0.1',
                'port'       => $config['app']['cache_port']     ?? 6379,
                'password'   => $config['app']['cache_password'] ?? '',
                'select'     => isset($config['app']['cache_db']) ? intval($config['app']['cache_db']) : 0,
                'timeout'    => $cacheTimeout,
                'persistent' => true,
            ], 'session');
        }

        $GLOBALS['config'] = $config;

        // 触发 addons 初始化（路由注册 + 钩子加载）
        if (function_exists('addons_boot')) {
            addons_boot();
        }

        return $next($request);
    }
}
