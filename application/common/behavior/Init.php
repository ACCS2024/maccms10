<?php
namespace app\common\behavior;

use think\facade\Cache;
use think\facade\Config;

class Init
{
    public function run(&$params)
    {
        // 安全加固(V9/XXE):全局禁用 libxml 外部实体加载,防止采集/接口解析远程XML时的XXE。
        // PHP 8.0+ 默认已禁用外部实体且此函数被弃用,故仅在 <8.0 调用。
        if (PHP_VERSION_ID < 80000 && function_exists('libxml_disable_entity_loader')) {
            libxml_disable_entity_loader(true);
        }

        // 主题配置已在 App::init() 中通过 extra 扫描加载，此处不再重复 include mctheme.php
        // 同步到 $GLOBALS 供模板与 mac_tpl_* 直接读取，避免重复 config() 解析
        $GLOBALS['mctheme'] = config('mctheme') ?: ['theme' => []];

        $config = config('maccms');
        if (!isset($config['meilisearch']) || !is_array($config['meilisearch'])) {
            $config['meilisearch'] = [
                'enabled' => '0',
                'host' => 'http://127.0.0.1:7700',
                'api_key' => '',
                'index_uid' => 'maccms_contents',
                'timeout' => '8',
                'sync_on_save' => '1',
                'search_only_wd' => '1',
            ];
        }
        $domain = config('domain');

        $isMobile = 0;
        $ua = strtolower($_SERVER['HTTP_USER_AGENT']);
        $uachar = "/(nokia|sony|ericsson|mot|samsung|sgh|lg|philips|panasonic|alcatel|lenovo|meizu|cldc|midp|iphone|wap|mobile|android)/i";
        if((preg_match($uachar, $ua))) {
            $isMobile = 1;
        }

        $isDomain=0;
        if( is_array($domain) && !empty($domain[$_SERVER['HTTP_HOST']])){
            $config['site'] = array_merge($config['site'],$domain[$_SERVER['HTTP_HOST']]);
            $isDomain=1;
            if(empty($config['site']['mob_template_dir']) || $config['site']['mob_template_dir'] =='no'){
                $config['site']['mob_template_dir'] = $config['site']['template_dir'];
            }
            $config['site']['site_wapurl'] = $config['site']['site_url'];
            $config['site']['mob_html_dir'] = $config['site']['html_dir'];
            $config['site']['mob_ads_dir'] = $config['site']['ads_dir'];
        }
        $TMP_ISWAP = 0;
        $TMP_TEMPLATEDIR = $config['site']['template_dir'];
        $TMP_HTMLDIR = $config['site']['html_dir'];
        $TMP_ADSDIR = $config['site']['ads_dir'];

        if($isMobile && $isDomain==0){
            if( ($config['site']['mob_status']==2 ) || ($config['site']['mob_status']==1 && $_SERVER['HTTP_HOST']==$config['site']['site_wapurl']) || ($config['site']['mob_status']==1 && $isDomain) ) {
                $TMP_ISWAP = 1;
                $TMP_TEMPLATEDIR = $config['site']['mob_template_dir'];
                $TMP_HTMLDIR = $config['site']['mob_html_dir'];
                $TMP_ADSDIR = $config['site']['mob_ads_dir'];
            }
        }

        define('MAC_URL','http://www.maccms.la/');  // 原 'http'.'://'.'www'... 拼接免杀已还原(该常量全仓未被使用)
        define('MAC_NAME','苹果CMS');
        define('MAC_PATH', $config['site']['install_dir'] .'');
        define('MAC_MOB', $TMP_ISWAP);
        define('MAC_ROOT_TEMPLATE', ROOT_PATH .'template/'.$TMP_TEMPLATEDIR.'/'. $TMP_HTMLDIR .'/');
        define('MAC_PATH_TEMPLATE', MAC_PATH.'template/'.$TMP_TEMPLATEDIR.'/');
        define('MAC_PATH_TPL', MAC_PATH_TEMPLATE. $TMP_HTMLDIR  .'/');
        define('MAC_PATH_ADS', MAC_PATH_TEMPLATE. $TMP_ADSDIR  .'/');
        define('MAC_PAGE_SP', $config['path']['page_sp'] .'');
        define('MAC_PLAYER_SORT', $config['app']['player_sort'] );
        define('MAC_ADDON_PATH', ROOT_PATH . 'addons' . '/');
        define('MAC_ADDON_PATH_STATIC', ROOT_PATH . 'static/addons/');

        $GLOBALS['MAC_ROOT_TEMPLATE'] = ROOT_PATH .'template/'.$TMP_TEMPLATEDIR.'/'. $TMP_HTMLDIR .'/';
        $GLOBALS['MAC_PATH_TEMPLATE'] = MAC_PATH.'template/'.$TMP_TEMPLATEDIR.'/';
        $GLOBALS['MAC_PATH_TPL'] = $GLOBALS['MAC_PATH_TEMPLATE']. $TMP_HTMLDIR  .'/';
        $GLOBALS['MAC_PATH_ADS'] = $GLOBALS['MAC_PATH_TEMPLATE']. $TMP_ADSDIR  .'/';

        $GLOBALS['http_type'] = ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https')) ? 'https://' : 'http://';

        Config::set(['view_path' => 'template/' . $TMP_TEMPLATEDIR .'/' . $TMP_HTMLDIR .'/'], 'template');

        if(ENTRANCE=='admin'){
            if(!file_exists('./template/' . $TMP_TEMPLATEDIR .'/' . $TMP_HTMLDIR .'/')){
                Config::set(['view_path' => ''], 'template');
            }
        }
        if(intval($config['app']['search_len'])<1){
            $config['app']['search_len'] = 50;
        }
        if(intval($config['app']['cache_time'])<1){
            $config['app']['cache_time'] = 60;
        }
        Config::set(['expire' => $config['app']['cache_time']], 'cache');


        if(!in_array($config['app']['cache_type'],['file','memcache','memcached','redis'])){
            $config['app']['cache_type'] = 'file';
        }
        if(!empty($config['app']['lang'])){
            Config::set(['default_lang' => $config['app']['lang']], 'lang');
        }

        Config::set(['type' => $config['app']['cache_type']], 'cache');
        // 连接超时(秒):TP5 redis/memcache 驱动把该值作为 connect() 的秒级超时。
        // 历史硬编码 1000(=1000 秒)会在 Redis/Memcache 不可达时,让每个请求在 connect 上
        // 阻塞十几分钟 → 整站挂死。改为秒级快速失败(可经 maccms.php 的 cache_timeout 覆盖),
        // 使"缓存切 Redis"在后端故障时安全降级而非拖垮站点。
        $cacheTimeout = (isset($config['app']['cache_timeout']) && (float)$config['app']['cache_timeout'] > 0)
            ? (float)$config['app']['cache_timeout'] : 1.5;
        Config::set(['timeout' => $cacheTimeout], 'cache');
        Config::set(['host' => $config['app']['cache_host'], 'port' => $config['app']['cache_port'], 'username' => $config['app']['cache_username'], 'password' => $config['app']['cache_password']], 'cache');
        if($config['app']['cache_type'] == 'redis' && isset($config['app']['cache_db']) && intval($config['app']['cache_db']) > 0){
            Config::set(['select' => intval($config['app']['cache_db'])], 'cache');
        }
        if($config['app']['cache_type'] != 'file'){
            $opt = config('cache');
            Cache::forgetDriver();
        }

        // 会话存储:可选切 Redis(默认文件)。PHP 文件 session 有写锁——同一用户的并发请求
        // (播放页常并行发计数/弹幕/推荐等 ajax)会在 session 文件锁上串行等待。切 Redis 去锁并发。
        // 复用上面的缓存 Redis 连接参数,避免重复配置;连接超时同样秒级,后端故障快速降级。
        // 本桥接在 app_init 执行,早于首次 session 访问(CsrfGuard 等在 app_begin),故配置及时生效。
        $sessionType = isset($config['app']['session_type']) ? strtolower(trim((string)$config['app']['session_type'])) : '';
        if ($sessionType === 'redis') {
            Config::set([
                'type'       => 'redis',
                'host'       => $config['app']['cache_host'],
                'port'       => $config['app']['cache_port'],
                'password'   => $config['app']['cache_password'],
                'select'     => isset($config['app']['cache_db']) ? intval($config['app']['cache_db']) : 0,
                'timeout'    => $cacheTimeout,
                'persistent' => true,
            ], 'session');
        }

        $GLOBALS['config'] = $config;
    }
}