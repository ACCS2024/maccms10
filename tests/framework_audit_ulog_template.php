<?php
/** Real TP8 template lookup/rendering; login and log data queries are isolated. */
namespace app\index\controller {
    class Base {
        public function assign($key, $value) { \think\facade\View::assign($key, $value); }
        public function fetch($template) { return \think\facade\View::fetch($template); }
    }
}
namespace app\common\model {
    class Ulog {
        public function listData($where, $order, $page, $limit) {
            $GLOBALS['ulog_queries'][] = $where;
            return ['list'=>[], 'total'=>0];
        }
    }
}
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) { throw new \ErrorException($message, 0, $level, $file, $line); });
    function lang($key) { return $key; }
    function mac_param_url() { return ['wd'=>'']; }
    function url($path, $params = []) { return '/'.$path; }
    function mac_page_param($total, $limit, $page, $url) { return compact('total','limit','page','url'); }
    $temporary = sys_get_temp_dir().'/maccms-ulog-template-'.bin2hex(random_bytes(6));
    mkdir($temporary.'/user',0700,true);
    $app = new \think\App($temporary);
    $request = (new \think\Request())->withGet(['type'=>'2'])->setController('User')->setAction('ulog');
    $app->instance('request',$request);
    $app->config->set(['default'=>'file','stores'=>['file'=>['type'=>'File','path'=>$temporary.'/cache/']]],'cache');
    $GLOBALS['user'] = ['user_id'=>7];
    $GLOBALS['ulog_queries'] = [];
    $controller = (new \ReflectionClass(\app\index\controller\User::class))->newInstanceWithoutConstructor();
    $checks = 0;
    function verify($ok, $message) { global $checks; ++$checks; if (!$ok) { throw new \RuntimeException($message); } }
    function configureView($path) {
        global $app, $temporary;
        $app->config->set(['type'=>'Think','view_path'=>$path.'/','view_suffix'=>'html','cache_path'=>$temporary.'/cache/','tpl_cache'=>false],'view');
        $app->instance('view',new \think\View($app));
    }
    try {
        foreach ([dirname(__DIR__).'/template/default/html',$temporary] as $path) {
            configureView($path);
            $missing = false;
            try { $controller->ulog(); } catch (\think\exception\HttpException $error) { $missing = $error->getStatusCode() === 404; }
            verify($missing,'Missing Ulog template must produce an explicit 404');
            verify($GLOBALS['ulog_queries'] === [],'Missing template must fail before loading private log rows');
        }
        file_put_contents($temporary.'/user/ulog.html','custom-log {$param.type}:{$__PAGING__.total}');
        configureView($temporary);
        verify($controller->ulog() === 'custom-log 2:0','Existing custom Ulog templates must retain real rendering');
        verify($GLOBALS['ulog_queries'] === [['user_id'=>7,'ulog_type'=>'2']], 'Custom template path lost the original owner/type filter');
        echo "Ulog template: $checks checks passed on PHP ".PHP_VERSION."\n";
    } finally {
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($temporary,\FilesystemIterator::SKIP_DOTS),\RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($iterator as $entry) { $entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname()); }
        rmdir($temporary);
    }
}
