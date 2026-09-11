<?php
/** Actual constructors, response exceptions and framework middleware; synthetic presentation/configuration only. */
declare(strict_types=1);
namespace {
    require dirname(__DIR__).'/vendor/autoload.php';
    require __DIR__.'/fixtures/security_audit_test_helpers.php';
    function request() { return \think\Container::getInstance()->make('request'); }
    function config($name, $default = null) { return \think\facade\Config::get($name, $default); }
    function lang($name, $vars = []) { return $name; }
    function mac_get_refer() { return ''; }
    function mac_param_url() { return $GLOBALS['response_params']; }
    function json($data) { return \think\Response::create($data, 'json'); }
    function url($path) { return '/index.php/'.$path; }
    function redirect($url) { return \think\Response::create($url, 'redirect', 302); }
    function cookie($key, $value = null) { \think\facade\Cookie::delete($key); }
    require dirname(__DIR__).'/application/common/controller/All.php';
}
namespace app\index\controller {
    // Omit the independent site/login/database bootstrap while retaining the actual common error/assign contract.
    class Base extends \app\common\controller\All {
        protected function label_fetch($tpl, $loadcache = 1, $type = 'html') { return 'rendered:'.$tpl; }
    }
}
namespace {
    $root = audit_temp_dir('constructor-response');
    define('APP_PATH', $root.'/application/');
    define('ENTRANCE', 'index');
    define('MAC_PATH', '/');
    define('MAC_ROOT', $root.'/');
    $mode = $argv[1] ?? 'normal';
    if ($mode !== 'unbound') { define('BIND_MODULE', 'install'); }
    foreach (['application/data/install', 'application/admin/controller', 'templates/label', 'sessions'] as $dir) {
        mkdir($root.'/'.$dir, 0700, true);
    }
    file_put_contents($root.'/templates/label/about.html', 'fixture');
    file_put_contents(APP_PATH.'admin/controller/Update.php', '<?php // fixture');
    $GLOBALS['MAC_ROOT_TEMPLATE'] = $root.'/templates/';
    $GLOBALS['config'] = ['gbook'=>['status'=>0], 'comment'=>['status'=>0], 'site'=>['install_dir'=>'/'], 'app'=>[]];
    $GLOBALS['user'] = ['user_id'=>0];
    $GLOBALS['response_params'] = [];
    $app = new \think\App($root.'/');
    $app->instance(\think\exception\Handle::class, new class($app) extends \think\exception\Handle {
        public function render(\think\Request $request, \Throwable $error): \think\Response {
            if (!$error instanceof \think\exception\HttpResponseException) { throw $error; }
            return parent::render($request, $error);
        }
    });
    $app->config->set(['type'=>'file', 'name'=>'fixture_session', 'expire'=>3600, 'path'=>$root.'/sessions'], 'session');
    $dbConfig = ['default'=>'fixture', 'auto_timestamp'=>false, 'connections'=>['fixture'=>[
        'type'=>'sqlite', 'database'=>':memory:', 'prefix'=>'fixture_', 'fields_cache'=>false,
    ]]];
    $manager = new \think\DbManager(); $manager->setConfig($dbConfig);
    $app->instance('think\\DbManager', $manager);
    $app->config->set($dbConfig, 'database');
    \think\Model::maker(static function ($model) use ($manager) { $model->setOption('db', $manager); });
    $manager->execute('CREATE TABLE fixture_user (user_id INTEGER PRIMARY KEY, user_portrait TEXT)');
    $app->config->set(['update_hash'=>str_repeat('0',32)], 'version');
    $app->instance('view', new class {
        public array $data = [];
        public function assign($name, $value = null) { $this->data = array_replace($this->data, is_array($name) ? $name : [$name=>$value]); }
        public function fetch($name) { return 'rendered:'.$name; }
    });
    // Use ThinkPHP's exception handler at each pipeline boundary, as the HTTP application does.
    $app->middleware->import([\app\middleware\SecurityHeaders::class, \think\middleware\SessionInit::class]);
    function responseRun(string $class, string $action, bool $ajax = false): \think\Response {
        global $app;
        $request = (new \think\Request())->withServer(['REQUEST_METHOD'=>'GET','HTTP_HOST'=>'fixture.invalid','SERVER_PORT'=>80, 'HTTP_X_REQUESTED_WITH'=>$ajax ? 'XMLHttpRequest' : '']);
        $request->setController('Fixture'); $request->setAction($action);
        if ($ajax) { $request->withHeader(['x-requested-with'=>'XMLHttpRequest']); }
        $app->instance('request', $request);
        $GLOBALS['response_action_reached'] = false;
        $finished = false;
        ob_start();
        try {
            $response = $app->middleware->pipeline()->send($request)->then(function () use ($class, &$finished) {
                try {
                    $controller = new $class();
                    $GLOBALS['response_action_reached'] = true;
                    return \think\Response::create('action reached');
                } finally { $finished = true; }
            });
        } finally { $output = ob_get_clean(); }
        check($finished && $output === '', 'Constructor must unwind without directly emitting output');
        check($response->getHeader('X-Content-Type-Options') === 'nosniff', 'Security middleware must finalize an early response');
        check(str_contains((string)$response->getHeader('Content-Security-Policy'), "script-src 'self'"), 'Early response must retain CSP');
        check($response->getHeader('Cache-Control') === 'private, no-store', 'Session-bearing early response must stay private');
        check($request->session() !== null, 'Session middleware must initialize the request');
        check(\think\facade\Cookie::getCookie() !== [], 'Session middleware must queue outgoing cookies');
        $app->middleware->end($response);
        return $response;
    }
    try {
        if ($mode === 'unbound') {
            $response = responseRun(\app\install\controller\Index::class, 'index');
            check($response->getCode() === 403 && $response->getContent() === '', 'Installer requires the installer entry point');
            check(!$GLOBALS['response_action_reached'], 'Unbound installer must not proceed');
        } else {
            foreach (['Gbook'=>'gbook is close', 'Comment'=>'comment is close'] as $name=>$body) {
                $response = responseRun('app\\index\\controller\\'.$name, 'index');
                check($response->getCode() === 200 && $response->getContent() === $body, 'Closed module response changed');
                check(!$GLOBALS['response_action_reached'], 'Closed module reached an action');
                $GLOBALS['config'][strtolower($name)]['status'] = 1;
                $response = responseRun('app\\index\\controller\\'.$name, 'index');
                check($GLOBALS['response_action_reached'], 'Enabled module must continue normally');
            }
            $response = responseRun(\app\index\controller\User::class, 'cash');
            check($response->getCode() === 302 && $response->getHeader('Location') === '/index.php/user/login', 'Guest member redirect changed');
            check(!$GLOBALS['response_action_reached'], 'Guest reached the member action');
            $response = responseRun(\app\index\controller\User::class, 'login');
            check($GLOBALS['response_action_reached'], 'Guest login must remain accessible');
            $response = responseRun(\app\index\controller\Label::class, 'about');
            check($response->getContent() === 'rendered:label/about' && !$GLOBALS['response_action_reached'], 'Custom page must render exactly once');
            $response = responseRun(\app\index\controller\Label::class, '');
            check($response->getContent() === '' && !$GLOBALS['response_action_reached'], 'Empty label action must end with an empty response');
            foreach ([null, [], ['about'], 1, false, 'missing', str_repeat('a',129), 'nested/about'] as $file) {
                $GLOBALS['response_params'] = ['file'=>$file];
                $response = responseRun(\app\index\controller\Label::class, 'about', true);
                check($response->getData()['code'] === 0 && !$GLOBALS['response_action_reached'], 'Invalid AJAX label must return the error and halt dispatch');
            }
            $GLOBALS['response_params'] = ['file'=>'missing'];
            $response = responseRun(\app\index\controller\Label::class, 'about');
            check($response->getContent() === 'rendered:public/jump' && !$GLOBALS['response_action_reached'], 'HTML label error must retain its jump response');
            file_put_contents(APP_PATH.'data/install/install.lock', 'fixture');
            $response = responseRun(\app\install\controller\Index::class, 'index');
            check($response->getCode() === 403 && $response->getContent() === 'already installed' && !$GLOBALS['response_action_reached'], 'Locked installer must stop');
            $response = responseRun(\app\admin\controller\Base::class, 'index');
            check($response->getContent() === 'admin/update/core_file_error' && !$GLOBALS['response_action_reached'], 'Integrity guard must stop before login/DDL');
        }
        echo 'Constructor response lifecycle: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.$mode."\n";
    } finally { audit_remove_temp($root); }
}
