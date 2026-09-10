<?php
/** Real Container/Request/ORM regression, SQLite memory only; no application initialization. */
declare(strict_types=1);

namespace app\common\controller {
    class All {}
}
namespace app\admin\controller {
    class Base {
        public function error($message) { return ['code'=>0, 'msg'=>$message]; }
    }
}
namespace app\common\util {
    // Bound the external search dependency; controller and Container calls remain real.
    class ApiMeilisearchSuggest {
        public static array $calls = [];
        public static function suggestListDataRes($kind, $keyword, $limit) {
            self::$calls[] = [$kind, $keyword, $limit];
            return ['code'=>1, 'list'=>[['name'=>$keyword]], 'limit'=>$limit];
        }
    }
}
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($severity, $message, $file, $line) {
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    function config($name, $default = null) { return think\facade\Config::get($name, $default); }
    function lang($name, $vars = []) { return $name; }
    function json($data) { return new think\response\Json(new think\Cookie(think\Container::getInstance()->make('request')), $data); }
    function validate($name) { $class = 'app\\api\\validate\\' . $name; return new $class(); }
    function mac_search_len_check($params) { return $params; }
    function mac_filter_xss($text) { return strip_tags($text); }
    function mac_url_search($params, $kind) { return '/' . $kind . '?wd=' . rawurlencode($params['wd']); }
    $configuration = ['default'=>'audit','auto_timestamp'=>false,'connections'=>['audit'=>[
        'type'=>'sqlite','database'=>':memory:','prefix'=>'audit_','trigger_sql'=>false,'fields_cache'=>false,
    ]]];
    $container = new think\Container();
    think\Container::setInstance($container);
    // Same alias as think\App: typed Request and the static facade share the active request service.
    $container->bind(think\Request::class, 'request');
    $config = new think\Config();
    $config->set($configuration, 'database');
    $container->instance('config', $config);
    $manager = new think\DbManager();
    $manager->setConfig($configuration);
    $container->instance('think\\DbManager', $manager);
    $GLOBALS['config'] = ['app'=>['search'=>'1','count_cache_sec'=>0]];
    think\facade\Db::execute('CREATE TABLE audit_link (link_id INTEGER PRIMARY KEY, link_type INTEGER, link_time INTEGER, link_name TEXT, link_logo TEXT, link_url TEXT)');
    think\facade\Db::name('Link')->insertAll([
        ['link_id'=>1,'link_type'=>1,'link_time'=>100,'link_name'=>'Alpha','link_logo'=>'alpha.png','link_url'=>'https://example.test/alpha'],
        ['link_id'=>2,'link_type'=>2,'link_time'=>200,'link_name'=>'Beta','link_logo'=>'beta.png','link_url'=>'https://example.test/beta'],
    ]);
    $checks = 0;
    function requestExpect($condition, string $message): void {
        global $checks;
        ++$checks;
        if (!$condition) { throw new RuntimeException($message); }
    }
    function activeRequest(array $params, string $controller, string $action): think\Request {
        $request = (new think\Request())->withGet($params)->setController($controller)->setAction($action);
        think\Container::getInstance()->instance('request', $request);
        return $request;
    }
    class LegacyRequestInjectionProbe {
        public function action(think\facade\Request $request) { return $request->param(); }
    }
    try {
        activeRequest(['wd'=>'negative'], 'Vod', 'suggest');
        $caught = false;
        try { $container->invokeMethod([new LegacyRequestInjectionProbe(), 'action']); }
        catch (Error $error) { $caught = str_contains($error->getMessage(), 'think\\facade\\Request::param'); }
        requestExpect($caught, 'A facade-typed parameter must reproduce the missing instance method failure');

        $vod = (new ReflectionClass(app\api\controller\Vod::class))->newInstanceWithoutConstructor();
        $link = (new ReflectionClass(app\api\controller\Link::class))->newInstanceWithoutConstructor();
        // Report both representative failures when this suite is run against the old signatures.
        $failures = [];
        foreach ([[$vod,'suggest',['wd'=>'Alpha','limit'=>3]], [$link,'get_list',['id'=>1,'orderby'=>'id']]] as [$controller,$action,$params]) {
            activeRequest($params, (new ReflectionClass($controller))->getShortName(), $action);
            try {
                $response = $container->invokeMethod([$controller, $action]);
                requestExpect($response instanceof think\response\Json && $response->getData()['code'] === 1, 'The action must return a successful JSON payload');
            } catch (Throwable $error) { $failures[] = get_class($controller) . '::' . $action . ': ' . $error->getMessage(); }
        }
        requestExpect($failures === [], implode("\n", $failures));

        foreach ([['Beta',2], ['Gamma',7]] as [$keyword,$limit]) {
            $request = activeRequest(['wd'=>$keyword,'limit'=>$limit], 'Vod', 'suggest');
            $data = $container->invokeMethod([$vod, 'suggest'])->getData();
            requestExpect($data['list'][0]['name'] === $keyword && $data['limit'] === $limit, 'Injected request changes must reach suggest business logic');
            requestExpect(think\facade\Request::param('wd') === $keyword, 'Existing static facade calls must still use the active request');
            requestExpect($container->invokeMethod([$vod,'suggest'], [$request])->getData() === $data, 'Explicit real Request arguments must also remain valid');
        }
        foreach ([1,2] as $id) {
            activeRequest(['id'=>$id,'orderby'=>'id','offset'=>0,'limit'=>1], 'Link', 'get_list');
            $data = $container->invokeMethod([$link,'get_list'])->getData();
            requestExpect($data['info']['total'] === 1 && array_column($data['info']['rows'], 'link_id') === [$id], 'Injected list parameters must produce the selected real database row');
        }
        activeRequest(['wd'=>''], 'Vod', 'suggest');
        requestExpect($container->invokeMethod([$vod,'suggest'])->getData()['code'] === 1001, 'Invalid suggest parameters must reach the normal validation branch');
        $admin = (new ReflectionClass(app\admin\controller\Adminaudit::class))->newInstanceWithoutConstructor();
        activeRequest(['id'=>0], 'Adminaudit', 'info');
        requestExpect($container->invokeMethod([$admin,'info']) === ['code'=>0,'msg'=>'param_err'], 'Admin audit detail must receive the real Request before validation');

        $typed = 0;
        $files = glob(dirname(__DIR__) . '/application/api/controller/*.php');
        $files[] = dirname(__DIR__) . '/application/admin/controller/Adminaudit.php';
        foreach ($files as $file) {
            $name = basename($file, '.php');
            $class = 'app\\' . ($name === 'Adminaudit' ? 'admin' : 'api') . '\\controller\\' . $name;
            if (!class_exists($class)) { continue; }
            $reflect = new ReflectionClass($class);
            foreach ($reflect->getMethods() as $method) {
                if ($method->getDeclaringClass()->getName() !== $class) { continue; }
                foreach ($method->getParameters() as $parameter) {
                    $type = $parameter->getType();
                    if ($parameter->getName() === 'request' && $type instanceof ReflectionNamedType) {
                        ++$typed;
                        requestExpect($type->getName() === think\Request::class, $class . '::' . $method->getName() . ' must type the concrete Request service');
                    }
                }
            }
        }
        requestExpect($typed >= 120, 'Contract inventory must cover the full API action/helper set and admin audit detail');
        echo 'framework_audit_request_injection: ' . $checks . ' checks passed (' . $typed . ' Request parameters) on PHP ' . PHP_VERSION . PHP_EOL;
    } catch (Throwable $error) {
        fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . PHP_EOL . $error->getTraceAsString() . PHP_EOL);
        exit(1);
    }
}
