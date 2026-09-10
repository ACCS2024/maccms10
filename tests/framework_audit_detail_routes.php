<?php
/** Real TP8 router and application route table, without application boot or database access. */
declare(strict_types=1);
namespace app\common\model {
    class HelpCfg { public static function get($key, $default = null) { return $default; } }
}
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    function config($name, $default = null) { return think\facade\Config::get($name, $default); }
    error_reporting(E_ALL);
    set_error_handler(static function ($severity, $message, $file, $line) {
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    class DetailRouteProbe extends think\Route {
        public function inspect(think\Request $request): array {
            $this->request = $request;
            $this->host = $request->host(true);
            $url = str_replace($this->config['pathinfo_depr'], '|', $this->path());
            $dispatch = $this->check($url, (bool)$this->config['route_complete_match']);
            $dispatch = $dispatch ?: $this->checkUrlDispatch($url);
            $dispatch->init($this->app);
            return [$request->controller(), $request->action(), $request->param()];
        }
    }
    $app = new think\App(sys_get_temp_dir() . '/maccms-route-audit-' . bin2hex(random_bytes(8)));
    $checks = 0;
    function routeExpect($condition, string $message): void {
        global $checks;
        ++$checks;
        if (!$condition) { throw new RuntimeException($message); }
    }
    function routeRequest(string $url): think\Request {
        $query = [];
        parse_str((string)parse_url($url, PHP_URL_QUERY), $query);
        return (new think\Request())->withServer(['REQUEST_METHOD'=>'GET', 'HTTP_HOST'=>'example.test', 'SCRIPT_NAME'=>'/index.php'])
            ->setPathinfo(ltrim((string)parse_url($url, PHP_URL_PATH), '/'))->withGet($query);
    }
    try {
        $app->config->set([], 'route');
        $old = new DetailRouteProbe($app);
        $old->any('actor-<page?>', 'actor/index');
        $old->any('actordetail-<id>', 'actor/detail');
        routeExpect($old->inspect(routeRequest('/actordetail-1.html'))[1] === 'index', 'The original optional-prefix rule must reproduce detail dispatch to the index');
        foreach ([0,1] as $legacy) {
            $app->config->set(['app'=>['legacy_pathinfo_url'=>$legacy]], 'maccms');
            $route = new DetailRouteProbe($app);
            $app->instance('route', $route);
            require dirname(__DIR__) . '/application/index/route/web.php';
            foreach (['actor'=>'Actor', 'topic'=>'Topic'] as $name=>$controller) {
                foreach ([
                    ["/$name.html", 'index', []],
                    ["/$name-2.html", 'index', ['page'=>'2']],
                    ["/{$name}detail-1.html", 'detail', ['id'=>'1']],
                    ["/$name/detail/id/1.html", 'detail', ['id'=>'1']],
                    ["/$name/detail.html?id=1", 'detail', ['id'=>'1']],
                    ["/$name/search.html?wd=CI", 'search', ['wd'=>'CI']],
                ] as [$url,$action,$params]) {
                    $request = routeRequest($url);
                    $app->instance('request', $request);
                    [$actualController,$actualAction,$actualParams] = $route->inspect($request);
                    routeExpect($actualController === $controller && $actualAction === $action, "$url must dispatch to $controller::$action (legacy=$legacy)");
                    foreach ($params as $key=>$value) {
                        routeExpect(($actualParams[$key] ?? null) === $value, "$url must preserve $key=$value");
                    }
                }
                $request = routeRequest('/');
                $app->instance('request', $request);
                $generated = $route->buildUrl($name . '/detail', ['id'=>1])->build();
                routeExpect(str_contains($generated, $name . 'detail-1.html'), 'Detail URL generation must retain its existing short form');
            }
        }
        echo 'framework_audit_detail_routes: ' . $checks . ' checks passed on PHP ' . PHP_VERSION . PHP_EOL;
    } catch (Throwable $error) {
        fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . PHP_EOL . $error->getTraceAsString() . PHP_EOL);
        exit(1);
    }
}
