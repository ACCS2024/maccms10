<?php
/** Real API controllers, Composer validator helper, Request injection and SQLite; no site bootstrap. */
declare(strict_types=1);

namespace app\common\controller {
    class All {}
}
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($severity, $message, $file, $line) {
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    function config($name, $default = null) { return think\facade\Config::get($name, $default); }
    function json($data) { return new think\response\Json(new think\Cookie(think\Container::getInstance()->make('request')), $data); }
    // Isolate presentation and user state; validation, controllers and database queries remain real.
    function mac_api_norm_limit($value) { return (int)$value <= 10 ? 10 : 20; }
    function mac_url_art_detail($row) { return '/art/' . $row['art_id']; }
    function mac_url_vod_detail($row) { return '/vod/' . $row['vod_id']; }
    function mac_url_img($value) { return $value; }
    function mac_content_read_points_amount($kind, $row) { return (int)($row['art_points_detail'] ?? 0); }
    function mac_append_type_is_vip_exclusive_for_rows(&$rows) {}
    function mac_user_fav_state($uid, $mid, $id) { return ['is_fav'=>false, 'fav_ulog_id'=>0]; }
    function mac_user_has_digg($mid, $id) { return false; }
    class ApiRuntimeCategoryCache {
        public function get($key) { return [1=>['type_id'=>1, 'type_pid'=>0, 'type_en'=>'audit']]; }
    }
    $container = new think\Container();
    think\Container::setInstance($container);
    $container->bind(think\Request::class, 'request');
    $configuration = ['default'=>'audit', 'auto_timestamp'=>false, 'connections'=>['audit'=>[
        'type'=>'sqlite', 'database'=>':memory:', 'prefix'=>'mac_', 'trigger_sql'=>false, 'fields_cache'=>false,
    ]]];
    $config = new think\Config();
    $config->set($configuration, 'database');
    $container->instance('config', $config);
    $container->instance('cache', new ApiRuntimeCategoryCache());
    $manager = new think\DbManager();
    $manager->setConfig($configuration);
    $container->instance('think\\DbManager', $manager);
    $GLOBALS['config'] = ['app'=>['count_cache_sec'=>0, 'cache_flag'=>'api_runtime_audit']];
    think\facade\Db::execute('CREATE TABLE mac_vod (vod_id INTEGER PRIMARY KEY, vod_name TEXT, vod_pic TEXT, vod_status INTEGER DEFAULT 1, vod_recycle_time INTEGER DEFAULT 0)');
    think\facade\Db::name('Vod')->insertAll([
        ['vod_id'=>1, 'vod_name'=>'First video', 'vod_pic'=>'one.png'],
        ['vod_id'=>2, 'vod_name'=>'Second video', 'vod_pic'=>'two.png'],
    ]);
    think\facade\Db::name('Vod')->insert(['vod_id'=>3, 'vod_name'=>'Hidden video', 'vod_pic'=>'hidden.png', 'vod_status'=>0]);
    think\facade\Db::name('Vod')->insert(['vod_id'=>4, 'vod_name'=>'Recycled video', 'vod_pic'=>'recycled.png', 'vod_recycle_time'=>100]);
    think\facade\Db::execute('CREATE TABLE mac_art (art_id INTEGER PRIMARY KEY, art_name TEXT, art_sub TEXT DEFAULT "", art_en TEXT DEFAULT "", art_pic TEXT DEFAULT "", art_blurb TEXT DEFAULT "", art_time INTEGER, art_time_add INTEGER DEFAULT 0, art_hits INTEGER, art_points INTEGER DEFAULT 0, art_points_detail INTEGER DEFAULT 0, art_remarks TEXT DEFAULT "", art_author TEXT DEFAULT "", type_id INTEGER DEFAULT 1, art_status INTEGER DEFAULT 1, art_recycle_time INTEGER DEFAULT 0)');
    think\facade\Db::name('Art')->insertAll([
        ['art_id'=>1, 'art_name'=>'Old popular article', 'art_time'=>100, 'art_hits'=>30],
        ['art_id'=>2, 'art_name'=>'Newest article', 'art_time'=>300, 'art_hits'=>10],
        ['art_id'=>3, 'art_name'=>'Middle article', 'art_time'=>200, 'art_hits'=>20],
    ]);
    think\facade\Db::name('Art')->insert(['art_id'=>4, 'art_name'=>'Hidden article', 'art_time'=>400, 'art_hits'=>40, 'art_status'=>0]);
    think\facade\Db::name('Art')->insert(['art_id'=>5, 'art_name'=>'Recycled article', 'art_time'=>500, 'art_hits'=>50, 'art_recycle_time'=>100]);
    $checks = 0;
    function apiRuntimeExpect($condition, string $message): void {
        global $checks;
        ++$checks;
        if (!$condition) { throw new RuntimeException($message); }
    }
    function apiRuntimeCall($controller, string $action, array $params): array {
        $request = (new think\Request())->withGet($params)
            ->setController((new ReflectionClass($controller))->getShortName())->setAction($action);
        $container = think\Container::getInstance();
        $container->instance('request', $request);
        return $container->invokeMethod([$controller, $action])->getData();
    }
    try {
        // Keep the real Composer helper: a test-defined validate() hides this migration failure.
        $legacy = validate('Vod');
        apiRuntimeExpect(get_class($legacy) === think\Validate::class && $legacy->getRules() === [], 'Short validator names must reproduce the package helper namespace-resolution failure');
        apiRuntimeExpect($legacy->scene('get_detail')->check(['id'=>1]), 'The legacy helper must reproduce silently skipped required-field rules');

        $vod = (new ReflectionClass(app\api\controller\Vod::class))->newInstanceWithoutConstructor();
        $art = (new ReflectionClass(app\api\controller\Art::class))->newInstanceWithoutConstructor();
        $failures = [];
        foreach ([[$vod, 'get_detail', []], [$art, 'get_list', []]] as [$controller, $action, $params]) {
            try {
                $data = apiRuntimeCall($controller, $action, $params);
                apiRuntimeExpect($data['code'] === ($action === 'get_detail' ? 1001 : 1), 'Missing required and optional fields must follow their respective JSON contracts');
            } catch (Throwable $error) { $failures[] = get_class($controller) . '::' . $action . ': ' . $error->getMessage(); }
        }
        apiRuntimeExpect($failures === [], implode("\n", $failures));

        foreach ([[], ['id'=>1], ['vod_id'=>''], ['vod_id'=>'abc'], ['vod_id'=>-1], ['vod_id'=>[1]]] as $params) {
            $data = apiRuntimeCall($vod, 'get_detail', $params);
            apiRuntimeExpect($data['code'] === 1001 && !isset($data['info']) && str_contains($data['msg'], 'vod_id'), 'Invalid detail IDs must return field validation JSON without reaching a database query');
        }
        foreach ([1, 2] as $id) {
            $data = apiRuntimeCall($vod, 'get_detail', ['vod_id'=>$id]);
            apiRuntimeExpect($data['code'] === 1 && $data['info']['vod_id'] === $id && $data['info']['vod_pic'] === ($id === 1 ? 'one.png' : 'two.png'), 'Valid detail IDs must select the requested database row');
        }
        apiRuntimeExpect(apiRuntimeCall($vod, 'get_detail', ['vod_id'=>999])['code'] === 1001, 'A valid but absent detail ID must keep the existing not-found contract');
        foreach ([3, 4] as $id) {
            apiRuntimeExpect(apiRuntimeCall($vod, 'get_detail', ['vod_id'=>$id])['code'] === 1001, 'Hidden and recycled video IDs must not resolve through the public detail endpoint');
        }

        foreach ([[[], [2,3,1]], [['orderby'=>''], [2,3,1]], [['orderby'=>'hits'], [1,3,2]], [['orderby'=>'id'], [3,2,1]]] as [$params, $ids]) {
            $data = apiRuntimeCall($art, 'get_list', $params);
            apiRuntimeExpect($data['code'] === 1 && $data['info']['total'] === 3 && array_column($data['info']['rows'], 'art_id') === $ids, 'Default/explicit article ordering must select real rows in the expected order');
        }
        foreach ([['orderby'=>'missing_column'], ['orderby'=>['hits']], ['limit'=>0]] as $params) {
            $data = apiRuntimeCall($art, 'get_list', $params);
            apiRuntimeExpect($data['code'] === 1001 && !isset($data['info']), 'Invalid article parameters must reach the JSON validation branch');
        }
        echo 'framework_audit_api_runtime: ' . $checks . ' checks passed on PHP ' . PHP_VERSION . PHP_EOL;
    } catch (Throwable $error) {
        fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . PHP_EOL . $error->getTraceAsString() . PHP_EOL);
        exit(1);
    }
}
