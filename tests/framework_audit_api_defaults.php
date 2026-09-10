<?php
/** Optional API parameters with populated real SQLite lists and real Request/validators. */
declare(strict_types=1);
namespace { require dirname(__DIR__) . '/vendor/autoload.php'; }
namespace app\common\controller { class All {} }
namespace app\common\model {
    // The manga page regression precedes its large reading/model pipeline; record this boundary only.
    class Manga extends Base {
        public function listData($where,$order,$page=1,$limit=20,$start=0,$field='*',$addition=1,$totalshow=1) {
            return ['code'=>1,'page'=>$page,'limit'=>$limit,'total'=>0,'list'=>[]];
        }
    }
}
namespace {
    error_reporting(E_ALL);
    set_error_handler(static function ($severity, $message, $file, $line) {
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    function lang($key, $vars = []) { return $key; }
    function config($name, $default = null) { return think\facade\Config::get($name, $default); }
    function json($data) { return new think\response\Json(new think\Cookie(think\Container::getInstance()->make('request')), $data); }
    function mac_api_norm_limit($limit) { return (int)$limit <= 10 ? 10 : 20; }
    $container = new think\Container();
    think\Container::setInstance($container);
    $container->bind(think\Request::class, 'request');
    $configuration = ['default'=>'audit','auto_timestamp'=>false,'connections'=>['audit'=>[
        'type'=>'sqlite','database'=>':memory:','prefix'=>'mac_','trigger_sql'=>false,'fields_cache'=>false,
    ]]];
    $config = new think\Config();
    $config->set($configuration, 'database');
    $container->instance('config', $config);
    $db = new think\DbManager();
    $db->setConfig($configuration);
    $container->instance('think\\DbManager', $db);
    $GLOBALS['config'] = ['app'=>['count_cache_sec'=>0]];
    foreach (['Gbook'=>'gbook_time','Link'=>'link_time','User'=>'user_reg_time','Website'=>'website_time'] as $name=>$time) {
        $prefix = strtolower($name);
        $columns = $name === 'Link' ? ', link_logo TEXT DEFAULT "", link_url TEXT DEFAULT ""' : '';
        if ($name === 'User') { $columns .= ', user_nick_name TEXT DEFAULT "", user_points INTEGER DEFAULT 0'; }
        think\facade\Db::execute('CREATE TABLE mac_' . $prefix . ' (' . $prefix . '_id INTEGER PRIMARY KEY, ' . $prefix . '_name TEXT, ' . $time . ' INTEGER' . $columns . ')');
        think\facade\Db::name($name)->insertAll([
            [$prefix.'_id'=>1,$prefix.'_name'=>'newest',$time=>300],
            [$prefix.'_id'=>2,$prefix.'_name'=>'oldest',$time=>100],
        ]);
    }
    $checks = 0;
    function defaultsExpect($condition, string $message): void {
        global $checks;
        ++$checks;
        if (!$condition) { throw new RuntimeException($message); }
    }
    function defaultsCall(string $name, array $params): array {
        $request = (new think\Request())->withGet($params)->setController($name)->setAction('get_list');
        $container = think\Container::getInstance();
        $container->instance('request', $request);
        $controller = (new ReflectionClass('app\\api\\controller\\' . $name))->newInstanceWithoutConstructor();
        return $container->invokeMethod([$controller,'get_list'])->getData();
    }
    try {
        $failures = [];
        foreach (['Gbook','Link','User','Website','Manga'] as $name) {
            try { defaultsExpect(defaultsCall($name, [])['code'] === 1, "$name defaults must succeed"); }
            catch (Throwable $error) { $failures[] = $name . ': ' . $error->getMessage(); }
        }
        defaultsExpect($failures === [], implode("\n", $failures));
        foreach (['Gbook','Link','User','Website'] as $name) {
            $prefix = strtolower($name);
            foreach ([[],['orderby'=>''],['orderby'=>$name === 'User' ? 'reg_time' : 'time']] as $params) {
                $data = defaultsCall($name,$params);
                defaultsExpect($data['code'] === 1 && $data['info']['total'] === 2 && array_column($data['info']['rows'],$prefix.'_id') === [1,2], "$name missing/empty/explicit time ordering must return real rows newest first");
            }
        }
        foreach ([[],['page'=>1],['page'=>3]] as $params) {
            $data = defaultsCall('Manga',$params);
            defaultsExpect($data['code'] === 1 && $data['page'] === ($params['page'] ?? 1), 'Manga must pass default page 1 or the requested page to its list model');
        }
        echo 'framework_audit_api_defaults: ' . $checks . ' checks passed on PHP ' . PHP_VERSION . PHP_EOL;
    } catch (Throwable $error) {
        fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . PHP_EOL . $error->getTraceAsString() . PHP_EOL);
        exit(1);
    }
}
