<?php
/** Real Type API, Request, validation and ORM. SQLite or only maccms_audit_http/audit_nav_type. */
declare(strict_types=1);
namespace app\common\controller { class All {} }
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($severity, $message, $file, $line) {
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    function config($name, $default = null) { return think\facade\Config::get($name, $default); }
    function json($data) { return new think\response\Json(new think\Cookie(think\Container::getInstance()->make('request')), $data); }
    function mac_url_type($row, $params = [], $flag = 'type') { return '/' . $flag . '/' . $row['type_id']; }
    $mysql = getenv('FRAMEWORK_AUDIT_MYSQL') === '1';
    $container = new think\Container();
    think\Container::setInstance($container);
    $container->bind(think\Request::class, 'request');
    $configuration = ['default'=>'audit', 'auto_timestamp'=>false, 'connections'=>['audit'=>[
        'type'=>$mysql ? 'mysql' : 'sqlite', 'database'=>$mysql ? 'maccms_audit_http' : ':memory:',
        'hostname'=>getenv('FRAMEWORK_AUDIT_HOST') ?: '127.0.0.1', 'username'=>'root',
        'password'=>getenv('FRAMEWORK_AUDIT_PASSWORD') ?: '', 'charset'=>'utf8mb4',
        'prefix'=>'audit_nav_', 'trigger_sql'=>false, 'fields_cache'=>false,
    ]]];
    $config = new think\Config();
    $config->set($configuration, 'database');
    $container->instance('config', $config);
    $db = new think\DbManager();
    $db->setConfig($configuration);
    $container->instance('think\\DbManager', $db);
    $GLOBALS['config'] = ['app'=>['count_cache_sec'=>0]];
    $schema = ' (type_id INTEGER PRIMARY KEY, type_pid INTEGER, type_mid INTEGER, type_sort INTEGER, type_name VARCHAR(100), type_en VARCHAR(100), type_extend TEXT)';
    think\facade\Db::execute('DROP TABLE IF EXISTS audit_nav_type');
    think\facade\Db::execute('CREATE TABLE audit_nav_type' . $schema);
    if (!$mysql) {
        // A decoy table makes hardcoded mac_type reads observable instead of just raising missing-table.
        think\facade\Db::execute('CREATE TABLE mac_type' . $schema);
        think\facade\Db::table('mac_type')->insert(['type_id'=>999,'type_pid'=>0,'type_mid'=>9,'type_sort'=>1,'type_name'=>'wrong prefix','type_en'=>'decoy','type_extend'=>'']);
    }
    think\facade\Db::name('Type')->insertAll([
        ['type_id'=>1,'type_pid'=>0,'type_mid'=>1,'type_sort'=>10,'type_name'=>'Video','type_en'=>'video','type_extend'=>'{"area":"CN"}'],
        ['type_id'=>2,'type_pid'=>0,'type_mid'=>2,'type_sort'=>20,'type_name'=>'Article','type_en'=>'article','type_extend'=>''],
        ['type_id'=>3,'type_pid'=>1,'type_mid'=>1,'type_sort'=>2,'type_name'=>'Second child','type_en'=>'second','type_extend'=>''],
        ['type_id'=>4,'type_pid'=>1,'type_mid'=>1,'type_sort'=>1,'type_name'=>'First child','type_en'=>'first','type_extend'=>'{"year":"2026"}'],
        ['type_id'=>5,'type_pid'=>2,'type_mid'=>2,'type_sort'=>3,'type_name'=>'Article child','type_en'=>'artchild','type_extend'=>''],
    ]);
    $checks = 0;
    function navExpect($condition, string $message): void {
        global $checks;
        ++$checks;
        if (!$condition) { throw new RuntimeException($message); }
    }
    function navCall(string $action, array $params = []): array {
        $request = (new think\Request())->withGet($params)->setController('Type')->setAction($action);
        $container = think\Container::getInstance();
        $container->instance('request', $request);
        $controller = (new ReflectionClass(app\api\controller\Type::class))->newInstanceWithoutConstructor();
        $response = $container->invokeMethod([$controller, $action]);
        return json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);
    }
    try {
        $failures = [];
        foreach (['get_nav_types'=>['parent'=>1], 'get_type_with_children'=>['type_id'=>1]] as $action=>$params) {
            try { navExpect(navCall($action,$params)['code'] === 1, "$action must handle real query collections"); }
            catch (Throwable $error) { $failures[] = "$action: " . $error->getMessage(); }
        }
        navExpect($failures === [], implode("\n",$failures));
        $rows = navCall('get_nav_types',['parent'=>1])['info']['rows'];
        navExpect(array_column($rows,'type_id') === [1,2], 'Parent rows must honor the configured non-mac_ prefix and order');
        navExpect(array_column($rows[0]['children'],'type_id') === [4,3], 'The parent ID batch must include real children in sort order');
        navExpect(array_column($rows[1]['children'],'type_id') === [5], 'Each parent must receive only its own children');
        navExpect($rows[0]['type_extend'] === ['area'=>'CN'] && $rows[0]['children'][0]['type_extend'] === ['year'=>'2026'], 'Parent and child extension JSON must be decoded');
        navExpect($rows[1]['type_extend'] === [] && $rows[0]['children'][1]['type_extend'] === [], 'Empty extension fields must remain arrays');
        foreach ([
            [['ids'=>'1'],[1]], [['ids'=>' 2, 1 '],[1,2]], [['ids'=>1],[1]],
            [['parent'=>1,'mid'=>2],[2]], [['parent'=>1,'num'=>1],[1]], [[],[4,3,5,1,2]],
        ] as [$params,$ids]) {
            $data = navCall('get_nav_types',$params);
            navExpect($data['code'] === 1 && $data['info']['total'] === count($ids) && array_column($data['info']['rows'],'type_id') === $ids, 'Navigation ID/mid/parent/limit filters must select the expected rows');
        }
        foreach ([['link_flag'=>'show','expected'=>'show'],['link_flag'=>'bad','expected'=>'type'],['link_flag'=>' type ','expected'=>'type']] as $case) {
            $row = navCall('get_nav_types',['ids'=>'1','link_flag'=>$case['link_flag']])['info']['rows'][0];
            navExpect($row['type_link'] === '/'.$case['expected'].'/1' && $row['children'][0]['type_link'] === '/'.$case['expected'].'/4', 'The selected/fallback link flag must reach both parent and child URL generation');
        }
        $empty = navCall('get_nav_types',['ids'=>'9999']);
        navExpect($empty['code'] === 1 && $empty['info'] === ['total'=>0,'rows'=>[]], 'An empty match set must serialize as a list');
        $detail = navCall('get_type_with_children',['type_id'=>1,'num'=>1]);
        navExpect($detail['info']['type_id'] === 1 && array_column($detail['info']['children'],'type_id') === [4], 'Parent detail and limited children must use the configured prefix');
        navExpect(navCall('get_type_with_children',['type_id'=>9999])['code'] === 1002, 'Missing parents must keep the not-found contract');
        navExpect(navCall('get_type_with_children',[])['code'] === 1001, 'The parent ID remains required');
        foreach (['ids','num','mid','parent','link_flag'] as $field) {
            navExpect(navCall('get_nav_types',[$field=>['bad']])['code'] === 1001, 'Array '.$field.' must be rejected before trimming/casting');
        }
        foreach ([['ids'=>'1,bad'],['num'=>-1],['mid'=>'bad'],['parent'=>2]] as $params) {
            navExpect(navCall('get_nav_types',$params)['code'] === 1001, 'Malformed navigation filters must follow the JSON validation branch');
        }
        foreach ([['type_id'=>[1]],['type_id'=>1,'num'=>[1]]] as $params) {
            navExpect(navCall('get_type_with_children',$params)['code'] === 1001, 'Malformed parent/limit parameters must not be silently coerced');
        }
        $list = navCall('get_list');
        navExpect(array_column($list['info']['rows'],'type_id') === [2,1] && array_column($list['info']['rows'][1]['child'],'type_id') === [3,4], 'The existing type-tree child query must also honor the configured prefix');
        $all = navCall('get_all_list');
        navExpect($all['info']['total'] === 2, 'The basic category endpoint must use the same table prefix');
        echo 'framework_audit_type_navigation: ' . $checks . ' checks passed on PHP ' . PHP_VERSION . ' / ' . ($mysql ? 'MySQL' : 'SQLite') . PHP_EOL;
    } catch (Throwable $error) {
        fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . PHP_EOL . $error->getTraceAsString() . PHP_EOL);
        $failed = true;
    } finally {
        think\facade\Db::execute('DROP TABLE audit_nav_type');
    }
    exit(empty($failed) ? 0 : 1);
}
