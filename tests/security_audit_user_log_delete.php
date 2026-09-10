<?php
/** Real frontend deletion actions, Request and ORM; authentication/rendering are isolated. */
namespace app\index\controller { class Base {} }
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) { throw new \ErrorException($message, 0, $level, $file, $line); });
    function lang($key, $vars = []) { return $key; }
    function request() { return \think\Container::getInstance()->make('request'); }
    function json($value) { return new \think\response\Json(new \think\Cookie(request()), $value); }
    $mysql = getenv('FRAMEWORK_AUDIT_MYSQL') === '1';
    $container = new \think\Container(); \think\Container::setInstance($container);
    $configuration = ['default'=>'audit','auto_timestamp'=>false,'connections'=>['audit'=>[
        'type'=>$mysql ? 'mysql':'sqlite','database'=>$mysql ? 'maccms_audit_models':':memory:',
        'hostname'=>getenv('FRAMEWORK_AUDIT_HOST') ?: '127.0.0.1','username'=>'root','password'=>getenv('FRAMEWORK_AUDIT_PASSWORD') ?: '',
        'prefix'=>'audit_log_delete_','charset'=>'utf8mb4','fields_cache'=>false,
    ]]];
    $config = new \think\Config(); $config->set($configuration,'database'); $container->instance('config',$config);
    $db = new \think\DbManager(); $db->setConfig($configuration); $container->instance('think\\DbManager',$db);
    $checks = 0;
    function verify($ok, string $message): void { global $checks; ++$checks; if (!$ok) { throw new \RuntimeException($message); } }
    function seedLogs($model): void {
        \think\facade\Db::name($model)->delete(true);
        $prefix = strtolower($model);
        foreach ([[1,1,2],[2,1,4],[3,2,2],[4,1,2]] as [$id,$owner,$type]) {
            \think\facade\Db::name($model)->insert([$prefix.'_id'=>$id,'user_id'=>$owner,$prefix.'_type'=>$type]);
        }
        $GLOBALS['user'] = ['user_id'=>1];
    }
    function state($model): array {
        $query = \think\facade\Db::name($model)->order(strtolower($model).'_id');
        if ($model === 'Plog') { $query->where('plog_user_hidden', 0); }
        return $query->select()->toArray();
    }
    function deletion($model, array $params, string $method = 'POST'): array {
        $request = (new \think\Request())->withServer(['REQUEST_METHOD'=>$method])->withPost($params)->withGet($params);
        \think\Container::getInstance()->instance('request',$request);
        $controller = (new \ReflectionClass(\app\index\controller\User::class))->newInstanceWithoutConstructor();
        return $controller->{strtolower($model).'_del'}()->getData();
    }
    try {
        foreach (['Ulog','Plog'] as $model) {
            $prefix = strtolower($model);
            \think\facade\Db::execute('DROP TABLE IF EXISTS audit_log_delete_'.$prefix);
            \think\facade\Db::execute('CREATE TABLE audit_log_delete_'.$prefix.' ('.$prefix.'_id INTEGER PRIMARY KEY,user_id INTEGER,'.$prefix.'_type INTEGER'.($model === 'Plog' ? ',plog_user_hidden INTEGER NOT NULL DEFAULT 0' : '').')');
            seedLogs($model);
            $result = deletion($model,['ids'=>'1,3,4','type'=>'2','all'=>'0']);
            verify($result['code'] === 1 && array_column(state($model),$prefix.'_id') === [2,3], 'Selected deletion must remove only owned IDs, preserving foreign rows');
            seedLogs($model);
            $result = deletion($model,['ids'=>'1,2','type'=>'2']);
            verify($result['code'] === 1 && array_column(state($model),$prefix.'_id') === ($model === 'Ulog' ? [2,3,4]:[3,4]), 'Type scope or omitted all flag changed');
            seedLogs($model);
            verify(deletion($model,['all'=>'1','type'=>'2'])['code'] === 1 && array_column(state($model),$prefix.'_id') === ($model === 'Ulog' ? [2,3]:[3]), 'Delete-all must retain ownership and Ulog type constraints');
            foreach ([[],['ids'=>[]],['ids'=>'1,,2'],['ids'=>'-1'],['ids'=>'1.0'],['ids'=>'1x'],['ids'=>'0'],['ids'=>'4294967296'],['ids'=>true],['ids'=>'1','all'=>[]],['ids'=>'1','all'=>'garbage'],['ids'=>implode(',',range(1,1001))]] as $bad) {
                seedLogs($model); $before = state($model);
                verify(deletion($model,$bad+['type'=>'2'])['code'] !== 1 && state($model) === $before, 'Invalid deletion input mutated rows');
            }
            seedLogs($model); $before = state($model);
            verify(deletion($model,['ids'=>'1','type'=>'2'],'GET')['code'] !== 1 && state($model) === $before, 'GET deleted logs');
            seedLogs($model);
            verify(deletion($model,['ids'=>' 1, 1, 4 ','type'=>'2'])['code'] === 1 && array_column(state($model),$prefix.'_id') === [2,3], 'Whitespace/duplicate valid IDs changed selection');
        }
        foreach ([[], '0', '6', '2x', true] as $type) {
            seedLogs('Ulog'); $before = state('Ulog');
            verify(deletion('Ulog',['ids'=>'1','type'=>$type])['code'] !== 1 && state('Ulog') === $before, 'Invalid Ulog type deleted rows');
        }
        echo "User log deletion: $checks checks passed on PHP " . PHP_VERSION . ' / ' . ($mysql ? 'MySQL':'SQLite') . "\n";
    } finally {
        foreach (['ulog','plog'] as $table) { \think\facade\Db::execute('DROP TABLE IF EXISTS audit_log_delete_'.$table); }
    }
}
