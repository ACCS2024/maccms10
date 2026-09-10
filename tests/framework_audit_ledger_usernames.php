<?php
/** Actual Plog/Cash list models and bounded SQL projections; dedicated SQLite/MySQL tables. */
require dirname(__DIR__).'/vendor/autoload.php';
error_reporting(E_ALL);
set_error_handler(static function ($level,$message,$file,$line) { throw new ErrorException($message,0,$level,$file,$line); });
function lang($key,$vars=[]) { return $key; }
function mac_array_rekey($rows,$key) { return array_column($rows,null,$key); }
$mysql = getenv('FRAMEWORK_AUDIT_MYSQL') === '1';
$container = new think\Container(); think\Container::setInstance($container);
$configuration = ['default'=>'audit','auto_timestamp'=>false,'connections'=>['audit'=>[
    'type'=>$mysql?'mysql':'sqlite','database'=>$mysql?'maccms_audit_models':':memory:',
    'hostname'=>getenv('FRAMEWORK_AUDIT_HOST')?:'127.0.0.1','username'=>'root','password'=>getenv('FRAMEWORK_AUDIT_PASSWORD')?:'',
    'prefix'=>'audit_ledger_names_','charset'=>'utf8mb4','fields_cache'=>false,'trigger_sql'=>true,
]]];
$config=new think\Config();$config->set($configuration,'database');$container->instance('config',$config);
$db=new think\DbManager();$db->setConfig($configuration);$container->instance('think\\DbManager',$db);
$sqls=[];$db->listen(static function($sql)use(&$sqls){$sqls[]=$sql;});
$checks=0;
function verify($ok,$message) {global $checks;++$checks;if(!$ok){throw new RuntimeException($message);}}
function readNames($model,$where,$page=1,$limit=20) {
    global $sqls;$sqls=[];$class='app\\common\\model\\'.$model;
    $result=(new $class())->listData($where,strtolower($model).'_id asc',$page,$limit);
    $queries=array_values(array_filter($sqls,static fn($sql)=>preg_match('/^SELECT\b.*\bFROM\s+[`"]?audit_ledger_names_user[`"]?(?:\s|$)/i',$sql)));
    return [$result,$queries];
}
try {
    foreach(['user'=>'user_id INTEGER PRIMARY KEY,user_name VARCHAR(100),user_pwd VARCHAR(100)',
             'plog'=>'plog_id INTEGER PRIMARY KEY,user_id INTEGER','cash'=>'cash_id INTEGER PRIMARY KEY,user_id INTEGER'] as $table=>$fields) {
        think\facade\Db::execute('DROP TABLE IF EXISTS audit_ledger_names_'.$table);
        think\facade\Db::execute('CREATE TABLE audit_ledger_names_'.$table.' ('.$fields.')');
    }
    think\facade\Db::name('User')->insertAll([['user_id'=>1,'user_name'=>'Owner'],['user_id'=>2,'user_name'=>'Other']]);
    $users=[];for($id=1000;$id<=2000;++$id){$users[]=['user_id'=>$id,'user_name'=>'User '.$id];}
    foreach(array_chunk($users,100) as $chunk){think\facade\Db::name('User')->insertAll($chunk);}
    foreach(['Plog','Cash'] as $model) {
        $prefix=strtolower($model);
        foreach([[1,1],[2,2],[3,1],[4,99],[5,0]] as [$id,$uid]){think\facade\Db::name($model)->insert([$prefix.'_id'=>$id,'user_id'=>$uid]);}
        [$missing,$queries]=readNames($model,[$prefix.'_id'=>[4,5]]);
        verify(array_column($missing['list'],'user_name')===['',''],'Missing users/guests must not raise strict errors');
        [$mixed,$queries]=readNames($model,[$prefix.'_id'=>[1,2,3]]);
        verify(array_column($mixed['list'],'user_name')===['Owner','Other','Owner'],'Current row mapping changed');
        verify(count($queries)===1,'Username lookup must use one projection without a separate user count');
        $rows=think\facade\Db::query($queries[0]);
        verify(array_column($rows,'user_id')==[1,2],'User SQL must remain scoped to current-page distinct IDs');
        foreach($rows as $row){$fields=array_keys($row);sort($fields);verify($fields===['user_id','user_name'],'User SQL fetched private/unrelated fields');}
        [$page,$queries]=readNames($model,[$prefix.'_id'=>[1,2,3]],2,1);
        verify($page['total']===3 && array_column($page['list'],'user_name')===['Other'],'Page selection changed');
        verify(count($queries)===1 && array_column(think\facade\Db::query($queries[0]),'user_id')===[2],'Pagination fetched another page’s usernames');
        foreach([['user_id'=>0],[$prefix.'_id'=>999999]] as $where){[$result,$queries]=readNames($model,$where);verify($queries===[],'Empty/guest-only result fetched users');}
        $logs=[];foreach($users as $user){$logs[]=[$prefix.'_id'=>$user['user_id'],'user_id'=>$user['user_id']];}
        foreach(array_chunk($logs,100)as$chunk){think\facade\Db::name($model)->insertAll($chunk);}
        [$large,$queries]=readNames($model,[[$prefix.'_id','>=',1000]],1,1001);
        verify(count($large['list'])===1001 && $large['list'][0]['user_name']==='User 1000' && $large['list'][1000]['user_name']==='User 2000','Large page retained a 999-user cutoff');
        verify(count($queries)===1 && count(think\facade\Db::query($queries[0]))===1001,'Large-page query changed scope');
    }
    echo "Ledger usernames: $checks checks passed on PHP ".PHP_VERSION.' / '.($mysql?'MySQL':'SQLite')."\n";
} finally {foreach(['plog','cash','user'] as $table){think\facade\Db::execute('DROP TABLE IF EXISTS audit_ledger_names_'.$table);}}
