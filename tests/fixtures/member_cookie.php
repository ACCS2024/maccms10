<?php
/** Real account/group DDL and native Cookie service; fixture helpers isolate decoration and throttling only. */
namespace app\common\model {
    function mac_fe_write_throttle(...$args){return true;}
    function mac_get_ip_long(){return 0;}
    function mac_get_user_portrait($id){return '/fixture-portrait.jpg';}
}
namespace {
require dirname(__DIR__,2).'/vendor/autoload.php';
require dirname(__DIR__,2).'/application/common.php';
require __DIR__.'/security_audit_test_helpers.php';
use think\facade\Db;
function lang($key,...$values){return $key;}
function request(){return think\Container::getInstance()->make('request');}
function config($key,$default=null){return think\facade\Config::get($key,$default);}
function cookie($name,...$args){$cookie=think\Container::getInstance()->make('cookie');if(!$args)return $cookie->get($name);return $cookie->set($name,(string)$args[0],$args[1]??null);}
$memberCookieHttp=defined('MEMBER_COOKIE_HTTP');
$temp=$memberCookieHttp?getcwd():audit_temp_dir('member-cookie');
if(!$memberCookieHttp)register_shutdown_function(static function()use($temp):void{audit_remove_temp($temp);});
$app=new think\App($temp.'/app');$app->setRuntimePath($temp.'/runtime/');
$mysql=getenv('MEMBER_COOKIE_MYSQL')==='1';
$connection=['type'=>$mysql?'mysql':'sqlite','database'=>$mysql?'maccms_audit_member_cookie':$temp.'/member.sqlite',
    'hostname'=>getenv('FRAMEWORK_AUDIT_HOST')?:'127.0.0.1','username'=>'root','password'=>getenv('FRAMEWORK_AUDIT_PASSWORD')?:'',
    'prefix'=>'cookie_audit_','charset'=>'utf8mb4','fields_cache'=>false,'trigger_sql'=>true];
if($mysql&&!$memberCookieHttp){
    $pdo=new PDO('mysql:host='.$connection['hostname'].';charset=utf8mb4','root',$connection['password'],[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $pdo->exec('CREATE DATABASE IF NOT EXISTS maccms_audit_member_cookie CHARACTER SET utf8mb4');$pdo=null;
}
$database=['default'=>'audit','auto_timestamp'=>false,'connections'=>['audit'=>$connection]];
$app->config->set($database,'database');$manager=new think\DbManager();$manager->setConfig($database);$app->instance('think\\DbManager',$manager);
$GLOBALS['member_cookie_writes']=0;Db::listen(static function($sql):void{if(preg_match('/^\s*(UPDATE|INSERT|DELETE)\b/i',$sql))$GLOBALS['member_cookie_writes']++;});
$app->config->set(['default'=>'file','stores'=>['file'=>['type'=>'File','path'=>$temp.'/cache/']]],'cache');
$app->config->set(['path'=>'/','httponly'=>true,'secure'=>false,'samesite'=>'Lax'],'cookie');
$app->instance('log',new class{public function record(...$args){}public function error(...$args){}});
$GLOBALS['config']=['app'=>['cache_flag'=>'member-cookie','api_jwt_enabled'=>1,'api_jwt_secret'=>str_repeat('isolated-cookie-',4),'api_jwt_iss'=>'member-cookie'],
    'user'=>['status'=>1,'login_verify'=>0]];
if($mysql)Db::execute("SET SESSION sql_mode=''");
if(!$memberCookieHttp){
    $ddl=file_get_contents(dirname(__DIR__,2).'/application/install/sql/install.sql');
    foreach(['user','group']as $table){
        if(!preg_match('/CREATE TABLE `mac_'.$table.'` \(([\s\S]*?)\) ENGINE[^;]*;/',$ddl,$match))throw new RuntimeException('Member Cookie install schema missing');
        Db::execute('DROP TABLE IF EXISTS cookie_audit_'.$table);
        if($mysql){Db::execute(str_replace('`mac_'.$table.'`','`cookie_audit_'.$table.'`',$match[0]));continue;}
        $columns=[];
        foreach(explode("\n",$match[1])as $line){
            if(!preg_match('/^\s*`([^`]+)`\s+([^ ]+)(.*)$/',$line,$field))continue;
            [$unused,$name,$type,$options]=$field;
            if(str_contains($options,'AUTO_INCREMENT')){$columns[]=$name.' INTEGER PRIMARY KEY AUTOINCREMENT';continue;}
            $column=$name.(str_contains($type,'int')?' INTEGER':' TEXT');
            if(str_contains($options,'NOT NULL'))$column.=' NOT NULL';
            if(preg_match("/DEFAULT ('[^']*'|[0-9]+)/",$options,$default))$column.=' DEFAULT '.$default[1];
            if(preg_match('/varchar\(([0-9]+)\)/',$type,$length))$column.=' CHECK(length('.$name.')<='.$length[1].')';
            $columns[]=$column;
        }
        Db::execute('CREATE TABLE cookie_audit_'.$table.' ('.implode(',',$columns).')');
    }
}
function memberCookieRequest(array $values=[],array $headers=[]):void{
    global $app;
    $request=(new \app\Request())->withCookie($values)->withHeader($headers)->withServer(['REQUEST_METHOD'=>'GET']);
    $app->instance('request',$request);$app->instance('cookie',new think\Cookie($request,$app->config->get('cookie')));
}
function memberCookieSeed(string $name='member'):void{
    Db::execute('DELETE FROM cookie_audit_user');Db::execute('DELETE FROM cookie_audit_group');
    $groups=[];foreach([1,2,3]as $id){$group=['group_id'=>$id,'group_name'=>'Fixture '.$id,'group_type'=>'','group_popedom'=>'{}','group_status'=>1];Db::name('Group')->insert($group);$group['group_popedom']=[];$groups[$id]=$group;}
    think\facade\Cache::set('member-cookie_group_list',$groups);
    Db::name('User')->insert(['user_id'=>1,'user_name'=>$name,'user_email'=>'cookie-fixture@example.test','user_pwd'=>password_hash('fixture-password',PASSWORD_DEFAULT),
        'user_status'=>1,'group_id'=>'2','user_points'=>100]);
    memberCookieRequest();
}
function memberCookieState():array{return Db::name('User')->order('user_id')->select()->toArray();}
if($memberCookieHttp){
    $request=\app\Request::__make($app);$app->instance('request',$request);$app->instance('cookie',new think\Cookie($request,$app->config->get('cookie')));
}
}
