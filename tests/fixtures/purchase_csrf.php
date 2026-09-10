<?php
/** Real authentication/session/controllers/financial/Vod/Art ORM. Manga mode adds its actual schema in a dedicated database. */
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
require dirname(__DIR__,2).'/application/common.php';
require __DIR__.'/security_audit_test_helpers.php';
use think\facade\Db;
function lang($key,...$values){
    if($key!=='index/buy_popedom3')return $key;
    $english=require dirname(__DIR__,2).'/application/lang/en-us.php';
    return vsprintf($english[$key],$values[0]);
}
function config($key,$default=null){return think\facade\Config::get($key,$default);}
function request(){return think\Container::getInstance()->make('request');}
function json($data){return think\Response::create($data,'json');}
function cookie($name,...$args){$cookie=think\Container::getInstance()->make('cookie');if(!$args)return $cookie->get($name);return $cookie->set($name,(string)$args[0],$args[1]??null);}
function session($name,...$args){$session=think\Container::getInstance()->make('session');if(!$args)return $session->get($name);return $session->set($name,$args[0]);}
function mac_validate($name){$class='app\\common\\validate\\'.$name;return new $class();}
if(!defined('ENTRANCE'))define('ENTRANCE','index');
if(!defined('MAC_PLAYER_SORT'))define('MAC_PLAYER_SORT','1');
class PurchaseCsrfIndex extends \app\index\controller\User {
    protected function label_maccms(){}
    protected function check_ip_limit(){}
    protected function check_site_status(){}
    protected function check_browser_jump(){}
    protected function assign($name,$value=''):void{}
}
class PurchaseCsrfPayment extends \app\api\controller\Payment {
    protected function assign($name,$value=''):void{}
}
class PurchaseCsrfMetadata {
    public function infoData($where,...$args){
        $GLOBALS['purchase_resource_reads']++;
        return ['code'=>1,'info'=>['vod_points'=>40,'vod_points_play'=>20,'vod_points_down'=>30,
            'art_points'=>40,'art_points_detail'=>20,'manga_points'=>40,'manga_points_detail'=>20]];
    }
}
if(getenv('MANGA_PURCHASE_AUDIT')!=='1')foreach(['Manga'] as $name)class_alias(PurchaseCsrfMetadata::class,'app\\common\\model\\'.$name);
class PurchaseCsrfRequest extends \app\Request {public function isCli():bool{return false;}}
$purchaseHttp=defined('PURCHASE_CSRF_HTTP');
$purchaseTemp=$purchaseHttp?getcwd():audit_temp_dir('purchase-csrf');
if(!defined('ROOT_PATH'))define('ROOT_PATH',$purchaseTemp.'/');
if(!defined('MAC_PATH'))define('MAC_PATH','/fixture/');
if(!$purchaseHttp)register_shutdown_function(static function()use($purchaseTemp):void{audit_remove_temp($purchaseTemp);});
$app=new \think\App($purchaseTemp.'/app');
$mysql=getenv('PURCHASE_CSRF_MYSQL')==='1';
$purchaseDatabase=getenv('MANGA_PURCHASE_AUDIT')==='1'?'maccms_audit_manga_purchase':'maccms_audit_purchase_csrf';
$connection=['type'=>$mysql?'mysql':'sqlite','database'=>$mysql?$purchaseDatabase:($purchaseHttp?$purchaseTemp.'/purchase.sqlite':':memory:'),
    'prefix'=>'audit_','trigger_sql'=>true,'fields_cache'=>false,'charset'=>'utf8mb4',
    'hostname'=>getenv('FRAMEWORK_AUDIT_HOST')?:'127.0.0.1','username'=>'root','password'=>getenv('FRAMEWORK_AUDIT_PASSWORD')?:''];
if($mysql){
    $pdo=new PDO('mysql:host='.$connection['hostname'].';charset=utf8mb4','root',$connection['password'],[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $pdo->exec('CREATE DATABASE IF NOT EXISTS `'.$purchaseDatabase.'` CHARACTER SET utf8mb4');$pdo=null;
}
$configuration=['default'=>'audit','auto_timestamp'=>false,'connections'=>['audit'=>$connection]];
$app->config->set($configuration,'database');$manager=new \think\DbManager();$manager->setConfig($configuration);$app->instance('think\\DbManager',$manager);
Db::listen(static function($sql):void{if(preg_match('/\bFROM\s+[`"]?audit_(?:vod|art|manga)\b/i',$sql))$GLOBALS['purchase_resource_reads']++;});
$app->config->set(['type'=>'file','name'=>'fixture_session','path'=>$purchaseTemp.'/sessions','expire'=>3600,'var_session_id'=>''],'session');
$app->config->set(['default'=>'file','stores'=>['file'=>['type'=>'File','path'=>$purchaseTemp.'/cache/']]],'cache');
$app->instance('log',new class{public function record(...$args){}public function error(...$args){}});
$app->instance(\think\exception\Handle::class,new class($app)extends \think\exception\Handle{public function render(\think\Request $request,\Throwable $error):\think\Response{throw $error;}});
$app->bind(\app\index\controller\User::class,PurchaseCsrfIndex::class);$app->bind(\app\api\controller\Payment::class,PurchaseCsrfPayment::class);
if($mysql)Db::execute("SET SESSION sql_mode=''");
if(!defined('PURCHASE_CSRF_EXISTING_DB')&&(!$purchaseHttp||!is_file($purchaseTemp.'/schema.ready'))){
    $ddl=file_get_contents(dirname(__DIR__,2).'/application/install/sql/install.sql');
    foreach(array_merge(['user','group','plog','ulog','vod','art'],getenv('MANGA_PURCHASE_AUDIT')==='1'?['manga']:[])as $table){
        if(!preg_match('/CREATE TABLE `mac_'.$table.'` \(([\s\S]*?)\) ENGINE[^;]*;/',$ddl,$match))throw new RuntimeException('Purchase install schema missing');
        Db::execute('DROP TABLE IF EXISTS audit_'.$table);
        if($mysql){Db::execute(str_replace('`mac_'.$table.'`','`audit_'.$table.'`',$match[0]));continue;}
        $columns=[];
        foreach(explode("\n",$match[1])as $line){
            if(!preg_match('/^\s*`([^`]+)`\s+([^ ]+)(.*)$/',$line,$field))continue;
            [$unused,$name,$type,$options]=$field;
            if(str_contains($options,'AUTO_INCREMENT')){$columns[]=$name.' INTEGER PRIMARY KEY AUTOINCREMENT';continue;}
            $column=$name.(str_contains($type,'int')?' INTEGER':' TEXT');
            if(str_contains($options,'NOT NULL'))$column.=' NOT NULL';
            if(preg_match("/DEFAULT ('[^']*'|[0-9]+)/",$options,$default))$column.=' DEFAULT '.$default[1];
            if(str_contains($options,'unsigned')){
                $max=match(true){str_starts_with($type,'tinyint')=>255,str_starts_with($type,'smallint')=>65535,str_starts_with($type,'mediumint')=>16777215,default=>4294967295};
                $column.=' CHECK('.$name.' BETWEEN 0 AND '.$max.')';
            }
            if(preg_match('/varchar\(([0-9]+)\)/',$type,$length))$column.=' CHECK(length('.$name.') <= '.$length[1].')';
            $columns[]=$column;
        }
        Db::execute('CREATE TABLE audit_'.$table.' ('.implode(',',$columns).')');
    }
    if($purchaseHttp)file_put_contents($purchaseTemp.'/schema.ready','ready');
}
function purchaseCsrfConfig():void{
    global $app;
    $GLOBALS['config']=['site'=>['site_status'=>1,'install_dir'=>'/fixture/'],'api'=>['publicapi'=>['status'=>1,'charge'=>0]],
        'upload'=>['mode'=>'local','protocol'=>'https','remoteurl'=>'','img_key'=>'','img_api'=>''],
        'app'=>['cache_flag'=>'purchase_csrf','api_jwt_enabled'=>1,'api_jwt_secret'=>str_repeat('fixture-signing-',4),'api_jwt_iss'=>'purchase-fixture'],
        'user'=>['status'=>1,'trysee'=>0,'reward_status'=>1,'reward_ratio'=>10,'reward_ratio_2'=>5,'reward_ratio_3'=>5,'vod_points_type'=>0,'art_points_type'=>0,'manga_points_type'=>0]];
    $app->config->set($GLOBALS['config'],'maccms');$GLOBALS['purchase_resource_reads']=0;
    $players=['primary'=>['from'=>'primary','show'=>'Primary','status'=>1,'sort'=>2],'secondary'=>['from'=>'secondary','show'=>'Secondary','status'=>1,'sort'=>1]];
    $app->config->set($players,'vodplayer');$app->config->set($players,'voddowner');$app->config->set([],'vodserver');
}
function purchaseCsrfVod(array $changes=[]):array{
    static $defaults;
    if($defaults===null){
        $ddl=file_get_contents(dirname(__DIR__,2).'/application/install/sql/install.sql');
        preg_match('/CREATE TABLE `mac_vod` \(([\s\S]*?)\) ENGINE[^;]*;/',$ddl,$match);$defaults=[];
        foreach(explode("\n",$match[1])as $line){
            if(preg_match('/^\s*`([^`]+)`\s+([^ ]+)(.*)$/',$line,$field)){
                if(preg_match("/DEFAULT ('([^']*)'|[0-9]+)/",$field[3],$value))$defaults[$field[1]]=str_starts_with($value[1],"'")?$value[2]:(int)$value[1];
                else $defaults[$field[1]]=str_contains($field[2],'int')?0:'';
            }
        }
    }
    $urls='One$https://fixture.invalid/VIDEO-ONE#Two$https://fixture.invalid/VIDEO-TWO#Three$https://fixture.invalid/VIDEO-THREE';
    return $changes+['vod_id'=>17,'vod_name'=>'Fixture video','vod_status'=>1,'type_id'=>1,'vod_points'=>40,'vod_points_play'=>20,'vod_points_down'=>30,
        'vod_play_from'=>'primary$$$secondary','vod_play_url'=>$urls.'$$$'.$urls,'vod_down_from'=>'primary$$$secondary','vod_down_url'=>$urls.'$$$'.$urls]+$defaults;
}
function purchaseCsrfArt(array $changes=[]):array{
    static $defaults;
    if($defaults===null){
        $ddl=file_get_contents(dirname(__DIR__,2).'/application/install/sql/install.sql');
        preg_match('/CREATE TABLE `mac_art` \(([\s\S]*?)\) ENGINE[^;]*;/',$ddl,$match);$defaults=[];
        foreach(explode("\n",$match[1])as $line){
            if(preg_match('/^\s*`([^`]+)`\s+([^ ]+)(.*)$/',$line,$field)){
                if(preg_match("/DEFAULT ('([^']*)'|[0-9]+)/",$field[3],$value))$defaults[$field[1]]=str_starts_with($value[1],"'")?$value[2]:(int)$value[1];
                else $defaults[$field[1]]=str_contains($field[2],'int')?0:'';
            }
        }
    }
    return $changes+['art_id'=>17,'art_name'=>'Fixture article','art_status'=>1,'type_id'=>1,'art_points'=>40,'art_points_detail'=>20,
        'art_content'=>'CHAPTER-ONE$$$CHAPTER-TWO$$$CHAPTER-THREE','art_title'=>'One$$$Two$$$Three']+$defaults;
}
function purchaseCsrfManga(array $changes=[]):array{
    static $defaults;
    if($defaults===null){
        $ddl=file_get_contents(dirname(__DIR__,2).'/application/install/sql/install.sql');
        preg_match('/CREATE TABLE `mac_manga` \(([\s\S]*?)\) ENGINE[^;]*;/',$ddl,$match);$defaults=[];
        foreach(explode("\n",$match[1])as $line){
            if(preg_match('/^\s*`([^`]+)`\s+([^ ]+)(.*)$/',$line,$field)){
                if(preg_match("/DEFAULT ('([^']*)'|[0-9]+)/",$field[3],$value))$defaults[$field[1]]=str_starts_with($value[1],"'")?$value[2]:(int)$value[1];
                else $defaults[$field[1]]=str_contains($field[2],'int')?0:'';
            }
        }
    }
    $primary='One$https://fixture.invalid/MANGA-ONE#Two$https://fixture.invalid/MANGA-TWO#Three$https://fixture.invalid/MANGA-THREE';
    $secondary='One$/images/MANGA-SECOND-ONE.jpg#Two$/images/MANGA-SECOND-TWO.jpg#Three$/images/MANGA-SECOND-THREE.jpg';
    return $changes+['manga_id'=>17,'manga_name'=>'Fixture manga','manga_status'=>1,'type_id'=>1,'manga_points'=>40,'manga_points_detail'=>20,
        'manga_content'=>'Public synopsis','manga_chapter_from'=>'primary$$$secondary',
        'manga_chapter_url'=>$primary.'$$$'.$secondary]+$defaults;
}
function purchaseCsrfSeed():void{
    purchaseCsrfConfig();
    foreach(array_merge(['ulog','plog','user','group','vod','art'],getenv('MANGA_PURCHASE_AUDIT')==='1'?['manga']:[])as $table)Db::execute('DELETE FROM audit_'.$table);
    $groups=[];
    foreach([1,2,3]as $id){$group=['group_id'=>$id,'group_name'=>'Fixture '.$id,'group_type'=>'1,','group_popedom'=>json_encode([1=>[3=>1,4=>1,5=>1]]),'group_status'=>1];Db::name('Group')->insert($group);$group['group_popedom']=json_decode($group['group_popedom'],true);$groups[$id]=$group;}
    \think\facade\Cache::set('purchase_csrf_group_list',$groups);
    Db::name('Vod')->insert(purchaseCsrfVod());
    Db::name('Art')->insert(purchaseCsrfArt());
    if(getenv('MANGA_PURCHASE_AUDIT')==='1')Db::name('Manga')->insert(purchaseCsrfManga());
    foreach([1,2,3,4]as $id)Db::name('User')->insert(['user_id'=>$id,'user_name'=>'fixture'.$id,'user_random'=>str_repeat((string)$id,32),
        'user_pwd'=>password_hash('fixture-password',PASSWORD_BCRYPT,['cost'=>4]),'user_status'=>1,'group_id'=>2,'user_points'=>$id===1?100:0,
        'user_pid'=>$id===1?2:0,'user_pid_2'=>$id===1?3:0,'user_pid_3'=>$id===1?4:0]);
}
function purchaseCsrfCookies(int $id=1):array{
    $row=Db::name('User')->where('user_id',$id)->find();
    return ['user_id'=>(string)$id,'user_name'=>$row['user_name'],'user_check'=>md5($row['user_random'].'-'.$row['user_name'].'-'.$id.'-')];
}
function purchaseCsrfBearer(int $id=1):string{return \app\common\util\JwtService::encode($id,Db::name('User')->where('user_id',$id)->value('user_random'));}
function purchaseCsrfBody(array $values=[]):array{return $values+['mid'=>'1','id'=>'17','type'=>'4','sid'=>'2','nid'=>'3'];}
function purchaseCsrfState():array{
    $state=[];foreach(['User','Plog','Ulog']as $table)$state[$table]=Db::name($table)->order(strtolower($table).'_id')->select()->toArray();return $state;
}
function purchaseCsrfRoute(string $target,array $body=[],array $query=[],array $cookies=[],array $headers=[],string $method='POST',array $server=[]):array{
    global $app;
    $api=str_starts_with($target,'payment/');$script=$api?'api.php':'index.php';
    $_GET=$query;$_POST=$body;$_COOKIE=$cookies;$_REQUEST=$body+$query;
    $_SERVER=$server+['REQUEST_METHOD'=>$method,'HTTP_HOST'=>'example.invalid','SCRIPT_NAME'=>'/fixture/'.$script,
        'SCRIPT_FILENAME'=>'/isolated/'.$script,'PATH_INFO'=>'/'.$target,'REQUEST_URI'=>'/fixture/'.$script.'/'.$target];
    $request=PurchaseCsrfRequest::__make($app)->withHeader($headers);
    $app->instance('request',$request);$app->instance('cookie',new \think\Cookie($request));
    $session=new \think\Session($app);$app->instance('session',$session);
    $app->setNamespace($api?'app\\api':'app\\index');$app->config->set([],'route');
    $GLOBALS['user']=['user_id'=>999,'user_points'=>999999];
    $middleware=new \think\middleware\SessionInit($app,$session);
    try { $response=$middleware->handle($request,static fn($request)=>(new \think\Route($app))->dispatch($request,false)); }
    catch(\think\exception\HttpResponseException $error){$response=$error->getResponse();}
    $middleware->end($response);
    check($response instanceof \think\response\Json&&in_array($response->getCode(),[200,400],true),'Actual purchase route must return controlled JSON');
    return ['data'=>$response->getData(),'response'=>$response,'session_id'=>$session->getId(),'cookie_queue'=>$app->cookie->getCookie()];
}
purchaseCsrfConfig();
