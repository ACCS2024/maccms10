<?php
/** Real Request/ORM, real catalog parsers and real password templates; synthetic configuration only. */
declare(strict_types=1);
namespace app\common\controller { class All {} }
namespace app\api\controller {
    function mac_url_img($value){return $value === '' ? '' : '/fixture/'.$value;}
    function mac_url_vod_detail($row){return '/vod/'.$row['vod_id'];}
    function mac_url_art_detail($row){return '/art/'.$row['art_id'];}
    function mac_url_manga_detail($row){return '/manga/'.$row['manga_id'];}
    function mac_url_manga_play($row,$p){return '/read/manga/'.$row['manga_id'].'/'.$p['sid'].'/'.$p['nid'];}
}
namespace app\common\util {
    function mac_url_vod_play($row,$p){return '/play/'.$row['vod_id'].'/'.$p['sid'].'/'.$p['nid'];}
    function mac_url_vod_down($row,$p){return '/down/'.$row['vod_id'].'/'.$p['sid'].'/'.$p['nid'];}
    function mac_url_manga_play($row,$p){return '/read/manga/'.$row['manga_id'].'/'.$p['sid'].'/'.$p['nid'];}
}
namespace {
require dirname(__DIR__).'/vendor/autoload.php';
require dirname(__DIR__).'/application/common.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
function json($value){return \think\Response::create($value,'json');}
function config($key,$default=null){return \think\facade\Config::get($key,$default);}
function lang($key,...$args){return $key;}
function cookie($name,...$args){return null;}
use think\facade\Db;
class PublicViewCache {
    public function get($key){
        if(str_ends_with($key,'vip_exclusive_type_ids'))return [1];
        if(str_ends_with($key,'type_list'))return [1=>['type_id'=>1,'type_pid'=>0,'type_mid'=>12,'type_name'=>'分类','type_en'=>'fixture','private_config'=>'PRIVATE-MARKER-TYPE']];
        if(str_ends_with($key,'group_list'))return [3=>['group_id'=>3,'group_name'=>'会员','private_config'=>'PRIVATE-MARKER-GROUP']];
        return null;
    }
    public function set(...$args){}
}
$socket=getenv('DATABASE_AUDIT_MYSQL_SOCKET');$database=getenv('DATABASE_AUDIT_DATABASE');
if($socket!=='/audit/mysql.sock'||!is_string($database)||!preg_match('/^maccms_audit_backup_[a-f0-9]+$/D',$database))throw new \RuntimeException('Dedicated MySQL fixture required');
$app=new \think\App(sys_get_temp_dir().'/public-view-fixture');
$cfg=['default'=>'fixture','auto_timestamp'=>false,'connections'=>['fixture'=>[
    'type'=>'mysql','dsn'=>'mysql:unix_socket='.$socket.';dbname='.$database.';charset=utf8mb4','database'=>$database,
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_public_','charset'=>'utf8mb4','trigger_sql'=>false,'fields_cache'=>false,
]]];
$app->config->set($cfg,'database');$manager=new \think\DbManager();$manager->setConfig($cfg);$app->instance('think\\DbManager',$manager);$app->instance('cache',new PublicViewCache());
$app->config->set(['player'=>['source'=>['show'=>'线路一','private_config'=>'PRIVATE-MARKER-PLAYER','url'=>'https://PRIVATE-MARKER-PLAYER.invalid']]],'maccms');
$GLOBALS['config']=['app'=>['cache_flag'=>'public_view_fixture','cache_core'=>0,'count_cache_sec'=>0],'upload'=>['protocol'=>'https'],'user'=>['art_points_type'=>'0','manga_points_type'=>'0']];
$GLOBALS['user']=['user_id'=>0];
function publicCall(string $kind,string $action,array $parameters): array {
    global $app;
    $request=(new \think\Request())->withGet($parameters)->setController(ucfirst($kind))->setAction($action);$app->instance('request',$request);
    $controller=(new \ReflectionClass('app\\api\\controller\\'.ucfirst($kind)))->newInstanceWithoutConstructor();
    $response=$controller->$action($request);
    return json_decode($response->getContent(),true,512,JSON_THROW_ON_ERROR);
}
function noPublicSecrets(array $data): void {
    $json=json_encode($data,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);
    check(!str_contains($json,'PRIVATE-MARKER'),'A public response contains a password, resource or private configuration marker');
    $walk=function(array $node)use(&$walk){foreach($node as $key=>$value){
        check(!preg_match('/^(?:vod_pwd(?:_play|_down)?|art_pwd|manga_pwd|(?:vod_play|vod_down|manga_chapter)_url|server|server_info|private_config|unreviewed_field|art_content|content)$/D',(string)$key),'Unexpected private field '.$key);
        if(is_array($value))$walk($value);
    }};$walk($data);
}
$temp=audit_temp_dir('public-content-view');$exports=[];
try {
    foreach(['vod','art','manga'] as $kind){
        $cols=[$kind.'_id INTEGER PRIMARY KEY','type_id INTEGER DEFAULT 1','type_id_1 INTEGER DEFAULT 0','group_id INTEGER DEFAULT 3'];
        foreach(['name','en','sub','alias','author','actor','director','area','lang','class','year','tag','title','note','pic','pic_thumb','pic_slide','blurb','remarks','content','pwd','pwd_url','pwd_play','pwd_play_url','pwd_down','pwd_down_url','play_from','play_url','play_server','play_note','down_from','down_url','down_server','down_note','chapter_from','chapter_url','unreviewed_field'] as $field)$cols[]=$kind.'_'.$field." VARCHAR(320) NOT NULL DEFAULT ''";
        foreach(['status','time','time_add','hits','hits_day','hits_week','hits_month','score','score_num','points','points_detail','points_play','points_down','up','down','recycle_time'] as $field)$cols[]=$kind.'_'.$field.' INTEGER NOT NULL DEFAULT 0';
        Db::execute('CREATE TABLE audit_public_'.$kind.' ('.implode(',',$cols).')');
        Db::name($kind)->insert([
            $kind.'_id'=>1,$kind.'_name'=>'公开标题',$kind.'_status'=>1,$kind.'_pic'=>'cover.png',$kind.'_blurb'=>'公开简介',
            $kind.'_pwd'=>'PRIVATE-MARKER-PASSWORD',$kind.'_pwd_url'=>'https://PRIVATE-MARKER-HELP.invalid',
            $kind.'_unreviewed_field'=>'PRIVATE-MARKER-NEW-COLUMN',$kind.'_points'=>7,$kind.'_points_detail'=>3,
            $kind.'_content'=>$kind==='art'?'PRIVATE-MARKER-BODY-1$$$PRIVATE-MARKER-BODY-2':'公开介绍',
        ]);
        Db::name($kind)->insert([$kind.'_id'=>2,$kind.'_name'=>'无目录',$kind.'_status'=>1]);
    }
    Db::execute('CREATE TABLE audit_public_type (type_id INTEGER PRIMARY KEY)');
    Db::execute('CREATE TABLE audit_public_group (group_id INTEGER PRIMARY KEY)');
    Db::name('vod')->where('vod_id',1)->update([
        'vod_pwd_play'=>'PRIVATE-MARKER-PLAY-PWD','vod_pwd_down'=>'PRIVATE-MARKER-DOWN-PWD','vod_points_play'=>2,'vod_points_down'=>4,
        'vod_play_from'=>'source$$$backup','vod_play_url'=>'第一集$https://PRIVATE-MARKER-PLAY.invalid/one#https://PRIVATE-MARKER-BARE.invalid/two$$$备用集$https://PRIVATE-MARKER-BACKUP.invalid/one',
        'vod_play_server'=>'PRIVATE-MARKER-SERVER','vod_play_note'=>'PRIVATE-MARKER-NOTE',
        'vod_down_from'=>'download','vod_down_url'=>'下载一$https://PRIVATE-MARKER-DOWN.invalid/one#https://PRIVATE-MARKER-DOWN-BARE.invalid/two',
    ]);
    Db::name('art')->where('art_id',1)->update(['art_title'=>'第一章$$$第二章','art_note'=>'章节说明一$$$章节说明二']);
    Db::name('manga')->where('manga_id',1)->update([
        'manga_chapter_from'=>'source$$$backup',
        'manga_chapter_url'=>'第一话$https://PRIVATE-MARKER-IMAGE.invalid/one,https://PRIVATE-MARKER-IMAGE.invalid/two#第二话$https://PRIVATE-MARKER-IMAGE.invalid/three$$$备用话$https://PRIVATE-MARKER-IMAGE.invalid/four',
        'manga_play_server'=>'PRIVATE-MARKER-SERVER$$$PRIVATE-MARKER-BACKUP-SERVER','manga_play_note'=>'线路一$$$线路二',
    ]);
    foreach(['vod','art','manga'] as $kind){
        $response=publicCall($kind,'get_detail',[$kind==='manga'?'id':$kind.'_id'=>1]);$exports[$kind]=$response;
        check($response['code']===1,'Public detail remains available');$row=$response['info'];noPublicSecrets($row);
        check($row['has_password']===true && $row[$kind.'_name']==='公开标题' && $row[$kind.'_pic']==='/fixture/cover.png','Public display and boolean password hint remain available');
        check($row['type_is_vip_exclusive']===1 && array_key_exists('is_fav',$row),'VIP and favorite fields survive projection');
        $empty=publicCall($kind,'get_detail',[$kind==='manga'?'id':$kind.'_id'=>2]);noPublicSecrets($empty);
        check($empty['code']===1 && $empty['info']['has_password']===false,'No-password detail remains a successful DTO');
        check($empty['info'][$kind==='vod'?'vod_play_list':$kind.'_page_list']===[],'Empty catalog is a JSON array');
    }
    $vod=$exports['vod']['info'];
    check($vod['has_play_password']===true && $vod['has_down_password']===true,'Video operation password hints are distinct booleans');
    check(array_column($vod['vod_play_list'],'from')===['source','backup'],'Video source order is preserved');
    check($vod['vod_play_list'][0]['player_info']===['show'=>'线路一','from'=>'source'],'Only public player labels are returned');
    check(array_column($vod['vod_play_list'][0]['urls'],'name')===['第一集','第2集'],'Bare media address is never reused as the episode label');
    check($vod['vod_play_list'][0]['urls'][1]['play_link']==='/play/1/1/2' && $vod['vod_down_list'][0]['urls'][1]['down_link']==='/down/1/1/2','Catalog links identify controlled page routes');
    $manga=$exports['manga']['info'];
    check(array_keys($manga['manga_page_list'])===[1,2],'Manga keeps its one-based source keys');
    check(array_keys($manga['manga_page_list'][1]['urls'])===[1,2] && $manga['manga_page_list'][1]['url_count']===2,'Manga keeps chapter keys and counts');
    check($manga['manga_page_list'][1]['urls'][2]['name']==='第二话' && $manga['manga_page_list'][1]['urls'][2]['play_link']==='/read/manga/1/1/2','Manga directory retains labels and controlled links');
    check($manga['type']['type_name']==='分类' && $manga['group']===['group_id'=>3,'group_name'=>'会员'],'Nested taxonomy/group output retains display fields only');
    check(array_column($exports['art']['info']['art_page_list'],'title')===['第一章','第二章'],'Article chapter titles survive without body text');
    $list=publicCall('manga','get_list',[]);check($list['code']===1 && count($list['list'])===2,'Manga listing retains its pagination envelope');noPublicSecrets($list);
    foreach($list['list'] as $row)check(is_bool($row['has_password']),'List password hints are booleans');
    foreach([
        ['template/default/html/vod/player_pwd.html','vod_pwd_play',1,4],['template/default/html/vod/detail_pwd.html','vod_pwd',1,1],
        ['template/m1938pc3_v2/html9/vod/player_pwd.html','vod_pwd_play',1,4],['template/m1938pc3_v2/html9/vod/detail_pwd.html','vod_pwd',1,1],
        ['template/m1938pc3_v2/html9/vod/downer_pwd.html','vod_pwd_down',1,5],['template/m1938pc3_v2/html9/art/detail_pwd.html','art_pwd',2,1],
    ] as [$file,$field,$mid,$type]){
        $source=file_get_contents(dirname(__DIR__).'/'.$file);
        // The global JS configuration component is outside the password form; keep the actual conditional/form markup.
        $source=preg_replace('/\{include\s+file="[^"]+"\s*\/?\}/','',$source);
        $template=new \think\Template(['cache_path'=>$temp.'/','tpl_cache'=>false]);
        foreach(['','https://fixture.invalid/password-help'] as $help){
            $data=['maccms'=>['path'=>'/','path_tpl'=>'/fixture/','mid'=>$mid,'site_url'=>'fixture.invalid','site_wapurl'=>'fixture.invalid','mob_status'=>0],'obj'=>['vod_id'=>1,'art_id'=>1,$field=>'PRIVATE-MARKER-FORM-PASSWORD',$field.'_url'=>$help,'vod_pwd_url'=>$help]];
            ob_start();try{$template->display($source,$data);$html=ob_get_contents();}finally{ob_end_clean();}
            check(!str_contains($html,'PRIVATE-MARKER'),$file.' must not print the stored password');
            check(str_contains($html,'type="password"') && str_contains($html,'MAC.Pwd.Check(this)') && str_contains($html,'data-mid="'.$mid.'"') && str_contains($html,'data-type="'.$type.'"'),$file.' must preserve password entry and verification scope');
            check(str_contains($html,'href="https://fixture.invalid/password-help"')===($help!==''),$file.' must preserve the configured password-help link');
        }
    }
    file_put_contents('/audit/public-content-dtos.json',json_encode($exports,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
    echo 'framework_audit_api_content_view: '.$checks.' checks passed on PHP '.PHP_VERSION.' / MySQL'.PHP_EOL;
}finally{
    foreach(['vod','art','manga','type','group'] as $kind)Db::execute('DROP TABLE IF EXISTS audit_public_'.$kind);
    audit_remove_temp($temp);
}
}
