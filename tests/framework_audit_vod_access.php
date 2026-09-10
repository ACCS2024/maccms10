<?php
/** Actual content/user/permission models and installation DDL; only presentation helpers are isolated. */
declare(strict_types=1);
namespace app\common\model { class SeoAiResult { public function getByObject(...$args){return [];} } }
namespace app\common\controller {
    function mac_url_vod_play($row,$p=[]){return '/play/'.$row['vod_id'].'/'.($p['sid']??1).'/'.($p['nid']??1);}
    function mac_url_vod_down($row,$p=[]){return '/down/'.$row['vod_id'].'/'.($p['sid']??1).'/'.($p['nid']??1);}
    function mac_user_fav_state(...$args){return ['is_fav'=>0,'fav_ulog_id'=>0];}
    function mac_vod_play_tagwall_payload(...$args){return ['enabled'=>false,'json'=>'[]'];}
}
namespace app\common\util {
    function mac_url_vod_play($row,$p=[]){return '/play/'.$row['vod_id'].'/'.($p['sid']??1).'/'.($p['nid']??1);}
    function mac_url_vod_down($row,$p=[]){return '/down/'.$row['vod_id'].'/'.($p['sid']??1).'/'.($p['nid']??1);}
}
namespace app\api\controller {
    function mac_url_img($value){return '/fixture/'.$value;}
    function mac_url_vod_play($row,$p=[]){return '/play/'.$row['vod_id'].'/'.($p['sid']??1).'/'.($p['nid']??1);}
}
namespace {
require dirname(__DIR__).'/vendor/autoload.php';
require dirname(__DIR__).'/application/common.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\ContentResource;
use app\common\util\ContentPassword;
use app\common\util\JwtService;
use think\facade\Db;
function config($key,$default=null){return think\facade\Config::get($key,$default);}
function lang($key,...$args){return $key;}
function model($name){$class='app\\common\\model\\'.ucfirst($name);return new $class();}
function input(){return request()->param();}
function request(){return think\Container::getInstance()->make('request');}
function url($model,$params=[]){return '/'.basename($model).'/'.($params['id']??1).'/'.($params['sid']??1).'/'.($params['nid']??1);}
function json($value){return think\Response::create($value,'json');}
function cookie($name,...$args){$c=think\Container::getInstance()->make('cookie');if($args===[])return $c->get($name);if($args[0]===null)return $c->delete($name);return $c->set($name,(string)$args[0],$args[1]??null);}
function session($name,...$args){$s=think\Container::getInstance()->make('session');if($args===[])return $s->get($name);if($args[0]===null)return $s->delete($name);return $s->set($name,$args[0]);}
class VodAccessCache {
    public array $data=[];
    public function get($key,$default=null){return $this->data[$key]??$default;}
    public function set($key,$value,...$args){$this->data[$key]=$value;return true;}
    public function delete($key){unset($this->data[$key]);return true;}
}
class VodPageProbe extends app\index\controller\Vod {
    public array $assigned=[];
    public function __construct(){}
    protected function assign($name,$value=''):void{if(is_array($name))$this->assigned=array_merge($this->assigned,$name);else $this->assigned[$name]=$value;}
    protected function label_fetch($tpl,$loadcache=1,$type='html'){return $tpl;}
    protected function page_error($msg=''){throw new RuntimeException('Page denied: '.$msg);}
}
define('IN_FILE','api.php');define('ENTRANCE','api');define('MAC_PLAYER_SORT','1');define('MAC_PATH','/');
$socket=getenv('DATABASE_AUDIT_MYSQL_SOCKET');$database=getenv('DATABASE_AUDIT_DATABASE');
if($socket!=='/audit/mysql.sock'||!is_string($database)||!preg_match('/^maccms_audit_backup_[a-f0-9]+$/D',$database))throw new RuntimeException('Dedicated MySQL fixture required');
$temp=audit_temp_dir('vod-access');$app=new think\App($temp.'/app');
$cfg=['default'=>'fixture','auto_timestamp'=>false,'connections'=>['fixture'=>[
    'type'=>'mysql','dsn'=>'mysql:unix_socket='.$socket.';dbname='.$database.';charset=utf8mb4','database'=>$database,
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_resource_','charset'=>'utf8mb4','trigger_sql'=>true,'fields_cache'=>false,
]]];
$app->config->set($cfg,'database');$manager=new think\DbManager();$manager->setConfig($cfg);$app->instance('think\\DbManager',$manager);
$app->config->set(['type'=>'file','name'=>'resource_session','path'=>$temp.'/sessions','expire'=>3600],'session');
$cache=new VodAccessCache();$app->instance('cache',$cache);
$GLOBALS['config']=['api'=>['publicapi'=>['status'=>1,'charge'=>0]],'site'=>['site_status'=>1],'app'=>['cache_flag'=>'resource_fixture','cache_core'=>0,'count_cache_sec'=>0,'encrypt'=>0,'copyright_status'=>0,'ajax_page'=>1,
    'api_jwt_enabled'=>'1','api_jwt_secret'=>str_repeat('synthetic-key-',4),'api_jwt_iss'=>'vod-resource-audit'],
    'user'=>['status'=>1,'vod_points_type'=>'0','trysee'=>2],'rewrite'=>['vod_id'=>0,'status'=>1,'suffix_hide'=>0]];
$cache->data['resource_fixture_type_list']=[1=>['type_id'=>1,'type_pid'=>0,'type_mid'=>1,'type_name'=>'Videos','type_tpl_detail'=>'','type_tpl_play'=>'','type_tpl_down'=>'']];
$groups=[];foreach([1=>'Guest',2=>'Member',3=>'VIP',4=>'BlockedVIP',5=>'Extra'] as $id=>$name)$groups[$id]=['group_id'=>$id,'group_name'=>$name,'group_type'=>'1,','group_popedom'=>[1=>[2=>1,3=>$id!==4?1:0,4=>$id!==4?1:0,5=>1]]];
$cache->data['resource_fixture_group_list']=$groups;$cache->data['resource_fixture_vip_exclusive_type_ids']=[];
$players=['source'=>['show'=>'线路一','from'=>'source','sort'=>2,'status'=>1,'private'=>'PRIVATE-CONFIG'],
    'backup'=>['show'=>'线路二','from'=>'backup','sort'=>1,'status'=>1,'private'=>'PRIVATE-CONFIG']];
$app->config->set($players,'vodplayer');$app->config->set($players,'voddowner');$app->config->set(['server'=>['url'=>'https://PRIVATE-SERVER.invalid']],'vodserver');$app->config->set(['comment'=>[],'player'=>$players],'maccms');
function vodRequest(array $parameters=[],int $uid=0,array $state=[],string $action='get_play_info',?string $sessionId=null,array $cookies=[]):void {
    global $app;
    $_COOKIE=$cookies;$_REQUEST=[];
    $header=$uid>0?['authorization'=>'Bearer '.JwtService::encode($uid,md5('fixture-'.$uid))]:[];
    $r=think\Request::__make($app)->withGet($parameters)->withHeader($header)->withServer(['REQUEST_METHOD'=>'GET'])->setController('Vod')->setAction($action);
    $s=new think\Session($app);if($sessionId!==null)$s->setId($sessionId);$s->init();foreach($state as $key=>$value)$s->set($key,$value);
    $r->withSession($s);$app->instance('request',$r);$app->instance('session',$s);$app->instance('cookie',new think\Cookie($r));
    $GLOBALS['user']=[];
    $identity=(new ReflectionClass(app\common\controller\All::class))->newInstanceWithoutConstructor();
    (new ReflectionMethod($identity,'label_user'))->invoke($identity);
}
function vodApi(string $action,array $parameters,int $uid=0,array $state=[],?string $sessionId=null,array $cookies=[]):array {
    vodRequest($parameters,$uid,$state,$action,$sessionId,$cookies);
    $controller=new app\api\controller\Vod();
    return json_decode($controller->$action(request())->getContent(),true,512,JSON_THROW_ON_ERROR);
}
function noVodSecrets($value,array $allowed=[]):void {
    $text=is_string($value)?$value:json_encode($value,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);
    foreach(['PWD-DETAIL','PWD-PLAY','PWD-DOWN','PRIVATE-CONFIG','PRIVATE-SERVER',
        'MEDIA-PLAY-1','MEDIA-PLAY-2','MEDIA-PLAY-3','MEDIA-DOWN-1','MEDIA-DOWN-2','MEDIA-DOWN-3'] as $marker){
        if(in_array($marker,$allowed,true))continue;
        check(!str_contains($text,$marker),'Unexpected secret/unapproved resource '.$marker);
        check(!str_contains($text,base64_encode('https://fixture.invalid/'.$marker)),'Encoded unapproved resource escaped');
        check(!str_contains($text,base64_encode(mac_escape('https://fixture.invalid/'.$marker))),'Player-encoded unapproved resource escaped');
    }
}
function purchase(int $uid,int $type,int $sid,int $nid,int $points,int $rid=1):void {
    Db::name('ulog')->insert(['user_id'=>$uid,'ulog_mid'=>1,'ulog_type'=>$type,'ulog_rid'=>$rid,'ulog_sid'=>$sid,'ulog_nid'=>$nid,'ulog_points'=>$points,'ulog_time'=>time()]);
}
$sqlTrace=[];Db::listen(function($sql)use(&$sqlTrace){$sqlTrace[]=$sql;});
$tables=['vod','user','ulog','type','group','role'];
try {
    $ddl=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
    foreach($tables as $table){if(!preg_match('/CREATE TABLE `mac_'.preg_quote($table,'/').'` \(.*?\) ENGINE=[^;]+;/s',$ddl,$m))throw new RuntimeException('Missing fixture DDL');Db::execute(str_replace('`mac_'.$table.'`','`audit_resource_'.$table.'`',$m[0]));}
    foreach([[1,'2'],[2,'3'],[3,'4'],[4,'2,5']] as [$id,$group])Db::name('user')->insert(['user_id'=>$id,'user_name'=>'member-'.$id,'user_random'=>md5('fixture-'.$id),'user_status'=>1,'group_id'=>$group,'user_points'=>100,'user_end_time'=>time()+3600]);
    $vodDefaults=['vod_content'=>'','vod_play_url'=>'','vod_down_url'=>'','vod_plot_name'=>'','vod_plot_detail'=>''];
    Db::name('vod')->insert(['vod_id'=>1,'vod_name'=>'Video','vod_en'=>'video-one','vod_status'=>1,'type_id'=>1,'vod_points'=>9,'vod_points_play'=>3,'vod_points_down'=>4,
        'vod_play_from'=>'source$$$backup','vod_play_url'=>'第一集$https://fixture.invalid/MEDIA-PLAY-1#第二集$https://fixture.invalid/MEDIA-PLAY-2$$$备用集$https://fixture.invalid/MEDIA-PLAY-3',
        'vod_down_from'=>'source$$$backup','vod_down_url'=>'下载一$https://fixture.invalid/MEDIA-DOWN-1#下载二$https://fixture.invalid/MEDIA-DOWN-2$$$下载三$https://fixture.invalid/MEDIA-DOWN-3']+$vodDefaults);
    Db::name('vod')->insert(['vod_id'=>2,'vod_name'=>'Other video','vod_status'=>1,'type_id'=>1]+$vodDefaults);
    Db::name('role')->insert(['role_id'=>1,'role_name'=>'Character','role_status'=>1,'role_rid'=>1,'role_content'=>'']);
    foreach(['play','down'] as $flag){
        $res=vodApi('get_'.$flag.'_info',['id'=>1]);check($res['code']===1 && $res['info']['can_'.$flag]===0 && $res['info']['current']===null,'A visitor cannot fetch a paid video '.$flag);noVodSecrets($res);
        check(count($res['info'][$flag.'_list'])===2 && count($res['info'][$flag.'_list'][1]['urls'])===2,'Denied requests retain keyed catalogs');
        $res=vodApi('get_'.$flag.'_info',['id'=>1],2);check($res['info']['can_'.$flag]===1,'An allowed VIP can fetch the current resource');noVodSecrets($res,[$flag==='play'?'MEDIA-PLAY-1':'MEDIA-DOWN-1']);
        check(array_keys($res['info']['current'])===['name','nid','from','url'],'Current resource uses an explicit response shape');
        $res=vodApi('get_'.$flag.'_info',['id'=>1],3);check($res['info']['can_'.$flag]===0,'VIP without category permission stays denied');noVodSecrets($res);
    }

    $validCookie=['user_id'=>'2','user_name'=>'member-2','user_check'=>md5(md5('fixture-2').'-member-2-2-')];
    $r=vodApi('get_play_info',['id'=>1],0,[],null,$validCookie);check($r['info']['can_play']===1,'Existing valid Cookie identity authorizes the same resource as Bearer');noVodSecrets($r,['MEDIA-PLAY-1']);
    $forged=$validCookie;$forged['user_check']='wrong';$r=vodApi('get_play_info',['id'=>1],0,[],null,$forged);check($r['info']['can_play']===0,'A forged Cookie cannot authorize video access');noVodSecrets($r);
    purchase(4,4,1,1,3);purchase(1,4,1,2,3);purchase(1,5,1,1,4);purchase(1,4,1,1,0);purchase(1,4,1,1,3,2);
    $res=vodApi('get_play_info',['id'=>1],1);check($res['info']['can_play']===0,'Other owner/resource/coordinate/price vouchers do not authorize current resource');noVodSecrets($res);
    $res=vodApi('get_play_info',['id'=>1,'nid'=>2],1);check($res['info']['can_play']===1,'Exact purchased episode is accessible');noVodSecrets($res,['MEDIA-PLAY-2']);
    $res=vodApi('get_down_info',['id'=>1],1);check($res['info']['can_down']===1,'Download uses its own matching voucher');noVodSecrets($res,['MEDIA-DOWN-1']);

    Db::name('vod')->where('vod_id',1)->update(['vod_points_play'=>5]);$r=vodApi('get_play_info',['id'=>1,'nid'=>2],1);check($r['info']['can_play']===0 && $r['info']['points_hint']===5,'A stale-price voucher does not match a changed server price');noVodSecrets($r);Db::name('vod')->where('vod_id',1)->update(['vod_points_play'=>3]);
    $GLOBALS['config']['user']['vod_points_type']='1';purchase(1,4,0,0,9);
    $res=vodApi('get_play_info',['id'=>1,'sid'=>2],1);check($res['info']['can_play']===1 && $res['info']['points_hint']===9,'Whole-content voucher uses canonical zero coordinates/server price');noVodSecrets($res,['MEDIA-PLAY-3']);

    vodRequest(['id'=>1],2,[],'play');$page=new VodPageProbe();$page->play();check($page->assigned['obj']['player_info']['points']===9,'The actual frontend player uses the whole-content server price');
    foreach(['0','1'] as $whole){
        $GLOBALS['config']['user']['vod_points_type']=$whole;Db::name('vod')->where('vod_id',1)->update(['vod_points'=>0,'vod_points_play'=>0,'vod_points_down'=>0]);
        foreach(['play','down'] as $flag){$res=vodApi('get_'.$flag.'_info',['id'=>1]);check($res['info']['can_'.$flag]===1 && $res['info']['points_hint']===0,'Zero-price resources remain free in both billing modes');}
    }
    $GLOBALS['config']['user']['vod_points_type']='0';Db::name('vod')->where('vod_id',1)->update(['vod_points'=>9,'vod_points_play'=>3,'vod_points_down'=>4,'vod_pwd'=>'PWD-DETAIL','vod_pwd_play'=>'PWD-PLAY','vod_pwd_down'=>'PWD-DOWN']);
    foreach(['play','down'] as $flag){$res=vodApi('get_'.$flag.'_info',['id'=>1],2);check($res['info']['can_'.$flag]===0 && $res['info']['password_required'],'VIP still needs the operation password');noVodSecrets($res);}

    foreach([1,4,5] as $type){$r=vodApi('verify_pwd',['id'=>1,'type'=>$type,'pwd'=>'wrong'],2);check($r['code']===1012,'Wrong API content passwords retain the controlled error code');noVodSecrets($r);$r=vodApi('verify_pwd',['id'=>1,'type'=>$type,'pwd'=>[]],2);check($r['code']===1001,'Array passwords are rejected before comparison');}
    foreach([1=>'PWD-DETAIL',4=>'PWD-PLAY',5=>'PWD-DOWN'] as $type=>$password){
        $res=vodApi('verify_pwd',['id'=>1,'type'=>$type,'pwd'=>$password],2);check($res['code']===1,'Correct scoped password can be verified');$sid=$app->session->getId();$app->session->save();
        foreach(['play'=>4,'down'=>5] as $flag=>$requiredType){$r=vodApi('get_'.$flag.'_info',['id'=>1],2,[],$sid);check($r['info']['can_'.$flag]===($requiredType===$type?1:0),'Password scopes remain independent');noVodSecrets($r,$requiredType===$type?[$flag==='play'?'MEDIA-PLAY-1':'MEDIA-DOWN-1']:[]);}

        $repeat=vodApi('verify_pwd',['id'=>1,'type'=>$type,'pwd'=>$password],2,[],$sid);check($repeat['code']===1002,'Reverification of the same current password grant preserves the repeat response');
        if($type===4){Db::name('vod')->where('vod_id',1)->update(['vod_pwd_play'=>'CHANGED']);$r=vodApi('get_play_info',['id'=>1],2,[],$sid);check($r['info']['can_play']===0,'A password change invalidates an old grant');Db::name('vod')->where('vod_id',1)->update(['vod_pwd_play'=>$password]);}
    }
    $res=vodApi('get_play_info',['id'=>1],2,['1-4-1'=>'1']);check($res['info']['can_play']===0,'Legacy unbound grants require verification again');
    Db::name('vod')->where('vod_id',1)->update(['vod_pwd_play'=>'0']);$res=vodApi('verify_pwd',['id'=>1,'type'=>4,'pwd'=>'0'],2);check($res['code']===1,'String zero is a valid configured password');
    foreach([[],false,1.5,null,'','1e0','-1','0','4294967296'] as $bad){
        foreach(['id','sid','nid'] as $key){$r=vodApi('get_play_info',array_replace(['id'=>1],[$key=>$bad]),2);check($r['code']===1001,'Malformed coordinates are rejected before selecting another resource');}
    }
    foreach([['sid'=>99],['nid'=>99]] as $bad){$r=vodApi('get_play_info',['id'=>1]+$bad,2);check($r['code']===1002,'Missing resource coordinates are controlled');noVodSecrets($r);}
    $GLOBALS['config']['user']['status']=0;$r=vodApi('get_play_info',['id'=>1]);check($r['info']['can_play']===0,'Disabling the member system does not bypass passwords');
    Db::name('vod')->where('vod_id',1)->update(['vod_pwd_play'=>'','vod_pwd_down'=>'']);$r=vodApi('get_play_info',['id'=>1]);check($r['info']['can_play']===1,'Disabling the member system retains its group/points bypass');$GLOBALS['config']['user']['status']=1;
    foreach(['play','player','down','downer'] as $action){
        vodRequest(['id'=>1],1,[],$action);$page=new VodPageProbe();$page->$action();
        $allowed=$action==='down'||$action==='downer'?['MEDIA-DOWN-1']:[];noVodSecrets($page->assigned,$allowed);
        if($action==='play'||$action==='player')check($page->assigned['player_data']==='' && $page->assigned['player_js']==='','Denied/trial frontend routes contain no full player resource');
        if($action==='down'){check($page->assigned['obj']['vod_down_list'][1]['urls'][1]['authorized'] && !$page->assigned['obj']['vod_down_list'][1]['urls'][2]['authorized'],'Frontend download list authorizes each entry separately');}
    }
    vodRequest(['id'=>1],2,[],'play');$page=new VodPageProbe();$page->play();noVodSecrets($page->assigned,['MEDIA-PLAY-1']);check($page->assigned['obj']['player_info']['url_next']==='' && $page->assigned['obj']['player_info']['link_next']==='/play/1/1/2','Next episode is a controlled page link, never its media URL');


    foreach(['detail','ajax_detail','rss','plot','role'] as $action){vodRequest(['id'=>1],0,[],$action);$page=new VodPageProbe();$page->$action();noVodSecrets($page->assigned);check(isset($page->assigned['obj']['vod_play_list'][1]['urls'][1]['play_link']),'Every detail-derived view receives only a controlled catalog');}
    vodRequest(['mid'=>1,'limit'=>10,'page'=>1,'tid'=>0]);$ajax=(new ReflectionClass(app\index\controller\Ajax::class))->newInstanceWithoutConstructor();$ajax->_param=mac_param_url();$r=json_decode($ajax->data()->getContent(),true);
    check($r['code']===1 && count($r['list'])===2 && isset($r['list'][0]['detail_link']) && is_bool($r['list'][0]['has_password']),'Legacy Ajax video lists keep pagination/links and boolean password hints');noVodSecrets($r);

    foreach(['play','player','down','downer'] as $action){vodRequest(['id'=>[]],2,[],$action);$denied=false;try{new app\index\controller\Vod();}catch(think\exception\HttpResponseException $e){$denied=$e->getResponse()->getCode()===400;}check($denied,'Malformed arrays are rejected before the real frontend constructor invokes the legacy global URL parser');}
    vodRequest(['mid'=>1,'id'=>[],'pwd'=>'test'],0,[],'pwd');$denied=false;try{new app\index\controller\Ajax();}catch(think\exception\HttpResponseException $e){$denied=json_decode($e->getResponse()->getContent(),true)['code']===1001;}check($denied,'The real Ajax constructor rejects arrays before trimming URL parameters');
    purchase(1,5,1,2,4);vodRequest(['id'=>1,'sid'=>1,'nid'=>2],1,[],'down');$page=new VodPageProbe();$page->down();check($page->assigned['obj']['vod_down_list'][1]['urls'][2]['authorized'],'Batched SQL groups same-source coordinates with AND and different sources with OR');noVodSecrets($page->assigned,['MEDIA-DOWN-1','MEDIA-DOWN-2']);Db::name('ulog')->where(['user_id'=>1,'ulog_mid'=>1,'ulog_type'=>5,'ulog_rid'=>1,'ulog_sid'=>1,'ulog_nid'=>2])->delete();

    foreach([1,2] as $encryption){$GLOBALS['config']['app']['encrypt']=$encryption;vodRequest(['id'=>1],2,[],'play');$page=new VodPageProbe();$page->play();$expected=mac_escape('https://fixture.invalid/MEDIA-PLAY-1');if($encryption===2)$expected=base64_encode($expected);check($page->assigned['obj']['player_info']['url']===$expected && $page->assigned['obj']['player_info']['url_next']==='','Legacy player encoding preserves only the authorized current resource');noVodSecrets($page->assigned,['MEDIA-PLAY-1']);}$GLOBALS['config']['app']['encrypt']=0;
    // Actual source/episode keys survive blank segments and server sorting.
    $original=Db::name('vod')->where('vod_id',1)->find();
    Db::name('vod')->where('vod_id',1)->update(['vod_play_from'=>'backup$$$source','vod_play_url'=>'$$$第一集$https://fixture.invalid/MEDIA-PLAY-1##第三集$https://fixture.invalid/MEDIA-PLAY-3']);
    $r=vodApi('get_play_info',['id'=>1,'sid'=>2,'nid'=>3],2);check($r['info']['sid']===2 && $r['info']['nid']===3 && $r['info']['current']['nid']===3,'Actual hole coordinates select the requested episode');noVodSecrets($r,['MEDIA-PLAY-3']);
    $r=vodApi('get_play_info',['id'=>1,'sid'=>2,'nid'=>2],2);check($r['code']===1002,'An empty episode slot cannot alias the next episode');
    vodRequest(['id'=>1,'sid'=>2,'nid'=>1],2,[],'play');$page=new VodPageProbe();$page->play();check($page->assigned['obj']['player_info']['link_next']==='/play/1/2/3','Next links use actual keys, not count or compressed position');noVodSecrets($page->assigned,['MEDIA-PLAY-1']);
    $GLOBALS['config']['rewrite']['vod_id']=1;vodRequest(['id'=>'video-one','sid'=>2,'nid'=>3],2,[],'play');$page=new VodPageProbe();$page->play();check($page->assigned['param']['id']===1,'Rewritten slugs resolve to the actual numeric resource ID before authorization');
    $GLOBALS['config']['rewrite']['vod_id']=0;Db::name('vod')->where('vod_id',1)->update(['vod_play_from'=>$original['vod_play_from'],'vod_play_url'=>$original['vod_play_url']]);
    foreach([[],false,1.5,null,'','1e0','-1','0','4294967296'] as $bad){foreach(['id','sid','nid'] as $key){
        vodRequest(array_replace(['id'=>1],[$key=>$bad]),2,[],'play');$page=new VodPageProbe();$denied=false;
        try{$page->play();}catch(RuntimeException $e){$denied=str_starts_with($e->getMessage(),'Page denied:');}
        check($denied,'Frontend malformed coordinates receive a controlled page error');noVodSecrets($page->assigned);
    }}
    // Trial permission and direct iframe/player access never hand out the complete media URL.
    $cache->data['resource_fixture_group_list'][2]['group_popedom'][1][3]=0;
    foreach(['play','player'] as $action){vodRequest(['id'=>1],1,[],$action);$page=new VodPageProbe();$page->$action();check($page->assigned['popedom']['code']===3002 && $page->assigned['player_data']==='' && $page->assigned['player_js']==='','Trial-only group cannot receive full player data through either route');noVodSecrets($page->assigned);}
    $r=vodApi('get_play_info',['id'=>1],1);check($r['info']['can_play']===0 && !$r['info']['preview_available'],'Full-file playback is not advertised as a secure preview');noVodSecrets($r);
    $cache->data['resource_fixture_group_list'][2]['group_popedom'][1][3]=1;
    $GLOBALS['config']['app']['cache_core']=1;$cache->data['resource_fixture_vod_detail_1_']=(new app\common\model\Vod())->infoData(['vod_id'=>1],'*',0)['info'];
    foreach(['vod_status'=>0,'vod_recycle_time'=>time()] as $field=>$value){Db::name('vod')->where('vod_id',1)->update([$field=>$value]);$r=vodApi('get_play_info',['id'=>1],2);check($r['code']===1002,'Unpublished/recycled resources are rejected using a fresh row');noVodSecrets($r);Db::name('vod')->where('vod_id',1)->update([$field=>$field==='vod_status'?1:0]);}
    $GLOBALS['config']['app']['cache_core']=0;
    // Render the shipped download directory with real ThinkPHP taglib, retaining all three labels.
    vodRequest(['id'=>1],1,[],'down');$page=new VodPageProbe();$page->down();
    $source=file_get_contents(dirname(__DIR__).'/template/default/html/vod/down.html');
    $start=strpos($source,'{maccms:foreach name="obj.vod_down_list"');$end=strpos($source,'{/maccms:foreach}',$start);$end=strpos($source,'{/maccms:foreach}',$end+1)+strlen('{/maccms:foreach}');
    $source=substr($source,$start,$end-$start);$template=new think\Template(['cache_path'=>$temp.'/templates/','tpl_cache'=>false,'taglib_pre_load'=>'app\\common\\taglib\\Maccms','default_filter'=>'']);
    ob_start();try{$template->display($source,$page->assigned+['maccms'=>['path'=>'/']]);$html=ob_get_contents();}finally{ob_end_clean();}
    noVodSecrets($html,['MEDIA-DOWN-1']);check(substr_count($html,'class="style-input down_url"')===1,'Only the purchased episode receives an actual download control');check(str_contains($html,'/down/1/1/2') && str_contains($html,'/down/1/2/1'),'Other download entries retain controlled acquisition links');

    foreach(['template/m1938pc3_v2/html9/vod/detail.html','template/demo/html/vod/detail.html','template/stui_tpl/html/vod/urllist.html','template/vozy/vo20w2/vod/detail.html'] as $file){
        $source=file_get_contents(dirname(__DIR__).'/'.$file);
        foreach(['play','down'] as $flag){
            $start=strpos($source,'{maccms:foreach name="obj.vod_'.$flag.'_list"');if($start===false)continue;
            preg_match_all('/\{\/?maccms:foreach\b[^}]*\}/',substr($source,$start),$tags,PREG_OFFSET_CAPTURE);$depth=0;$end=0;
            foreach($tags[0] as [$tag,$offset]){$depth+=str_starts_with($tag,'{/')?-1:1;if($depth===0){$end=$offset+strlen($tag);break;}}
            $block=substr($source,$start,$end);$row=(new app\common\model\Vod())->infoData(['vod_id'=>1],'*',0)['info'];
            ob_start();try{$template->display($block,['obj'=>ContentResource::vodTemplate($row),'param'=>['sid'=>1,'nid'=>1]]);$html=ob_get_contents();}finally{ob_end_clean();}
            noVodSecrets($html);check(str_contains($html,'/'.$flag.'/1/1/2'),'Existing theme directories display/copy controlled links with actual coordinates');
        }
    }
    // A download page reads matching vouchers in one query even when many episodes are listed.
    $episodes=[];for($i=1;$i<=160;$i++)$episodes[]='下载'.$i.'$https://fixture.invalid/MEDIA-DOWN-'.$i;
    Db::name('vod')->where('vod_id',1)->update(['vod_down_from'=>'source','vod_down_url'=>implode('#',$episodes)]);
    vodRequest(['id'=>1],1,[],'down');$sqlTrace=[];$page=new VodPageProbe();$page->down();
    $voucherReads=array_values(array_filter($sqlTrace,fn($sql)=>str_starts_with($sql,'SELECT') && str_contains($sql,'audit_resource_ulog')));
    check(count($voucherReads)===1 && count($page->assigned['obj']['vod_down_list'][1]['urls'])===160,'Large catalogs use one bounded voucher query, not one query per episode');
    check(count(array_filter($sqlTrace,fn($sql)=>preg_match('/^(INSERT|UPDATE|DELETE)/',$sql)))===0,'Resource reads never debit points or create purchase records');

    check(count(array_filter($page->assigned['obj']['vod_down_list'][1]['urls'],fn($episode)=>$episode['url']!==''))===1,'A large catalog still exposes exactly the purchased entry');
    for($i=161;$i<=1200;$i++)$episodes[]='下载'.$i.'$https://fixture.invalid/MEDIA-DOWN-'.$i;
    Db::name('vod')->where('vod_id',1)->update(['vod_down_url'=>implode('#',$episodes)]);
    vodRequest(['id'=>1],1,[],'down');$sqlTrace=[];$page=new VodPageProbe();$page->down();
    $voucherReads=array_values(array_filter($sqlTrace,fn($sql)=>str_starts_with($sql,'SELECT') && str_contains($sql,'audit_resource_ulog')));
    check(count($voucherReads)===3 && count($page->assigned['obj']['vod_down_list'][1]['urls'])===1200,'Long catalogs cap each exact-coordinate voucher query at 500 entries');
    check(count(array_filter($page->assigned['obj']['vod_down_list'][1]['urls'],fn($episode)=>$episode['url']!==''))===1,'Chunk boundaries never broaden authorization');
    Db::name('vod')->where('vod_id',1)->update(['vod_down_from'=>$original['vod_down_from'],'vod_down_url'=>$original['vod_down_url']]);
    // The real front-end password endpoint and both themes use exactly the requested password scope.
    foreach(['play'=>4,'down'=>5] as $flag=>$type){
        Db::name('vod')->where('vod_id',1)->update(['vod_pwd_'.$flag=>'a&+b','vod_pwd_'.$flag.'_url'=>'https://fixture.invalid/'.$flag.'-help']);
        foreach($flag==='play'?['play','player']:['down','downer'] as $action){vodRequest(['id'=>1],2,[],$action);$page=new VodPageProbe();check($page->$action()==='vod/'.($flag==='play'?'player':'downer').'_pwd','Both frontend entries require the corresponding password');noVodSecrets($page->assigned);}
        vodRequest(['mid'=>1,'id'=>1,'type'=>$type,'pwd'=>'a&+b']);$ajax=(new ReflectionClass(app\index\controller\Ajax::class))->newInstanceWithoutConstructor();$r=json_decode($ajax->pwd()->getContent(),true);check($r['code']===1,'Guests can establish a password grant through the real Ajax endpoint');$sessionId=$app->session->getId();$app->session->save();
        $r=vodApi('get_'.$flag.'_info',['id'=>1],2,[],$sessionId);check($r['info']['can_'.$flag]===1,'A guest password session remains valid for an authenticated resource request');
        $r=vodApi('get_'.$flag.'_info',['id'=>1],0,[],$sessionId);check($r['info']['can_'.$flag]===0 && $r['info']['password_verified'],'Password verification alone does not waive points');noVodSecrets($r);
        foreach(['template/default/html','template/m1938pc3_v2/html9'] as $theme){
            $source=file_get_contents(dirname(__DIR__).'/'.$theme.'/vod/'.($flag==='play'?'player':'downer').'_pwd.html');$source=preg_replace('/\{include\s+file="[^"]+"\s*\/?\}/','',$source);
            $row=(new app\common\model\Vod())->infoData(['vod_id'=>1],'*',0)['info'];$view=ContentResource::vodTemplate($row);
            ob_start();try{$template->display($source,['obj'=>$view,'maccms'=>['path'=>'/','path_tpl'=>'/fixture/','mid'=>1,'site_url'=>'fixture.invalid','site_wapurl'=>'fixture.invalid','mob_status'=>0]]);$html=ob_get_contents();}finally{ob_end_clean();}
            check(!str_contains($html,'a&+b') && str_contains($html,'type="password"') && str_contains($html,'data-type="'.$type.'"'),'Actual theme password form contains no stored password and retains its scope');check(str_contains($html,'href="https://fixture.invalid/'.$flag.'-help"'),'Password helper link matches the current scope');
        }
        Db::name('vod')->where('vod_id',1)->update(['vod_pwd_'.$flag=>'']);
    }

    // Direct static label use remains forbidden; Make now writes separately verified safe redirects.
    foreach([2,3,4] as $view){foreach(['play','down'] as $flag){
        $GLOBALS['config']['view']=['vod_detail'=>2,'vod_play'=>1,'vod_down'=>1];$GLOBALS['config']['view']['vod_'.$flag]=$view;
        vodRequest(['id'=>1],2);request()->withHeader(['x-requested-with'=>'XMLHttpRequest'])->withServer(['HTTP_X_REQUESTED_WITH'=>'XMLHttpRequest']);$sqlTrace=[];
        $page=new VodPageProbe();$method=new ReflectionMethod($page,'label_vod_play');$denied=false;try{$method->invoke($page,$flag,[],$view);}catch(RuntimeException $e){$denied=str_contains($e->getMessage(),'动态授权');}check($denied && $page->assigned===[],'Direct static label use cannot render authorization-dependent resource HTML');
    }}
    $GLOBALS['config']['view']=['vod_detail'=>2,'vod_play'=>1,'vod_down'=>1];vodRequest(['id'=>1]);$page=new VodPageProbe();$row=(new app\common\model\Vod())->infoData(['vod_id'=>1],'*',0)['info'];(new ReflectionMethod($page,'label_vod_detail'))->invoke($page,$row,2);noVodSecrets($page->assigned);check(isset($page->assigned['obj']['vod_play_list'][1]['urls'][1]['play_link']),'Static detail rendering retains the safe directory');
    echo 'framework_audit_vod_access: '.$checks.' checks passed on PHP '.PHP_VERSION.' / MySQL'.PHP_EOL;
}finally{foreach($tables as $table)Db::execute('DROP TABLE IF EXISTS audit_resource_'.$table);audit_remove_temp($temp);}
}
