<?php
/** Real frontend User controller/Request/ORM lists with owner and foreign SQLite records. */
declare(strict_types=1);
namespace { require dirname(__DIR__) . '/vendor/autoload.php'; }
namespace app\index\controller {
    class Base {
        public array $assigned = [];
        public function assign($key,$value) { $this->assigned[$key] = $value; }
        public function fetch($template) { return ['template'=>$template] + $this->assigned; }
    }
}
namespace app\common\model {
    // Content enrichment is peripheral; log/user/payment queries below use actual ORM models.
    class Vod {
        public function infoData($where,$field='*',$addition=1) {
            return ['info'=>['vod_id'=>1,'vod_name'=>'Fixture video','vod_pic'=>'','type'=>['type_id'=>1,'type_name'=>'Video']]];
        }
    }
    class Actor {
        public function infoData($where,$field='*',$addition=1) { return ['info'=>['actor_id'=>1,'actor_name'=>'Fixture actor','actor_pic'=>'']]; }
    }
}
namespace {
    error_reporting(E_ALL);
    set_error_handler(static function ($severity,$message,$file,$line) { throw new ErrorException($message,0,$severity,$file,$line); });
    function lang($key,$vars=[]) { return $key; }
    function config($key,$default=null) { return think\facade\Config::get($key,$default); }
    function request() { return think\Container::getInstance()->make('request'); }
    function json($data) { return new think\response\Json(new think\Cookie(request()),$data); }
    function url($path,$params=[]) { return '/'.$path.'?'.http_build_query($params); }
    function mac_url($path) { return '/'.$path; }
    function mac_param_url() { return ['wd'=>'','page'=>1,'limit'=>0]; }
    function mac_page_param($total,$limit,$page,$url) { return compact('total','limit','page','url'); }
    function mac_array_rekey($rows,$key) { return array_column($rows,null,$key); }
    function mac_url_vod_detail($row) { return '/vod/'.$row['vod_id']; }
    function mac_url_vod_play($row,$params=[]) { return '/vod/play/'.$row['vod_id']; }
    function mac_url_vod_down($row,$params=[]) { return '/vod/down/'.$row['vod_id']; }
    function mac_url_actor_detail($row) { return '/actor/'.$row['actor_id']; }
    function mac_url_type($row) { return '/type/'.$row['type_id']; }
    function mac_url_img($value) { return $value; }
    class UserListCache { public function get($key) { return [2=>['group_id'=>2,'group_name'=>'registered']]; } }
    $container = new think\Container();
    think\Container::setInstance($container);
    $configuration = ['default'=>'mysql','auto_timestamp'=>false,'connections'=>['mysql'=>[
        'type'=>'sqlite','database'=>':memory:','prefix'=>'audit_','trigger_sql'=>false,'fields_cache'=>false,
    ]]];
    $config = new think\Config();
    $config->set($configuration,'database');
    $container->instance('config',$config);
    // This suite isolates rendering; actual template availability has its own regression.
    $container->instance('view',new class { public function engine() { return $this; } public function exists($template) { return true; } });
    $container->instance('cache',new UserListCache());
    $db = new think\DbManager();
    $db->setConfig($configuration);
    $container->instance('think\\DbManager',$db);
    $GLOBALS['config'] = ['app'=>['cache_flag'=>'audit']];
    $GLOBALS['user'] = ['user_id'=>1,'user_invite_code'=>'OWNER'];
    $GLOBALS['http_type'] = 'http://';
    $_SERVER['HTTP_HOST'] = 'example.test';
    $schemas = [
        'user'=>'user_id INTEGER PRIMARY KEY,user_name TEXT,user_nick_name TEXT DEFAULT "",user_invite_code TEXT DEFAULT "",user_invite_count INTEGER DEFAULT 0,user_reg_time INTEGER DEFAULT 0,user_pid INTEGER DEFAULT 0,user_pid_2 INTEGER DEFAULT 0,user_pid_3 INTEGER DEFAULT 0,group_id TEXT DEFAULT "2",user_pwd TEXT DEFAULT "secret",user_random TEXT DEFAULT "secret"',
        'ulog'=>'ulog_id INTEGER PRIMARY KEY,user_id INTEGER,ulog_mid INTEGER,ulog_type INTEGER,ulog_rid INTEGER DEFAULT 1,ulog_sid INTEGER DEFAULT 0,ulog_nid INTEGER DEFAULT 0,ulog_time INTEGER',
        'plog'=>'plog_id INTEGER PRIMARY KEY,user_id INTEGER,plog_type INTEGER,plog_points INTEGER',
        'cash'=>'cash_id INTEGER PRIMARY KEY,user_id INTEGER,cash_money REAL',
        'order'=>'order_id INTEGER PRIMARY KEY,user_id INTEGER,order_price REAL',
        'card'=>'card_id INTEGER PRIMARY KEY,user_id INTEGER,card_use_status INTEGER',
    ];
    foreach ($schemas as $table=>$fields) { think\facade\Db::execute('CREATE TABLE audit_'.$table.' ('.$fields.')'); }
    think\facade\Db::name('User')->insertAll([
        ['user_id'=>1,'user_name'=>'owner','user_pid'=>0,'user_pid_2'=>0],
        ['user_id'=>2,'user_name'=>'foreign','user_pid'=>0,'user_pid_2'=>0],
        ['user_id'=>3,'user_name'=>'invitee','user_pid'=>1,'user_pid_2'=>0],
        ['user_id'=>4,'user_name'=>'grandchild','user_pid'=>3,'user_pid_2'=>1],
    ]);
    foreach ([[1,1,1,2],[2,1,8,2],[3,1,1,4],[4,1,1,5],[5,2,1,2]] as [$id,$uid,$mid,$type]) {
        think\facade\Db::name('Ulog')->insert(['ulog_id'=>$id,'user_id'=>$uid,'ulog_mid'=>$mid,'ulog_type'=>$type,'ulog_time'=>$id]);
    }
    for ($id=1;$id<=25;$id++) { think\facade\Db::name('Plog')->insert(['plog_id'=>$id,'user_id'=>1,'plog_type'=>$id%2 ? 1 : 7,'plog_points'=>$id]); }
    think\facade\Db::name('Plog')->insert(['plog_id'=>100,'user_id'=>2,'plog_type'=>1,'plog_points'=>999]);
    foreach (['Cash'=>'cash_money','Order'=>'order_price','Card'=>'card_use_status'] as $name=>$field) {
        foreach ([1,2] as $uid) { think\facade\Db::name($name)->insert([strtolower($name).'_id'=>$uid,'user_id'=>$uid,$field=>1]); }
    }
    $checks = 0;
    function userListExpect($condition,$message): void { global $checks; ++$checks; if (!$condition) { throw new RuntimeException($message); } }
    function userListCall($action,$params=[]) {
        $request = (new think\Request())->withServer(['REQUEST_METHOD'=>'GET'])->withGet($params)->setController('User')->setAction($action);
        think\Container::getInstance()->instance('request',$request);
        $controller = (new ReflectionClass(app\index\controller\User::class))->newInstanceWithoutConstructor();
        $result = $controller->$action();
        return $result instanceof think\response\Json ? $result->getData() : $result;
    }
    try {
        $failures=[];
        foreach (['ajax_ulog','plays','downs','favs','ulog','plog','cash','reward','orders','cards','invite'] as $action) {
            try {
                $data=userListCall($action);
                userListExpect(isset($data['list']),$action.' must return a list with no query parameters');
                if ($action !== 'ajax_ulog') { userListExpect(($data['param']['wd'] ?? null) === '', $action.' must preserve common header/search template defaults'); }
            }
            catch (Throwable $error) { $failures[]=$action.': '.$error->getMessage(); }
        }
        userListExpect($failures===[],implode("\n",$failures));
        foreach (['plays'=>[3],'downs'=>[4],'favs'=>[2,1],'ulog'=>[4,3,2,1]] as $action=>$ids) {
            $data=userListCall($action);
            userListExpect(array_column($data['list'],'ulog_id')===$ids,$action.' must preserve its log type and owner filters');
            userListExpect($data['param']['page']===1 && $data['param']['limit']===20,$action.' must expose normalized page/limit to its template');
        }
        userListExpect(array_column(userListCall('favs',['mid'=>1])['list'],'ulog_id')===[1],'Favorite model filters must survive default handling');
        userListExpect(array_column(userListCall('ulog',['mid'=>1,'type'=>5])['list'],'ulog_id')===[4],'Combined log filters must preserve ownership');
        $page=userListCall('plog',['page'=>2,'limit'=>20]);
        userListExpect(array_column($page['list'],'plog_id')===[5,4,3,2,1] && $page['__PAGING__']['total']===25,'Page two must query the correct owner rows');
        foreach (['income'=>13,'expense'=>12] as $filter=>$total) {
            $data=userListCall('plog',['filter'=>$filter]);
            userListExpect(count($data['list'])===$total && $data['__PAGING__']['total']===$total,'Ledger filters must select the expected income/expense records');
        }
        foreach (['cash'=>'cash_id','orders'=>'order_id','cards'=>'card_id'] as $action=>$id) {
            userListExpect(array_column(userListCall($action)['list'],$id)===[1],$action.' must never include another user');
        }
        $reward=userListCall('reward');
        userListExpect(array_column($reward['list'],'user_id')===[3] && !isset($reward['list'][0]['user_random'],$reward['list'][0]['user_pwd']),'Default reward level must preserve referral scope and sensitive-field stripping');
        userListExpect(array_column(userListCall('reward',['level'=>2])['list'],'user_id')===[4],'Second referral level must remain selectable');
        $invite=userListCall('invite');
        userListExpect(array_column($invite['list'],'user_id')===[3] && array_column($invite['list'][0]['sub_invitees'],'user_id')===[4],'Invite hierarchy must survive absent page/limit');
        userListExpect(userListCall('invite',['limit'=>1])['param']['limit']===1,'Invite must retain its existing lower limit of one');
        $ajax=userListCall('ajax_ulog',['mid'=>1,'type'=>5]);
        userListExpect($ajax['code']===1 && array_column($ajax['list'],'ulog_id')===[4] && $ajax['limit']===10,'AJAX read mode must retain its default limit and query filters');
        echo 'framework_audit_user_lists: '.$checks.' checks passed on PHP '.PHP_VERSION.PHP_EOL;
    } catch (Throwable $error) {
        fwrite(STDERR,get_class($error).': '.$error->getMessage().PHP_EOL.$error->getTraceAsString().PHP_EOL);
        exit(1);
    }
}
