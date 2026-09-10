<?php
/** Included by the avatar suite: real nonempty list/API/admin-save call chains. */
use app\common\util\UserPortrait;
use think\facade\Db;

// Only load the actual small helper, avoiding the application's unrelated global bootstrap/functions.
$source=file_get_contents(dirname(__DIR__,2).'/application/common.php');
if (!preg_match('/function mac_get_user_portrait\([^)]*\)\s*\{[\s\S]*?\n\}/',$source,$match))throw new RuntimeException('Avatar helper missing');
eval($match[0]);
function mac_restore_htmlfilter($value) { return $value; }
function mac_em_replace($value) { return $value; }
class AvatarFixtureVod {
    public function infoData($where) { return ['code'=>1,'info'=>['vod_id'=>1,'vod_name'=>'fixture']]; }
}
class_alias(AvatarFixtureVod::class,'app\\common\\model\\Vod');
class AvatarReadCache {
    public function get($key,$default=null) { return $default; }
    public function set($key,$value,$ttl=null) { return true; }
}
$cache=think\Container::getInstance()->make('cache');
think\Container::getInstance()->instance('cache',new AvatarReadCache());
$GLOBALS['config']['app']['count_cache_sec']=0;
if ($mysql) {
    $ddl=file_get_contents(dirname(__DIR__,2).'/application/install/sql/install.sql');
    foreach (['comment','gbook','chatroom'] as $table) {
        if (!preg_match('/CREATE TABLE `mac_'.$table.'` \([\s\S]*?\) ENGINE[^;]*;/',$ddl,$match))throw new RuntimeException('Avatar list fixture missing table');
        Db::execute('DROP TABLE IF EXISTS upload_audit_'.$table);
        Db::execute(str_replace('`mac_'.$table.'`','`upload_audit_'.$table.'`',$match[0]));
    }
} else {
    Db::execute('CREATE TABLE upload_audit_comment (comment_id INTEGER PRIMARY KEY, comment_pid INTEGER DEFAULT 0,
        comment_status INTEGER DEFAULT 1, comment_mid INTEGER DEFAULT 1, comment_rid INTEGER DEFAULT 1,
        user_id INTEGER, comment_content TEXT, comment_time INTEGER DEFAULT 1, comment_up INTEGER DEFAULT 0, comment_down INTEGER DEFAULT 0)');
    Db::execute('CREATE TABLE upload_audit_gbook (gbook_id INTEGER PRIMARY KEY, user_id INTEGER, gbook_content TEXT, gbook_reply TEXT)');
    Db::execute('CREATE TABLE upload_audit_chatroom (chat_id INTEGER PRIMARY KEY, vod_id INTEGER DEFAULT 1, user_id INTEGER,
        user_name TEXT, chat_content TEXT, chat_time INTEGER DEFAULT 1, chat_status INTEGER DEFAULT 1)');
}
foreach ([1=>1,2=>2,3=>4294967295] as $row=>$uid) {
    Db::name('Comment')->insert(['comment_id'=>$row,'comment_pid'=>$row===3?1:0,'user_id'=>$uid,'comment_content'=>'comment '.$row,'comment_mid'=>1,'comment_rid'=>1,'comment_status'=>1]);
    Db::name('Gbook')->insert(['gbook_id'=>$row,'user_id'=>$uid,'gbook_content'=>'entry '.$row,'gbook_reply'=>'reply']);
    Db::name('Chatroom')->insert(['chat_id'=>$row,'user_id'=>$uid,'user_name'=>'fixture','chat_content'=>'message','vod_id'=>1,'chat_status'=>1]);
}
$avatarQueries=[];
Db::listen(static function ($sql) use (&$avatarQueries): void {
    if (preg_match('/^SELECT /i',$sql) && str_contains($sql,'upload_audit_user')) { $avatarQueries[]=$sql; }
});
$expected=[];foreach ([1,2,4294967295] as $uid)$expected[$uid]=UserPortrait::url($uid);
foreach (['comment','gbook','chatroom','api-comment'] as $entry) {
    uploadIdentityRequest(['mid'=>1,'rid'=>1],'GET',false);request()->setAction('get_list');$avatarQueries=[];
    $rows=match($entry) {
        'comment'=>(new app\common\model\Comment())->listData(['comment_pid'=>0],'comment_id asc')['list'],
        'gbook'=>(new app\common\model\Gbook())->listData([],'gbook_id asc')['list'],
        'chatroom'=>(new app\common\model\Chatroom())->getNewMessages(1)['info']['rows'],
        'api-comment'=>(new ReflectionClass(app\api\controller\Comment::class))->newInstanceWithoutConstructor()->get_list(request())->getData()['info']['rows'],
    };
    check(count($avatarQueries)===1,'Nonempty '.$entry.' performed per-user avatar queries: '.count($avatarQueries));
    check(count($rows)>=2,'Nonempty '.$entry.' lost list rows');
    foreach ($rows as $row) {
        check($row['user_portrait']===$expected[$row['user_id']],'Nonempty '.$entry.' returned the wrong owner avatar');
        foreach ($row['sub']??[] as $reply)check($reply['user_portrait']===$expected[$reply['user_id']],'Reply avatar lost its owner');
    }
}
think\Container::getInstance()->instance('cache',$cache);
class AvatarAdminProfileController extends app\admin\controller\User {
    public function success($message) { return ['code'=>1,'msg'=>$message]; }
    public function error($message) { return ['code'=>0,'msg'=>$message]; }
}
$before=Db::name('User')->find(1)['user_portrait'];
foreach (['user_portrait','USER_PORTRAIT','User_Portrait'] as $field) {
    uploadIdentityRequest(['user_id'=>1,'user_name'=>'fixture1','group_id'=>'2',$field=>'stale-or-forged-path'],'POST',false);
    $result=(new ReflectionClass(AvatarAdminProfileController::class))->newInstanceWithoutConstructor()->info();
    check($result['code']===1 && Db::name('User')->find(1)['user_portrait']===$before,'Ordinary admin profile save overwrote managed avatar via '.$field);
}
$template=file_get_contents(dirname(__DIR__,2).'/application/admin/view/user/info.html');
$dom=new DOMDocument();@$dom->loadHTML($template);
$input=(new DOMXPath($dom))->query('//input[@id="user_portrait"]')->item(0);
check($input && $input->hasAttribute('readonly') && !$input->hasAttribute('name'),'Admin avatar field remained an editable/submittable pointer');
