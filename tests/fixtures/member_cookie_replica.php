<?php
/** Real ORM read/write separation across two explicit databases on the isolated MySQL fixture server. */
use think\facade\Db;

$originalManager=think\Container::getInstance()->make('think\\DbManager');
$writer=Db::connect();
memberCookieSeed();
$writer->name('User')->where('user_id',1)->update(['user_random'=>str_repeat('a',32)]);
$writer->execute('CREATE DATABASE IF NOT EXISTS maccms_audit_member_cookie_read CHARACTER SET utf8mb4');
foreach(['user','group']as $table){
    $writer->execute('DROP TABLE IF EXISTS maccms_audit_member_cookie_read.cookie_audit_'.$table);
    $writer->execute('CREATE TABLE maccms_audit_member_cookie_read.cookie_audit_'.$table.' LIKE maccms_audit_member_cookie.cookie_audit_'.$table);
    $writer->execute('INSERT INTO maccms_audit_member_cookie_read.cookie_audit_'.$table.' SELECT * FROM maccms_audit_member_cookie.cookie_audit_'.$table);
}
$row=$writer->name('User')->where('user_id',1)->find();$credentials=memberCredential($row);
$token=\app\common\util\JwtService::encode(1,$row['user_random']);
$split=$database;
$host=$connection['hostname'];
$split['connections']['audit']=array_replace($connection,[
    'deploy'=>1,'rw_separate'=>true,'master_num'=>1,'slave_no'=>1,'hostname'=>$host.','.$host,
    'database'=>'maccms_audit_member_cookie,maccms_audit_member_cookie_read',
]);
$splitManager=new think\DbManager();$splitManager->setConfig($split);
$splitManager->listen(static function($sql):void{if(preg_match('/^\s*(UPDATE|INSERT|DELETE)\b/i',$sql))$GLOBALS['member_cookie_writes']++;});
think\Container::getInstance()->instance('think\\DbManager',$splitManager);
function memberReplicaState():array{
    global $writer;
    return [$writer->query('SELECT * FROM maccms_audit_member_cookie.cookie_audit_user ORDER BY user_id'),
        $writer->query('SELECT * FROM maccms_audit_member_cookie_read.cookie_audit_user ORDER BY user_id')];
}
function memberReplicaCheck(array $cookies,array $headers=[],bool $success=false):array{
    memberCookieRequest($cookies,$headers);$before=memberReplicaState();$GLOBALS['member_cookie_writes']=0;
    $result=(new \app\common\model\User())->checkLogin();
    check(($result['code']===1)===$success,'Authentication must follow the current writer account, regardless of the stale reader row');
    check(memberReplicaState()===$before&&$GLOBALS['member_cookie_writes']===0,'Replica-lag credential checks must leave both databases unchanged');
    return $result;
}
try{
    check(Db::connect()->query('SELECT DATABASE() AS db',[],true)[0]['db']==='maccms_audit_member_cookie'
        &&Db::connect()->query('SELECT DATABASE() AS db',[],false)[0]['db']==='maccms_audit_member_cookie_read',
        'The fixture must use real ORM master and reader connections to different databases');
    foreach(['rotated'=>['user_random'=>str_repeat('b',32)],'disabled'=>['user_status'=>0],
        'renamed'=>['user_name'=>'renamed'],'empty_secret'=>['user_random'=>'']]as $scenario=>$changes){
        $writer->name('User')->where('user_id',1)->update($row);
        $writer->name('User')->where('user_id',1)->update($changes+['group_id'=>3,'user_end_time'=>time()-60]);
        check(Db::name('User')->where('user_id',1)->find()['user_random']===str_repeat('a',32)
            &&Db::name('User')->master()->where('user_id',1)->find()!==Db::name('User')->where('user_id',1)->find(),
            'The ordinary ORM read must actually retain the old valid reader row for '.$scenario);
        memberReplicaCheck($credentials);
        // JWT binds uid/random, not a username; renaming alone is covered by the Cookie identity check.
        if($scenario!=='renamed')memberReplicaCheck($credentials,['Authorization'=>'Bearer '.$token]);
    }
    $writer->name('User')->where('user_id',1)->delete();
    check(Db::name('User')->where('user_id',1)->find()!==null&&Db::name('User')->master()->where('user_id',1)->find()===null,
        'The deleted writer account remains present only on the stale reader');
    memberReplicaCheck($credentials);memberReplicaCheck($credentials,['Authorization'=>'Bearer '.$token]);
    $writer->name('User')->insert($row);
    $writer->execute('UPDATE maccms_audit_member_cookie_read.cookie_audit_user SET user_random=?,user_name=?,user_status=0 WHERE user_id=1',
        [str_repeat('b',32),'old-reader-name']);
    check(Db::name('User')->where('user_id',1)->find()['user_name']==='old-reader-name','A default ORM read still sees the stale renamed/disabled row');
    $cookie=memberReplicaCheck($credentials,[],true);
    $jwt=memberReplicaCheck([],['Authorization'=>'Bearer '.$token],true);
    check($cookie['info']['user_name']==='member'&&$jwt['info']['user_name']==='member',
        'Both authentication channels return the valid current writer identity instead of the stale reader row');
}finally{
    think\Container::getInstance()->instance('think\\DbManager',$originalManager);
    $writer->execute('DROP DATABASE maccms_audit_member_cookie_read');
}
