<?php
/** Normal guest/member message workflows only; this does not reproduce the interrupted security cases. */
require __DIR__.'/fixtures/security_audit_comment_submission_db.php';
use think\facade\Db;
if ($mysql) {
    if (!preg_match('/CREATE TABLE `mac_gbook` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) { throw new RuntimeException('Gbook DDL missing'); }
    Db::execute('DROP TABLE IF EXISTS audit_gbook');
    Db::execute(str_replace('`mac_gbook`','`audit_gbook`',$match[0]));
} else {
    Db::execute('CREATE TABLE audit_gbook (gbook_id INTEGER PRIMARY KEY AUTOINCREMENT,gbook_rid INTEGER DEFAULT 0,user_id INTEGER DEFAULT 0,
        gbook_status INTEGER DEFAULT 1,gbook_name TEXT,gbook_ip INTEGER,gbook_time INTEGER,gbook_reply_time INTEGER DEFAULT 0,gbook_content TEXT,gbook_reply TEXT)');
}
function normalGbookSeed(): void {
    commentSeed();
    Db::name('Gbook')->delete(true);
    $GLOBALS['config']['gbook']=['status'=>1,'login'=>0,'verify'=>0,'audit'=>0,'timespan'=>30];
}
function normalGbookSubmit(string $entry,array $form): array {
    $request=commentRequest($form);
    $class=$entry==='index'?app\index\controller\Gbook::class:app\api\controller\Gbook::class;
    $controller=(new ReflectionClass($class))->newInstanceWithoutConstructor();
    return $entry==='index'?$controller->saveData():$controller->submit($request);
}
foreach (['index','api'] as $entry) {
    normalGbookSeed();
    $result=normalGbookSubmit($entry,['gbook_content'=>'Normal guest message','gbook_name'=>'Fixture visitor']);
    $row=Db::name('Gbook')->order('gbook_id','desc')->find();
    check($result['code']===1 && $row['user_id']===0 && $row['gbook_status']===1,$entry.' must create a normal published guest message');
    check($row['gbook_content']==='Normal guest message' && $row['gbook_reply']==='' && $row['gbook_reply_time']===0,$entry.' must initialize message and reply fields');
    check((int)$row['gbook_ip']===2130706433 && $row['gbook_time']>0,$entry.' must store an integer address and server timestamp');
    check($row['gbook_name']===($entry==='index'?'controller/visitor':'Fixture visitor'),$entry.' must preserve its normal guest display name contract');
    normalGbookSeed();commentLogin();$GLOBALS['config']['gbook']['login']=1;
    $GLOBALS['config']['gbook']['verify']=1;$GLOBALS['config']['gbook']['audit']=1;
    $result=normalGbookSubmit($entry,['gbook_content'=>'Normal member video report','gbook_rid'=>1,'verify'=>'fixture-valid-captcha']);
    $row=Db::name('Gbook')->order('gbook_id','desc')->find();
    check($result['code']===1 && $row['user_id']===1 && $row['gbook_name']==='alice-nickname',$entry.' must use the real logged-in account');
    check($row['gbook_status']===0 && $row['gbook_rid']===1,$entry.' must retain moderation and normal video-report association');
    check(($GLOBALS['comment_cookies']['gbook_timespan']??'')==='t',$entry.' must set the configured post-success interval');
    check((new app\common\model\Gbook())->saveData(['gbook_id'=>$row['gbook_id'],'gbook_name'=>$row['gbook_name'],
        'gbook_content'=>$row['gbook_content'],'gbook_reply'=>'Administrator reply','gbook_status'=>1])['code']===1,
        'The existing administrator reply workflow must remain available');
    $request=commentRequest([],'GET')->setAction('get_list');
    $controller=(new ReflectionClass(app\api\controller\Gbook::class))->newInstanceWithoutConstructor();
    $list=$controller->get_list($request);
    check($list['code']===1 && $list['info']['total']===1 && $list['info']['rows'][0]['gbook_reply']==='Administrator reply',
        'The normal published API list must retain the administrator reply');
    check(!array_key_exists('gbook_ip',$list['info']['rows'][0]),'Public message rows must omit the stored address');
}
echo 'framework_audit_gbook_normal: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite').PHP_EOL;
