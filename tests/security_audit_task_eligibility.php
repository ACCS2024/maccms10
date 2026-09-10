<?php
require __DIR__ . '/fixtures/security_audit_task_clock.php';
require __DIR__ . '/fixtures/security_audit_task_eligibility_db.php';
use app\common\model\Comment;
use app\common\model\TaskLog;
use think\facade\Db;

// A ready task row and arbitrary client increment are not proof of a submitted/approved comment.
taskApiSeed(); taskApiReady(); $before=taskApiState();
check(taskApi('claim_reward',['task_id'=>1])['code'] !== 1 && taskApiState() === $before,
    'Legacy ready status alone authorized a comment reward');
for ($i=0; $i<3; $i++) {
    $result=taskApi('report_progress',['task_action'=>'post_comment','increment'=>4294967295,'progress'=>999999]);
    check($result['code'] === 1 && (int)$result['info']['log_progress'] === 0 && (int)$result['info']['log_status'] === 0
        && taskApiBalance() === 100 && Db::name('Plog')->count() === 0, 'Client reports fabricated comment progress or credits');
}

// A complete real path: authenticated create -> pending review -> approval -> list -> claim.
taskApiSeed(); $comment=taskApiComment(false);
check((int)$comment['comment_reward_verified'] === 1 && (int)$comment['comment_status'] === 0,
    'Pending authenticated comment lacks provenance or bypassed moderation');
$row=taskApiListRow();
check($row['progress'] === 0 && $row['status'] === 0 && $row['reward_available'] === true,
    'Unapproved comment completed the task');
check((new Comment())->fieldData(['comment_id'=>$comment['comment_id']],'comment_status',1)['code'] === 1,
    'Real moderation action failed');
$row=taskApiListRow();
check($row['progress'] === 1 && $row['status'] === 1 && $row['progress_source'] === 'approved_comment',
    'Server approval did not independently advance task progress');
check(taskApi('claim_reward',['task_id'=>1])['code'] === 1 && taskApiBalance() === 120
    && Db::name('Plog')->count() === 1 && (int)Db::name('Plog')->value('plog_points') === 20,
    'Verified comment did not produce one consistent reward and ledger');
$before=taskApiState();
check(taskApi('claim_reward',['task_id'=>1])['code'] !== 1 && taskApiState() === $before,
    'Verified comment claim replay paid twice');
check(taskApi('report_progress',['task_action'=>'post_comment'])['info']['log_status'] == 2 && taskApiState() === $before,
    'Refreshing evidence reopened a paid task');

// No report_progress or task-list visit is required before claiming a real approved comment.
taskApiSeed(); taskApiComment();
check(Db::name('TaskLog')->count() === 0 && taskApi('claim_reward',['task_id'=>1])['code'] === 1
    && taskApiBalance() === 120, 'Comment reward depended on a client report or pre-created task log');
taskApiSeed(0); taskApiComment();
check(taskApi('claim_reward',['task_id'=>1])['code'] === 1 && taskApiBalance() === 100
    && (int)Db::name('Plog')->value('plog_points') === 0, 'A legitimate zero-point comment task stopped working');

foreach (['unverified','other_owner','yesterday','future','deleted','unapproved','edited'] as $case) {
    taskApiSeed(); $comment=taskApiComment(); taskApiReady();
    $where=['comment_id'=>$comment['comment_id']];
    if ($case === 'unverified') { Db::name('Comment')->where($where)->update(['comment_reward_verified'=>0]); }
    if ($case === 'other_owner') { Db::name('Comment')->where($where)->update(['user_id'=>2]); }
    if ($case === 'yesterday') { Db::name('Comment')->where($where)->update(['comment_time'=>strtotime('yesterday')]); }
    if ($case === 'future') { Db::name('Comment')->where($where)->update(['comment_time'=>time()+3600]); }
    if ($case === 'deleted') { (new Comment())->delData($where); }
    if ($case === 'unapproved') { (new Comment())->fieldData($where,'comment_status',0); }
    if ($case === 'edited') { (new Comment())->fieldData($where,'comment_content','Edited after creation'); }
    $before=taskApiState();
    check(taskApi('claim_reward',['task_id'=>1,'user_id'=>2,'progress'=>9999])['code'] !== 1 && taskApiState() === $before,
        "$case evidence or a forged owner/progress value authorized reward");
    $row=taskApiListRow();
    check($row['progress'] === 0 && $row['status'] === 0, "$case evidence was still advertised as ready to claim");
}

taskApiSeed();
Db::name('Task')->where('task_id',1)->update(['task_target'=>2]);
taskApiComment();
foreach ([1,2,3] as $_) {
    $result=taskApi('report_progress',['task_action'=>'post_comment']);
    check((int)$result['info']['log_progress'] === 1 && (int)$result['info']['log_status'] === 0,
        'Reporting the same comment multiple times increased progress');
}
taskApiComment();
check(taskApi('claim_reward',['task_id'=>1])['code'] === 1 && taskApiBalance() === 120,
    'Two distinct approved comments did not satisfy the server target');
taskApiSeed();
Db::name('Task')->where('task_id',1)->update(['task_target'=>0]); taskApiReady();
$before=taskApiState();
check(taskApi('claim_reward',['task_id'=>1])['code'] !== 1 && taskApiState() === $before
    && taskApiListRow()['reward_unavailable_reason'] === 'invalid_comment_task_configuration',
    'A zero-target task granted a reward without comment evidence');

// No trusted watch/share event exists in the current code. Preserve paid history, reject new awards.
foreach ([2=>'watch_vod',3=>'share_vod'] as $id=>$action) {
    taskApiSeed(); $before=taskApiState();
    $result=taskApi('report_progress',['task_action'=>$action]);
    check($result['code'] !== 1 && $result['info']['reward_available'] === false && taskApiState() === $before,
        "$action client report created progress");
    taskApiReady($id); $before=taskApiState();
    check(taskApi('claim_reward',['task_id'=>$id])['code'] !== 1 && taskApiState() === $before,
        "$action legacy ready flag authorized a new award");
    $row=taskApiListRow($id);
    check($row['reward_available'] === false && $row['status'] === 0 && $row['progress'] === 0
        && $row['reward_unavailable_reason'] === 'trusted_server_event_unavailable',
        "$action list advertised a claimable reward without a trusted event");
    taskApiReady($id,2);
    $paid=Db::name('TaskLog')->where(['user_id'=>1,'task_id'=>$id])->find();
    $row=taskApiListRow($id);
    check($row['status'] === 2 && Db::name('TaskLog')->where(['user_id'=>1,'task_id'=>$id])->find() === $paid,
        "$action unsupported capability erased its paid history");
}

foreach (['daily_sign','claim_reward','claim_sign_milestone','report_progress'] as $action) {
    foreach (['GET','PUT','DELETE','HEAD'] as $method) {
        taskApiSeed(); taskApiComment(); $before=taskApiState();
        check(taskApi($action,['task_id'=>1,'milestone_id'=>1,'task_action'=>'post_comment'],$method)['code'] !== 1
            && taskApiState() === $before, "$action performed a write on $method");
    }
    taskApiSeed(); $GLOBALS['comment_cookies']=[]; $before=taskApiState();
    check(taskApi($action,['task_id'=>1,'milestone_id'=>1,'task_action'=>'post_comment'])['code'] === 1401
        && taskApiState() === $before, "$action accepted an anonymous request");
}
foreach (['claim_reward'=>'task_id','claim_sign_milestone'=>'milestone_id'] as $action=>$key) {
    foreach ([null,[1],true,0,-1,'1.0','1e0','4294967296'] as $bad) {
        taskApiSeed(); taskApiComment(); $before=taskApiState();
        check(taskApi($action,[$key=>$bad])['code'] !== 1 && taskApiState() === $before,
            "$action malformed identifier caused coercion, a type error or mutation");
    }
    taskApiSeed(); $before=taskApiState();
    check(taskApi($action,[],'POST',[$key=>1])['code'] !== 1 && taskApiState() === $before,
        "$action accepted an identifier supplied only in the query string");
}
foreach ([null,[],true,1,'daily_sign','post_comment '] as $bad) {
    taskApiSeed(); $before=taskApiState();
    check(taskApi('report_progress',['task_action'=>$bad])['code'] !== 1 && taskApiState() === $before,
        'Malformed/unapproved report action caused progress or a type error');
}
taskApiSeed(); taskApiComment();
check(taskApi('claim_reward',['task_id'=>1],'POST',['task_id'=>2])['code'] === 1 && taskApiBalance() === 120,
    'Query parameters overrode the claim body');
taskApiSeed(); $before=taskApiState();
check(taskApi('claim_sign_milestone',['milestone_id'=>1,'serial_days'=>9999])['code'] !== 1 && taskApiState() === $before,
    'Client-supplied sign days authorized a milestone reward');
check(taskApi('daily_sign')['code'] === 1 && taskApiBalance() === 105, 'POST daily sign stopped working');
check(taskApi('claim_sign_milestone',['milestone_id'=>1])['code'] === 1 && taskApiBalance() === 115,
    'Milestone failed to use real server sign history');

// IDs and target counts use their installed UINT32 bounds, independent of recharge/order limits.
taskApiSeed(); taskApiComment();
Db::name('Task')->where('task_id',1)->update(['task_id'=>4294967295]);
check(taskApi('claim_reward',['task_id'=>'4294967295'])['code'] === 1 && taskApiBalance() === 120,
    'Maximum installed task identifier was rejected or clipped to a points limit');
taskApiSeed();
Db::name('SignMilestone')->where('milestone_id',1)->update(['milestone_id'=>4294967295]);
check(taskApi('daily_sign')['code'] === 1
    && taskApi('claim_sign_milestone',['milestone_id'=>'4294967295'])['code'] === 1 && taskApiBalance() === 115,
    'Maximum installed milestone identifier was rejected or clipped');
taskApiSeed();
Db::name('User')->where('user_id',1)->update(['user_id'=>4294967295]);
commentLogin(4294967295); taskApiComment();
check(taskApi('report_progress',['task_action'=>'post_comment'])['code'] === 1
    && taskApi('claim_reward',['task_id'=>1])['code'] === 1
    && (int)Db::name('User')->where('user_id',4294967295)->value('user_points') === 120
    && (int)Db::name('Plog')->value('user_id') === 4294967295,
    'Maximum installed user identifier lost ownership or could not refresh/claim');
taskApiSeed(); taskApiComment();
Db::name('Task')->where('task_id',1)->update(['task_target'=>4294967295]);
$row=taskApiListRow();
check($row['reward_available'] === true && $row['progress'] === 1 && $row['status'] === 0,
    'Maximum installed target count was treated as an invalid points amount');

// A request crossing midnight must not use today's comments to pay yesterday's task as well.
taskApiSeed(); taskApiComment();
$GLOBALS['task_model_clock']=strtotime('today')-1;
Db::name('TaskLog')->insert(['user_id'=>1,'task_id'=>1,'task_action'=>'post_comment',
    'log_date'=>date('Y-m-d',strtotime('yesterday')),'log_status'=>1,'log_progress'=>1]);
$GLOBALS['task_cross_midnight']=true;
$manager->event('before_find',static function ($query): void {
    if (!empty($GLOBALS['task_cross_midnight']) && $query->getTable() === 'audit_task_log') {
        $GLOBALS['task_cross_midnight']=false;
        $GLOBALS['task_model_clock']=time();
    }
});
$before=taskApiState();
check(taskApi('claim_reward',['task_id'=>1])['code'] !== 1 && taskApiState() === $before,
    'Request crossing midnight used new-day evidence to pay the prior day');
check(taskApi('claim_reward',['task_id'=>1])['code'] === 1 && taskApiBalance() === 120,
    'New-day comment could not be claimed once for its actual calendar day');
unset($GLOBALS['task_model_clock']);

if ($mysql) {
    // Verify the actual MySQL lock, not just a mocked claim interleaving. Approval cannot be
    // revoked between the eligibility read and the balance/ledger commit on another connection.
    taskApiSeed(); $comment=taskApiComment();
    $GLOBALS['task_lock_probe_comment']=(int)$comment['comment_id'];
    $GLOBALS['task_lock_probe_ran']=false;
    $manager->event('after_update', static function ($query): void {
        // For this fresh claim the first TaskLog UPDATE follows the locked evidence count.
        if (empty($GLOBALS['task_lock_probe_comment']) || $query->getTable() !== 'audit_task_log') { return; }
        $id=$GLOBALS['task_lock_probe_comment']; $GLOBALS['task_lock_probe_comment']=0;
        $other=new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST') ?: '127.0.0.1').';dbname=maccms_audit_membership',
            'root',getenv('MEMBERSHIP_AUDIT_PASSWORD') ?: '',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
        $other->exec('SET SESSION innodb_lock_wait_timeout=1');
        $blocked=false;
        try { $other->exec('UPDATE audit_comment SET comment_status=0 WHERE comment_id='.$id); }
        catch (PDOException $error) { $blocked=(int)($error->errorInfo[1] ?? 0) === 1205; }
        check($blocked, 'Concurrent approval revocation bypassed the real eligibility row lock');
        $GLOBALS['task_lock_probe_ran']=true;
    });
    check(taskApi('claim_reward',['task_id'=>1])['code'] === 1 && $GLOBALS['task_lock_probe_ran']
        && taskApiBalance() === 120, 'Claim did not complete under the two-connection MySQL lock probe');
    (new Comment())->fieldData(['comment_id'=>$comment['comment_id']],'comment_status',0);
    check(taskApiListRow()['status'] === 2 && taskApiBalance() === 120,
        'Review after the completed payout erased its paid history');
}

// Old databases can still publish and sign in; comment reward capability is explicitly unavailable.
taskApiSeed(); taskApiReady();
if ($mysql) { Db::execute('ALTER TABLE audit_comment DROP INDEX comment_reward_user'); }
Db::execute('ALTER TABLE audit_comment DROP COLUMN comment_reward_verified');
$manager->connect()->getSchemaInfo('audit_comment',true);
$before=taskApiState();
$result=taskApi('claim_reward',['task_id'=>1]);
check($result['code'] !== 1 && $result['info']['reward_unavailable_reason'] === 'comment_provenance_migration_required'
    && taskApiState() === $before, 'Unmigrated schema trusted legacy ready state');
$row=taskApiListRow();
check($row['reward_available'] === false && $row['status'] === 0, 'Missing migration still advertised a ready comment reward');
check(taskApi('report_progress',['task_action'=>'post_comment'])['code'] !== 1, 'Refresh invented a missing provenance column');
check(publicComment('api',['comment_mid'=>1,'comment_rid'=>1,'comment_content'=>'Ordinary old-schema comment'])['code'] === 1,
    'Reward migration requirement blocked ordinary comment publication');
check(taskApi('daily_sign')['code'] === 1, 'Missing comment provenance blocked independent daily signing');
taskApiReady(1,2);
check(taskApiListRow()['status'] === 2, 'Missing migration erased paid comment-task history');
echo "task eligibility audit: $checks checks passed on PHP " . PHP_VERSION . ($mysql ? ' / MySQL' : ' / SQLite') . "\n";
