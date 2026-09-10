<?php
/** Real comment submission, login and reward models in the same isolated database. */
require __DIR__ . '/security_audit_comment_submission_db.php';
require __DIR__ . '/security_audit_task_tables.php';
use think\facade\Db;
if ($mysql) {
    if (!preg_match('/CREATE TABLE `mac_plog` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) { throw new RuntimeException('Ledger DDL missing'); }
    Db::execute('DROP TABLE IF EXISTS audit_plog');
    Db::execute(str_replace('`mac_plog`', '`audit_plog`', $match[0]));
} else {
    Db::execute('ALTER TABLE audit_comment ADD COLUMN comment_reward_verified INTEGER NOT NULL DEFAULT 0');
    Db::execute('ALTER TABLE audit_user ADD COLUMN user_points INTEGER NOT NULL DEFAULT 0 CHECK(user_points BETWEEN 0 AND 4294967295)');
    Db::execute('CREATE TABLE audit_plog (plog_id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,plog_type INTEGER,
        plog_points INTEGER CHECK(plog_points BETWEEN 0 AND 4294967295),plog_time INTEGER,plog_remarks TEXT)');
}
function taskApiSeed(int $points = 20): void {
    commentSeed(); commentLogin();
    Db::name('User')->where('user_id',1)->update(['user_points'=>100]);
    foreach (['task','task_log','sign_log','sign_milestone','sign_milestone_log','plog'] as $table) {
        Db::name($table)->delete(true);
    }
    foreach ([1=>'post_comment',2=>'watch_vod',3=>'share_vod',4=>'daily_sign'] as $id=>$action) {
        Db::name('Task')->insert(['task_id'=>$id,'task_action'=>$action,'task_points'=>$id===4 ? 5 : $points]);
    }
    Db::name('SignMilestone')->insert(['milestone_id'=>1,'milestone_days'=>1,'milestone_points'=>10]);
}
function taskApi(string $action, array $body = [], string $method = 'POST', array $query = []): array {
    $request = commentRequest($body,$method,$query);
    $controller = (new ReflectionClass(app\api\controller\Task::class))->newInstanceWithoutConstructor();
    return $controller->$action($request);
}
function taskApiComment(bool $approved = true): array {
    unset($GLOBALS['comment_cookies']['comment_timespan']);
    $GLOBALS['config']['comment']['audit'] = $approved ? '0' : '1';
    $result = publicComment('api',['comment_mid'=>1,'comment_rid'=>1,'comment_content'=>'Real server comment']);
    check($result['code'] === 1, 'Real comment submission failed before testing task eligibility');
    return Db::name('Comment')->order('comment_id desc')->find();
}
function taskApiReady(int $taskId = 1, int $status = 1): void {
    Db::name('TaskLog')->where(['user_id'=>1,'task_id'=>$taskId])->delete();
    $action = Db::name('Task')->where('task_id',$taskId)->value('task_action');
    Db::name('TaskLog')->insert(['user_id'=>1,'task_id'=>$taskId,'task_action'=>$action,'log_date'=>date('Y-m-d'),
        'log_progress'=>99,'log_status'=>$status,'log_points'=>$status===2 ? 20 : 0]);
}
function taskApiState(): array {
    return [Db::name('User')->field('user_id,user_points')->order('user_id')->select()->toArray(), commentRows(),
        Db::name('TaskLog')->order('log_id')->select()->toArray(), Db::name('SignLog')->order('sign_id')->select()->toArray(),
        Db::name('SignMilestoneLog')->order('log_id')->select()->toArray(), Db::name('Plog')->order('plog_id')->select()->toArray()];
}
function taskApiBalance(): int { return (int)Db::name('User')->where('user_id',1)->value('user_points'); }
function taskApiListRow(int $id = 1): array {
    $result = taskApi('get_task_list',[],'GET');
    check($result['code'] === 1, 'Authenticated task list failed');
    foreach ($result['info']['daily_tasks'] as $task) { if ((int)$task['task_id'] === $id) { return $task; } }
    throw new RuntimeException('Expected task absent from the response');
}
