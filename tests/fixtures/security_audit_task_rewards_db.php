<?php
/** Installed reward tables and real ORM. Uses the dedicated MEMBERSHIP audit database only. */
require __DIR__ . '/security_audit_membership_db.php';
use think\facade\Db;
require __DIR__ . '/security_audit_task_tables.php';
if ($mysql) {
    if (!preg_match('/CREATE TABLE `mac_comment` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) { throw new RuntimeException('Comment DDL missing'); }
    Db::execute('DROP TABLE IF EXISTS audit_comment');
    Db::execute(str_replace('`mac_comment`', '`audit_comment`', $match[0]));
} else {
    Db::execute('CREATE TABLE audit_comment (comment_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
        comment_status INTEGER DEFAULT 1, comment_reward_verified INTEGER DEFAULT 0, comment_time INTEGER,
        comment_mid INTEGER, comment_rid INTEGER, comment_name TEXT, comment_content TEXT)');
    // The current installed ledger schema supports the same unsigned INT bound as the balance.
    Db::execute('DROP TABLE audit_plog');
    Db::execute('CREATE TABLE audit_plog (plog_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, plog_type INTEGER,
        plog_points INTEGER CHECK(plog_points BETWEEN 0 AND 4294967295), plog_time INTEGER, plog_remarks TEXT)');
}
function taskRewardSeed(string $kind, int $balance = 100, int $points = 20): void {
    membershipSeed($balance);
    foreach (['task_log', 'task', 'sign_log', 'sign_milestone_log', 'sign_milestone', 'comment'] as $table) {
        Db::execute('DELETE FROM audit_' . $table);
    }
    if ($kind === 'milestone') {
        Db::name('SignMilestone')->insert(['milestone_id'=>1, 'milestone_days'=>1, 'milestone_points'=>$points]);
    } else {
        Db::name('Task')->insert(['task_id'=>1, 'task_action'=>$kind === 'sign' ? 'daily_sign' : 'post_comment', 'task_points'=>$points]);
        if ($kind === 'task') {
            taskRewardComment();
            Db::name('TaskLog')->insert(['log_id'=>1, 'user_id'=>1, 'task_id'=>1, 'task_action'=>'post_comment',
                'log_status'=>1, 'log_progress'=>1, 'log_date'=>date('Y-m-d')]);
        }
    }
}
function taskRewardComment(array $values = []): void {
    Db::name('Comment')->insert($values + ['user_id'=>1, 'comment_status'=>1, 'comment_reward_verified'=>1,
        'comment_time'=>time(), 'comment_mid'=>1, 'comment_rid'=>1, 'comment_name'=>'fixture', 'comment_content'=>'Verified fixture comment']);
}
function claimTaskReward(string $kind, $userId = 1): array {
    return match ($kind) {
        'sign' => (new app\common\model\SignLog())->doSign($userId),
        'task' => (new app\common\model\TaskLog())->claimReward($userId, 1),
        'milestone' => (new app\common\model\SignMilestone())->claimMilestone($userId, 1, 1),
    };
}
function taskRewardState(): array {
    return [membershipState(), Db::name('TaskLog')->order('log_id')->select()->toArray(),
        Db::name('SignLog')->order('sign_id')->select()->toArray(),
        Db::name('SignMilestoneLog')->order('log_id')->select()->toArray()];
}
