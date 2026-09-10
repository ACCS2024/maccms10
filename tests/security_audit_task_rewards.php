<?php
/** Reward eligibility, bounded balances and ledgers share one transaction. */
require __DIR__ . '/fixtures/security_audit_task_rewards_db.php';
use think\facade\Db;
use app\common\model\TaskLog;
use app\common\util\PointsBalance;

foreach (['sign', 'task', 'milestone'] as $kind) {
    taskRewardSeed($kind);
    check(claimTaskReward($kind)['code'] === 1 && memberRow()['user_points'] === 120, "$kind valid reward failed");
    check(Db::name('Plog')->count() === 1 && (int)Db::name('Plog')->value('plog_points') === 20,
        "$kind reward and ledger disagree");
    if ($kind === 'sign') {
        check((int)Db::name('TaskLog')->value('log_status') === 2
            && (int)Db::name('SignLog')->value('sign_points') === 20, 'Sign was not synchronized with the paid task');
    }
    $before = taskRewardState();
    check(claimTaskReward($kind)['code'] !== 1 && taskRewardState() === $before, "$kind replay paid twice");

    taskRewardSeed($kind, PointsBalance::MAX - 10);
    $before = taskRewardState();
    check(claimTaskReward($kind)['code'] !== 1 && taskRewardState() === $before,
        "$kind overflow clipped balance or consumed reward eligibility");
    taskRewardSeed($kind, PointsBalance::MAX - 20);
    check(claimTaskReward($kind)['code'] === 1 && memberRow()['user_points'] === PointsBalance::MAX,
        "$kind exact-capacity reward failed");

    // Zero points intentionally retain achievement/claim semantics without attempting an increment.
    taskRewardSeed($kind, PointsBalance::MAX, 0);
    check(claimTaskReward($kind)['code'] === 1 && memberRow()['user_points'] === PointsBalance::MAX
        && Db::name('Plog')->count() === 1 && (int)Db::name('Plog')->value('plog_points') === 0,
        "$kind legitimate zero-point reward failed");
    $before = taskRewardState();
    check(claimTaskReward($kind)['code'] !== 1 && taskRewardState() === $before, "$kind zero-point claim was reopened");
    taskRewardSeed($kind, 0, PointsBalance::MAX);
    check(claimTaskReward($kind)['code'] === 1 && memberRow()['user_points'] === PointsBalance::MAX
        && (int)Db::name('Plog')->value('plog_points') === PointsBalance::MAX, "$kind full unsigned reward was truncated");

    foreach ([0, 20] as $points) {
        taskRewardSeed($kind, 100, $points);
        Db::name('User')->where('user_id', 1)->delete();
        $before = taskRewardState();
        check(claimTaskReward($kind)['code'] !== 1 && taskRewardState() === $before,
            "$kind missing recipient consumed reward eligibility");
    }
    foreach (['validation', 'throwable'] as $failure) {
        taskRewardSeed($kind);
        $flag = $failure === 'validation' ? 'member_fail_log_types' : 'member_throw_log_types';
        $GLOBALS[$flag] = [$kind === 'milestone' ? 10 : 11];
        $before = taskRewardState();
        $result = claimTaskReward($kind);
        check($result['code'] !== 1 && !str_contains($result['msg'], 'fixture') && taskRewardState() === $before,
            "$kind ledger $failure escaped, leaked details, or left partial writes");
        $GLOBALS[$flag] = [];
        check(claimTaskReward($kind)['code'] === 1 && memberRow()['user_points'] === 120,
            "$kind failed claim could not be retried");
    }
    // The loser has already read eligibility; the winner commits before it starts its transaction.
    taskRewardSeed($kind);
    $manager->beforeStart = static function () use ($kind): void {
        check(claimTaskReward($kind)['code'] === 1, "$kind interleaved winner failed");
        $GLOBALS['task_reward_winner'] = taskRewardState();
    };
    check(claimTaskReward($kind)['code'] !== 1 && taskRewardState() === $GLOBALS['task_reward_winner'],
        "$kind stale losing claimant paid again or rolled back the winner");

    foreach ([[1], true, 0, -1, '1e0'] as $badId) {
        taskRewardSeed($kind);
        $before = taskRewardState();
        check(claimTaskReward($kind, $badId)['code'] !== 1 && taskRewardState() === $before,
            "$kind malformed user identifier caused mutation or a type error");
    }
}

// A stale progress writer used to change a paid row back to status 1, enabling a second reward.
class StaleProgressTaskLog extends TaskLog {
    public bool $interleave = true;
    public function getOrCreateDaily($user_id, $task_id, $task_action, $date = null) {
        $stale = parent::getOrCreateDaily($user_id, $task_id, $task_action, $date);
        if ($this->interleave) {
            $this->interleave = false;
            Db::name('TaskLog')->where('log_id', $stale['log_id'])->update(['log_status'=>1, 'log_progress'=>1]);
            check((new TaskLog())->claimReward($user_id, $task_id)['code'] === 1, 'Progress race winner failed');
        }
        return $stale;
    }
}
taskRewardSeed('task');
Db::name('TaskLog')->where('log_id', 1)->update(['log_status'=>0, 'log_progress'=>0]);
$result = (new StaleProgressTaskLog())->addProgress(1, 'post_comment');
check($result['code'] === 1 && (int)$result['info']['log_status'] === 2
    && (int)Db::name('TaskLog')->value('log_status') === 2, 'Stale progress reopened a paid task');
$before = taskRewardState();
check((new TaskLog())->claimReward(1, 1)['code'] !== 1 && taskRewardState() === $before
    && memberRow()['user_points'] === 120 && Db::name('Plog')->count() === 1, 'Progress race allowed double payment');

// The automatic newbie detector has the same stale-write hazard.
class StaleNewbieTaskLog extends TaskLog {
    public function getOrCreateNewbie($user_id, $task_id, $task_action) {
        $stale = parent::getOrCreateNewbie($user_id, $task_id, $task_action);
        Db::name('TaskLog')->where('log_id', $stale['log_id'])->update(['log_status'=>1, 'log_progress'=>1]);
        check((new TaskLog())->claimReward($user_id, $task_id)['code'] === 1, 'Newbie race winner failed');
        return $stale;
    }
}
taskRewardSeed('task');
Db::name('TaskLog')->delete(true);
Db::name('Task')->where('task_id', 1)->update(['task_type'=>2, 'task_action'=>'bind_email']);
$result = (new StaleNewbieTaskLog())->getUserTaskStatus(1, ['user_id'=>1, 'user_email'=>'fixture@example.invalid']);
check($result['newbie_tasks'][0]['status'] === 2 && (int)Db::name('TaskLog')->value('log_status') === 2,
    'Newbie detection reopened a paid task');
$before = taskRewardState();
check((new TaskLog())->claimReward(1, 1)['code'] !== 1 && taskRewardState() === $before,
    'Newbie detection race allowed duplicate reward');

// Daily-sign cashflow has one authority even if an imported/stale task row says ready.
taskRewardSeed('sign');
Db::name('TaskLog')->insert(['user_id'=>1, 'task_id'=>1, 'task_action'=>'daily_sign', 'log_status'=>1, 'log_date'=>date('Y-m-d')]);
$before = taskRewardState();
check((new TaskLog())->claimReward(1, 1)['code'] !== 1 && taskRewardState() === $before,
    'Generic task claim paid a sign reward independently of SignLog');
check(claimTaskReward('sign')['code'] === 1 && memberRow()['user_points'] === 120
    && Db::name('Plog')->count() === 1 && (int)Db::name('TaskLog')->value('log_status') === 2,
    'Ready sign task prevented the real sign payout');

// A failure after balance + ledger writes must undo those writes and the unique sign record.
taskRewardSeed('sign');
Db::execute($mysql
    ? "CREATE TRIGGER audit_sign_sync_failure BEFORE UPDATE ON audit_task_log FOR EACH ROW
        BEGIN IF NEW.log_status = 2 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fixture sign sync failure'; END IF; END"
    : "CREATE TRIGGER audit_sign_sync_failure BEFORE UPDATE ON audit_task_log WHEN NEW.log_status = 2
        BEGIN SELECT RAISE(ABORT, 'fixture sign sync failure'); END");
$before = taskRewardState();
check(claimTaskReward('sign')['code'] !== 1 && taskRewardState() === $before,
    'Sign task synchronization failure committed a partial payout');
Db::execute('DROP TRIGGER audit_sign_sync_failure');
check(claimTaskReward('sign')['code'] === 1, 'Sign could not be retried after synchronization rollback');

taskRewardSeed('sign');
Db::execute($mysql
    ? "CREATE TRIGGER audit_sign_progress_failure BEFORE INSERT ON audit_task_log FOR EACH ROW
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fixture progress insert failure'"
    : "CREATE TRIGGER audit_sign_progress_failure BEFORE INSERT ON audit_task_log
        BEGIN SELECT RAISE(ABORT, 'fixture progress insert failure'); END");
$before = taskRewardState();
check(claimTaskReward('sign')['code'] !== 1 && taskRewardState() === $before,
    'Controlled addProgress error was ignored by the outer sign transaction');
Db::execute('DROP TRIGGER audit_sign_progress_failure');
check(claimTaskReward('sign')['code'] === 1, 'Sign progress insert failure could not be retried');

// Deterministically emulate a stale empty read followed by an existing unique-key winner.
taskRewardSeed('task');
Db::name('TaskLog')->delete(true);
$GLOBALS['task_create_race'] = true;
$manager->event('before_find', static function ($query): void {
    if (!empty($GLOBALS['task_create_race']) && $query->getTable() === 'audit_task_log') {
        $GLOBALS['task_create_race'] = false;
        Db::name('TaskLog')->insert(['user_id'=>1, 'task_id'=>1, 'task_action'=>'post_comment',
            'log_status'=>1, 'log_progress'=>1, 'log_date'=>date('Y-m-d')]);
        throw new \think\db\exception\DbEventException('fixture stale empty read');
    }
});
$existing = (new TaskLog())->getOrCreateDaily(1, 1, 'post_comment');
check((int)$existing['log_status'] === 1 && Db::name('TaskLog')->count() === 1,
    'Concurrent daily record creator did not recover the unique-key winner');

// Progress is monotonic, capped at the server target, and accepts only positive integer increments.
taskRewardSeed('task');
Db::name('TaskLog')->where('log_id', 1)->update(['log_status'=>0, 'log_progress'=>0]);
Db::name('Task')->where('task_id', 1)->update(['task_target'=>3]);
taskRewardComment(); taskRewardComment();
check((new TaskLog())->addProgress(1, 'post_comment', 1)['info']['log_progress'] === 1, 'First progress increment failed');
check((new TaskLog())->addProgress(1, 'post_comment', PointsBalance::MAX)['info']['log_progress'] === 3,
    'Progress exceeded its target or overflowed');
check((new TaskLog())->claimReward(1, 1)['code'] === 1, 'Completed progress could not be claimed');
$before = taskRewardState();
check((new TaskLog())->addProgress(1, 'post_comment')['code'] === 1 && taskRewardState() === $before,
    'Progress on a claimed task altered the claim');
foreach ([0, -1, true, [1], '1.5', '4294967296'] as $increment) {
    check((new TaskLog())->addProgress(1, 'post_comment', $increment)['code'] !== 1 && taskRewardState() === $before,
        'Malformed progress caused a type error, overflow or mutation');
}
check(PointsBalance::amount(0) === null && PointsBalance::amount(0, true) === 0
    && !PointsBalance::credit(1, 0), 'Optional zero rewards weakened the positive credit primitive');
echo "task reward audit: $checks checks passed on PHP " . PHP_VERSION . ($mysql ? ' / MySQL non-strict' : ' / SQLite') . "\n";
