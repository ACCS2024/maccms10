<?php
/** Paid task and sign records must survive ordinary deletion and continue preventing repeat rewards. */
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_task_rewards_db.php';
require __DIR__.'/fixtures/security_audit_reward_retention_admin.php';
use think\facade\Db;

foreach (['task', 'sign'] as $kind) {
    taskRewardSeed($kind);
    check(claimTaskReward($kind)['code'] === 1 && memberRow()['user_points'] === 120
        && Db::name('Plog')->count() === 1, 'The original '.$kind.' claim did not succeed');
    $before = taskRewardState();
    $taskId = (int)Db::name('TaskLog')->value('log_id');
    $models = [new app\common\model\TaskLog()];
    if ($kind === 'sign') { $models[] = new app\common\model\SignLog(); }
    foreach ($models as $model) {
        $field = $model instanceof app\common\model\SignLog ? 'sign_id' : 'log_id';
        $id = (int)$model->value($field);
        foreach ([[$field=>$id], [[$field, 'in', [$id]]], [[$field, '>', 0]], [], true, null, 'invalid'] as $where) {
            check($model->delData($where)['code'] === 1005 && taskRewardState() === $before,
                get_class($model).' deletion changed balances, ledger or reward evidence');
        }
    }
    foreach (['GET', 'POST'] as $method) {
        foreach ([[], ['ids'=>(string)$taskId], ['all'=>'1'], ['ids'=>[$taskId], 'all'=>[]]] as $parameters) {
            $result = retentionAdmin('Task', 'log_del', $parameters, $method);
            check($result['code'] === 0 && str_contains($result['msg'], '凭证') && taskRewardState() === $before,
                'Admin '.$method.' task log deletion changed original evidence');
        }
    }
    check(claimTaskReward($kind)['code'] !== 1 && taskRewardState() === $before, 'Deletion reopened '.$kind.' rewards');
    check((new app\common\model\TaskLog())->claimReward(1, 1)['code'] !== 1
        && taskRewardState() === $before, 'The task center paid an already claimed '.$kind.' reward');
    if ($kind === 'sign') {
        $info = (new app\common\model\SignLog())->getSignInfo(1);
        check($info['is_signed_today'] && $info['total_signs'] === 1 && $info['serial_days'] === 1
            && $info['month_total_points'] === 20, 'Sign retention lost daily or streak evidence');
    }
    $page = retentionAdmin('Task', 'log');
    check(count($page['data']['list']) === 1 && (int)$page['data']['list'][0]['log_status'] === 2,
        'The real admin list did not return the retained paid record');
    $html = retentionRender($page);
    retentionReadOnlyPage($html, 'Task log');
    check(str_contains($html, $kind === 'task' ? 'post_comment' : 'daily_sign')
        && str_contains($html, date('Y-m-d')), 'The real nonempty task template failed to render');
    check(taskRewardState() === $before, 'Read-only task rendering mutated financial records');
}

// Zero-point tasks still occupy their daily slot and remain visible evidence.
foreach (['task', 'sign'] as $kind) {
    taskRewardSeed($kind, 100, 0);
    check(claimTaskReward($kind)['code'] === 1 && memberRow()['user_points'] === 100, 'Zero-point '.$kind.' no longer works');
    $before = taskRewardState();
    check((new app\common\model\TaskLog())->delData([])['code'] === 1005
        && (new app\common\model\SignLog())->delData([])['code'] === 1005
        && claimTaskReward($kind)['code'] !== 1 && taskRewardState() === $before, 'Zero-point evidence was discarded or replayed');
}
// The ordinary interface is uniformly read-only, including pending and historical records.
taskRewardSeed('task');
foreach ([0, 1, 2] as $status) {
    Db::name('TaskLog')->where('log_id', 1)->update(['log_status'=>$status, 'log_date'=>'2020-01-01']);
    $before = taskRewardState();
    check((new app\common\model\TaskLog())->delData(['log_status'=>$status])['code'] === 1005
        && taskRewardState() === $before, 'Pending/historical task evidence was silently discarded');
}
taskRewardSeed('sign');
Db::name('SignLog')->insert(['user_id'=>1, 'sign_date'=>date('Y-m-d', strtotime('-1 day')),
    'sign_time'=>time()-86400, 'sign_points'=>20, 'sign_serial_days'=>3]);
$before = taskRewardState();
check((new app\common\model\SignLog())->delData([])['code'] === 1005 && taskRewardState() === $before,
    'Historical sign deletion shortened a streak');
check(claimTaskReward('sign')['info']['serial_days'] === 4, 'Retained history did not contribute to the next sign streak');

taskRewardSeed('task');
Db::name('TaskLog')->where('log_id', 1)->update(['task_action'=>'<b>retained</b>']);
$html = retentionRender(retentionAdmin('Task', 'log'));
check(str_contains($html, '&lt;b&gt;retained&lt;/b&gt;') && !str_contains($html, '<b>retained</b>'),
    'Task list emitted unescaped historical content');
echo 'Task/sign retention: '.$checks.' checks passed on PHP '.PHP_VERSION.' ('.($mysql ? 'MySQL' : 'SQLite').")\n";
