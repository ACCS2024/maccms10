<?php
namespace app\common\model;
use think\facade\Db;

class TaskLog extends Base {
    protected $name = 'task_log';
    protected $createTime = '';
    protected $updateTime = '';
    protected $auto   = [];
    protected $insert = [];
    protected $update = [];

    public function countData($where)
    {
        return $this->where($where)->count();
    }

    public function listData($where, $order, $page = 1, $limit = 20, $start = 0, $field = '*')
    {
        $page = $page > 0 ? (int)$page : 1;
        $limit = $limit ? (int)$limit : 20;
        $start = $start ? (int)$start : 0;
        if (!is_array($where)) {
            $where = json_decode($where, true);
        }
        $offset = ($limit * ($page - 1) + $start);
        $total = $this->where($where)->count();
        $list = Db::name('TaskLog')->field($field)->where($where)->order($order)->limit($offset, $limit)->select()->toArray();
        return ['code' => 1, 'msg' => lang('data_list'), 'page' => $page, 'pagecount' => ceil($total / $limit), 'limit' => $limit, 'total' => $total, 'list' => $list];
    }

    public function delData($where)
    {
        // The record also prevents a second reward for the same task and day.
        return ['code' => 1005, 'msg' => '任务奖励凭证仅供查阅，不支持删除或清空'];
    }

    /**
     * 获取或创建用户的每日任务记录
     */
    public function getOrCreateDaily($user_id, $task_id, $task_action, $date = null)
    {
        $date = $date ?: date('Y-m-d');
        $where = [
            'user_id' => $user_id,
            'task_id' => $task_id,
            'log_date' => $date,
        ];
        $log = Db::name('TaskLog')->where($where)->find();
        if ($log) {
            return $log;
        }
        $data = [
            'user_id' => $user_id,
            'task_id' => $task_id,
            'task_action' => $task_action,
            'log_progress' => 0,
            'log_status' => 0,
            'log_points' => 0,
            'log_date' => $date,
            'log_time' => time(),
            'log_claim_time' => 0,
        ];
        try {
            Db::name('TaskLog')->insert($data);
        } catch (\think\db\exception\PDOException $e) {
            $error = $e->getData()['PDO Error Info'] ?? [];
            if (($error['SQLSTATE'] ?? '') !== '23000'
                || !in_array((int)($error['Driver Error Code'] ?? 0), [1062, 19], true)) {
                throw $e;
            }
            // A competing creator may have won the existing unique user/task/date key.
            $existing = Db::name('TaskLog')->where($where)->lock(true)->find();
            if ($existing) {
                return $existing;
            }
            throw $e;
        }
        $data['log_id'] = Db::name('TaskLog')->getLastInsID();
        return $data;
    }

    /**
     * 获取用户新手任务记录（固定日期 2000-01-01）
     */
    public function getOrCreateNewbie($user_id, $task_id, $task_action)
    {
        return $this->getOrCreateDaily($user_id, $task_id, $task_action, '2000-01-01');
    }

    /**
     * 增加每日任务进度
     */
    public function addProgress($user_id, $task_action, $increment = 1)
    {
        $user_id = \app\common\util\PointsBalance::amount($user_id);
        $increment = \app\common\util\PointsBalance::amount($increment);
        if ($user_id === null || $increment === null || !is_string($task_action)
            || $task_action === '' || strlen($task_action) > 50) {
            return ['code' => 1002, 'msg' => lang('param_err')];
        }
        $task = Db::name('Task')->where(['task_action' => $task_action, 'task_status' => 1])->find();
        if (!$task) {
            return ['code' => 1001, 'msg' => lang('task/not_found')];
        }
        Db::startTrans();
        try {
            $log = $this->getOrCreateDaily($user_id, $task['task_id'], $task_action);
            // Re-read after locking: a stale progress writer must never reopen a paid claim.
            $log = Db::name('TaskLog')->where('log_id', $log['log_id'])->lock(true)->find();
            if (!$log) {
                throw new \RuntimeException('task progress missing');
            }
            if ((int)$log['log_status'] >= 1) {
                Db::commit();
                return ['code' => 1, 'msg' => lang('task/already_done'), 'info' => $log];
            }
            $new_progress = min((int)$log['log_progress'] + $increment, (int)$task['task_target']);
            $update = ['log_progress' => $new_progress];
            if ($new_progress >= (int)$task['task_target']) {
                $update['log_status'] = 1;
            }
            $changed = Db::name('TaskLog')->where('log_id', $log['log_id'])->where('log_status', 0)->update($update);
            if ($changed !== 1) {
                throw new \RuntimeException('task progress rejected');
            }
            Db::commit();
            return ['code' => 1, 'msg' => 'ok', 'info' => array_merge($log, $update)];
        } catch (\Throwable $e) {
            Db::rollback();
            return ['code' => 1002, 'msg' => lang('save_err')];
        }
    }

    /**
     * 领取任务奖励
     */
    public function claimReward($user_id, $task_id)
    {
        $user_id = \app\common\util\PointsBalance::amount($user_id);
        $task_id = \app\common\util\PointsBalance::amount($task_id);
        if ($user_id === null || $task_id === null) {
            return ['code' => 1001, 'msg' => lang('param_err')];
        }
        $task = Db::name('Task')->where(['task_id' => $task_id, 'task_status' => 1])->find();
        if (!$task) {
            return ['code' => 1001, 'msg' => lang('task/not_found')];
        }

        $date = ($task['task_type'] == 1) ? date('Y-m-d') : '2000-01-01';
        $where = [
            'user_id' => $user_id,
            'task_id' => $task_id,
            'log_date' => $date,
        ];
        $log = Db::name('TaskLog')->where($where)->find();
        $commentTask = $task['task_action'] === 'post_comment';
        if ($log && (int)$log['log_status'] === 2) {
            return ['code' => 1004, 'msg' => lang('task/already_claimed')];
        }
        $capability = $this->rewardCapability($task);
        if (!$capability['reward_available']) {
            return ['code'=>1006, 'msg'=>'该任务暂不支持领取奖励', 'info'=>$capability];
        }
        if (!$log && !$commentTask) {
            return ['code' => 1002, 'msg' => lang('task/not_completed')];
        }
        if (!$commentTask && $log['log_status'] == 0) {
            return ['code' => 1003, 'msg' => lang('task/not_completed')];
        }
        // SignLog owns the sign reward and its ledger. Never pay it a second time here.
        if ($task['task_action'] === 'daily_sign') {
            return ['code' => 1003, 'msg' => lang('task/not_completed')];
        }

        // 发放积分（事务保护，与 SignLog::doSign / SignMilestone::claimMilestone 一致）
        $points = \app\common\util\PointsBalance::amount($task['task_points'], true);
        if ($points === null) {
            return ['code' => 1005, 'msg' => lang('save_err')];
        }

        Db::startTrans();
        try {
            if (!Db::name('User')->where('user_id', $user_id)->lock(true)->find()) {
                throw new \RuntimeException('task recipient missing');
            }
            if ($commentTask) {
                $log = $log ?: $this->getOrCreateDaily($user_id, $task_id, 'post_comment', $date);
                $log = Db::name('TaskLog')->where('log_id', $log['log_id'])->lock(true)->find();
                if (!$log || (int)$log['log_status'] === 2) {
                    Db::rollback();
                    return ['code'=>1004, 'msg'=>lang('task/already_claimed')];
                }
                // Historical ready flags and client reports are not evidence of a real approved comment.
                $progress = $this->verifiedCommentCount($user_id, $date, true);
                if ($progress < (int)$task['task_target']) {
                    Db::rollback();
                    return ['code'=>1003, 'msg'=>lang('task/not_completed')];
                }
                $log = $this->writeCommentProgress($log, min($progress, (int)$task['task_target']), 1);
            }
            // 原子认领:仅当 log_status 仍为 1(已完成未领取)时置 2;受影响行数==1 才算抢到本次领取。
            // 修复 TOCTOU:此处是对已存在行的 UPDATE,不受唯一索引保护(不同于 SignLog/SignMilestone 的 INSERT),
            // 并发/重放请求若都读到 log_status==1 会重复发放积分。必须用条件 UPDATE + 受影响行数闸门。
            $claim = Db::name('TaskLog')->where('log_id', $log['log_id'])->where('log_status', 1)->update([
                'log_status' => 2,
                'log_points' => $points,
                'log_claim_time' => time(),
            ]);
            if ($claim !== 1) {
                // 0 行:已被(并发的)其它请求领取
                Db::rollback();
                return ['code' => 1004, 'msg' => lang('task/already_claimed')];
            }

            if ($points > 0 && !\app\common\util\PointsBalance::credit($user_id, $points)) {
                throw new \RuntimeException('task credit rejected');
            }

            // 积分日志 plog_type=11 任务/签到奖励（与 SignLog::doSign 一致；9 保留为提现）
            $plog = [
                'user_id' => $user_id,
                'plog_type' => 11,
                'plog_points' => $points,
                'plog_remarks' => lang('task/reward_log', [$task['task_name'], $points]),
            ];
            $plogRes = (new \app\common\model\Plog())->saveData($plog);
            if (empty($plogRes['code']) || (int)$plogRes['code'] !== 1) {
                throw new \Exception('plog');
            }

            Db::commit();
        } catch (\Throwable $e) {
            Db::rollback();
            return ['code' => 1005, 'msg' => lang('save_err')];
        }

        return ['code' => 1, 'msg' => lang('task/claim_ok'), 'info' => ['points' => $points]];
    }

    /** Advertise what the server can actually verify; a client timer/share click is insufficient. */
    public function rewardCapability(array $task): array
    {
        if (in_array($task['task_action'], ['watch_vod','share_vod'], true)) {
            return ['reward_available'=>false, 'progress_source'=>'unavailable',
                'reward_unavailable_reason'=>'trusted_server_event_unavailable'];
        }
        if ($task['task_action'] === 'post_comment') {
            if ((int)$task['task_type'] !== 1 || \app\common\util\PointsBalance::amount($task['task_target']) === null) {
                return ['reward_available'=>false, 'progress_source'=>'approved_comment',
                    'reward_unavailable_reason'=>'invalid_comment_task_configuration'];
            }
            try {
                if (!(new Comment())->supportsRewardVerification()) {
                    return ['reward_available'=>false, 'progress_source'=>'approved_comment',
                        'reward_unavailable_reason'=>'comment_provenance_migration_required'];
                }
            } catch (\Throwable $error) {
                return ['reward_available'=>false, 'progress_source'=>'approved_comment',
                    'reward_unavailable_reason'=>'comment_verification_unavailable'];
            }
            return ['reward_available'=>true, 'progress_source'=>'approved_comment', 'reward_unavailable_reason'=>''];
        }
        return ['reward_available'=>true, 'progress_source'=>'server', 'reward_unavailable_reason'=>''];
    }

    private function verifiedCommentCount(int $userId, string $date, bool $lock = false): int
    {
        $now = time();
        $start = strtotime($date);
        $end = strtotime('+1 day', $start);
        $query = Db::name('Comment')->where('user_id', $userId)->where('comment_reward_verified', 1)
            ->where('comment_status', 1)->where('comment_time', '>=', $start)->where('comment_time', '<', $end)
            ->where('comment_time', '<=', $now);
        if ($lock) { $query->lock(true); }
        return (int)$query->count();
    }

    /** Caller locks the task row and owns a transaction. Never reopen a completed payment. */
    private function writeCommentProgress(array $log, int $progress, int $status): array
    {
        if ((int)$log['log_status'] === 2) { return $log; }
        $update = ['log_progress'=>$progress, 'log_status'=>$status];
        if ((int)$log['log_progress'] !== $progress || (int)$log['log_status'] !== $status) {
            if (Db::name('TaskLog')->where('log_id', $log['log_id'])->whereIn('log_status', [0,1])->update($update) !== 1) {
                throw new \RuntimeException('verified comment progress update failed');
            }
        }
        return array_merge($log, $update);
    }

    /** Optional legacy refresh endpoint; progress is always recomputed from persisted server evidence. */
    public function refreshCommentProgress($userId, array $task = []): array
    {
        $userId = \app\common\util\PointsBalance::amount($userId);
        if ($userId === null) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        $task = $task ?: Db::name('Task')->where(['task_action'=>'post_comment','task_status'=>1])->find();
        if (!$task || $task['task_action'] !== 'post_comment') { return ['code'=>1001, 'msg'=>lang('task/not_found')]; }
        $capability = $this->rewardCapability($task);
        if (!$capability['reward_available']) {
            return ['code'=>1006, 'msg'=>'评论奖励暂不可用', 'info'=>$capability];
        }
        $date = date('Y-m-d');
        Db::startTrans();
        try {
            if (!Db::name('User')->where('user_id', $userId)->lock(true)->find()) {
                throw new \RuntimeException('comment task owner missing');
            }
            $log = $this->getOrCreateDaily($userId, $task['task_id'], 'post_comment', $date);
            $log = Db::name('TaskLog')->where('log_id', $log['log_id'])->lock(true)->find();
            if (!$log) { throw new \RuntimeException('comment task missing'); }
            if ((int)$log['log_status'] !== 2) {
                $progress = min($this->verifiedCommentCount($userId, $date, true), (int)$task['task_target']);
                $log = $this->writeCommentProgress($log, $progress, $progress >= (int)$task['task_target'] ? 1 : 0);
            }
            Db::commit();
            return ['code'=>1, 'msg'=>'ok', 'info'=>array_merge($log, $capability)];
        } catch (\Throwable $error) {
            Db::rollback();
            return ['code'=>1002, 'msg'=>lang('save_err')];
        }
    }

    /**
     * 获取用户今日所有任务状态
     */
    public function getUserTaskStatus($user_id, $user_info = [])
    {
        $tasks = (new \app\common\model\Task())->getActiveTasks();
        $today = date('Y-m-d');

        // 取今日每日任务记录
        $daily_logs = Db::name('TaskLog')->where([
            'user_id' => $user_id,
            'log_date' => $today,
        ])->select();
        $daily_map = [];
        foreach ($daily_logs as $l) {
            $daily_map[$l['task_id']] = $l;
        }

        // 取新手任务记录
        $newbie_logs = Db::name('TaskLog')->where([
            'user_id' => $user_id,
            'log_date' => '2000-01-01',
        ])->select();
        $newbie_map = [];
        foreach ($newbie_logs as $l) {
            $newbie_map[$l['task_id']] = $l;
        }

        // 组装每日任务
        $daily_result = [];
        foreach ($tasks['daily'] as $t) {
            $log = isset($daily_map[$t['task_id']]) ? $daily_map[$t['task_id']] : null;
            $t = array_merge($t, $this->rewardCapability($t));
            if ($t['task_action'] === 'post_comment' && (!$log || (int)$log['log_status'] !== 2) && $t['reward_available']) {
                $refreshed = $this->refreshCommentProgress($user_id, $t);
                if (($refreshed['code'] ?? null) === 1) {
                    $log = $refreshed['info'];
                } else {
                    $t['reward_available'] = false;
                    $t['reward_unavailable_reason'] = 'comment_verification_unavailable';
                }
            }
            $t['progress'] = $log ? (int)$log['log_progress'] : 0;
            $t['status'] = $log ? (int)$log['log_status'] : 0;
            if (!$t['reward_available'] && $t['status'] !== 2) { $t['progress'] = 0; $t['status'] = 0; }
            $daily_result[] = $t;
        }

        // 组装新手任务（检测型策略A）
        $newbie_result = [];
        foreach ($tasks['newbie'] as $t) {
            $t = array_merge($t, $this->rewardCapability($t));
            $log = isset($newbie_map[$t['task_id']]) ? $newbie_map[$t['task_id']] : null;
            $detected = $this->detectNewbieCompletion($t['task_action'], $user_info);

            if ($detected && (!$log || $log['log_status'] == 0)) {
                // 检测到已完成，自动更新记录
                $log_record = $this->getOrCreateNewbie($user_id, $t['task_id'], $t['task_action']);
                Db::name('TaskLog')->where('log_id', $log_record['log_id'])->where('log_status', 0)->update([
                    'log_progress' => $t['task_target'],
                    'log_status' => 1,
                ]);
                $current = Db::name('TaskLog')->where('log_id', $log_record['log_id'])->find();
                $t['progress'] = (int)($current['log_progress'] ?? 0);
                $t['status'] = (int)($current['log_status'] ?? 0);
            } else {
                $t['progress'] = $log ? (int)$log['log_progress'] : 0;
                $t['status'] = $log ? (int)$log['log_status'] : 0;
            }
            if (!$t['reward_available'] && $t['status'] !== 2) { $t['progress'] = 0; $t['status'] = 0; }
            $newbie_result[] = $t;
        }

        // 今日已获积分
        $today_earned = (int)Db::name('TaskLog')->where([
            'user_id' => $user_id,
            'log_date' => $today,
            'log_status' => 2,
        ])->sum('log_points');

        return [
            'daily_tasks' => $daily_result,
            'newbie_tasks' => $newbie_result,
            'today_earned' => $today_earned,
        ];
    }

    /**
     * 检测新手任务是否已完成（策略A - 零侵入）
     */
    protected function detectNewbieCompletion($action, $user_info)
    {
        if (empty($user_info)) return false;

        switch ($action) {
            case 'bind_phone':
                return !empty($user_info['user_phone']);
            case 'bind_email':
                return !empty($user_info['user_email']);
            case 'set_portrait':
                return !empty($user_info['user_portrait']);
            case 'complete_profile':
                return !empty($user_info['user_nick_name']);
            case 'first_pay':
                $order_count = Db::name('Order')->where([
                    'user_id' => $user_info['user_id'],
                    'order_status' => 1,
                ])->count();
                return $order_count > 0;
            default:
                return false;
        }
    }
}
