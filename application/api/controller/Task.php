<?php
namespace app\api\controller;
use think\facade\Request;

class Task extends Base
{
    use PublicApi;

    public function __construct()
    {
        parent::__construct();
        $this->check_config();
    }

    /**
     * 获取任务列表及用户完成状态
     * GET /api.php/Task/get_task_list
     */
    public function get_task_list(\think\Request $request)
    {
        $check = (new \app\common\model\User())->checkLogin();
        if ($check['code'] > 1) {
            return json(['code' => 1401, 'msg' => lang('task/login_required')]);
        }
        $user_id = intval($check['info']['user_id']);
        $user_info = $check['info'];

        $task_status = (new \app\common\model\TaskLog())->getUserTaskStatus($user_id, $user_info);
        $sign_info = (new \app\common\model\SignLog())->getSignInfo($user_id);

        return json([
            'code' => 1,
            'msg' => lang('obtain_ok'),
            'info' => [
                'daily_tasks' => $task_status['daily_tasks'],
                'newbie_tasks' => $task_status['newbie_tasks'],
                'sign_info' => $sign_info,
                'today_earned' => $task_status['today_earned'],
                'user_points' => intval($user_info['user_points']),
            ],
        ]);
    }

    /**
     * 每日签到
     * POST /api.php/Task/daily_sign
     */
    public function daily_sign(\think\Request $request)
    {
        if (!$request->isPost()) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        $check = (new \app\common\model\User())->checkLogin();
        if ($check['code'] > 1) {
            return json(['code' => 1401, 'msg' => lang('task/login_required')]);
        }
        $user_id = intval($check['info']['user_id']);
        $res = (new \app\common\model\SignLog())->doSign($user_id);
        return json($res);
    }

    /**
     * 获取签到信息（含里程碑）
     * GET /api.php/Task/get_sign_info
     */
    public function get_sign_info(\think\Request $request)
    {
        $check = (new \app\common\model\User())->checkLogin();
        if ($check['code'] > 1) {
            return json(['code' => 1401, 'msg' => lang('task/login_required')]);
        }
        $user_id = intval($check['info']['user_id']);
        $sign_info = (new \app\common\model\SignLog())->getSignInfo($user_id);

        return json([
            'code' => 1,
            'msg' => lang('obtain_ok'),
            'info' => $sign_info,
        ]);
    }

    /**
     * 领取签到里程碑奖励
     * POST /api.php/Task/claim_sign_milestone
     * @param milestone_id 里程碑ID
     */
    public function claim_sign_milestone(\think\Request $request)
    {
        if (!$request->isPost()) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        $check = (new \app\common\model\User())->checkLogin();
        if ($check['code'] > 1) {
            return json(['code' => 1401, 'msg' => lang('task/login_required')]);
        }
        $user_id = intval($check['info']['user_id']);
        $param = $request->post();

        $milestone_id = \app\common\util\PointsBalance::amount($param['milestone_id'] ?? null);
        if ($milestone_id === null) {
            return json(['code' => 1001, 'msg' => lang('param_err')]);
        }

        // 获取用户当前连续签到天数
        $sign_info = (new \app\common\model\SignLog())->getSignInfo($user_id);
        $serial_days = $sign_info['serial_days'];

        $res = (new \app\common\model\SignMilestone())->claimMilestone($user_id, $milestone_id, $serial_days);
        return json($res);
    }

    /**
     * 领取任务奖励
     * POST /api.php/Task/claim_reward
     * @param task_id 任务ID
     */
    public function claim_reward(\think\Request $request)
    {
        if (!$request->isPost()) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        $check = (new \app\common\model\User())->checkLogin();
        if ($check['code'] > 1) {
            return json(['code' => 1401, 'msg' => lang('task/login_required')]);
        }
        $user_id = intval($check['info']['user_id']);
        $param = $request->post();

        $task_id = \app\common\util\PointsBalance::amount($param['task_id'] ?? null);
        if ($task_id === null) {
            return json(['code' => 1001, 'msg' => lang('param_err')]);
        }

        $res = (new \app\common\model\TaskLog())->claimReward($user_id, $task_id);
        return json($res);
    }

    /**
     * 兼容旧客户端的任务刷新入口；不接受客户端自报的完成次数
     * POST /api.php/Task/report_progress
     * @param task_action 任务动作标识 (watch_vod/share_vod/post_comment)
     */
    public function report_progress(\think\Request $request)
    {
        if (!$request->isPost()) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        $check = (new \app\common\model\User())->checkLogin();
        if ($check['code'] > 1) {
            return json(['code' => 1401, 'msg' => lang('task/login_required')]);
        }
        $user_id = intval($check['info']['user_id']);
        $param = $request->post();

        $task_action = $param['task_action'] ?? null;
        $allowed = ['watch_vod', 'share_vod', 'post_comment'];
        if (!is_string($task_action) || !in_array($task_action, $allowed, true)) {
            return json(['code' => 1001, 'msg' => lang('param_err')]);
        }
        if ($task_action !== 'post_comment') {
            return json(['code'=>1006, 'msg'=>'该任务尚无可验证的服务端完成事件', 'info'=>[
                'reward_available'=>false, 'progress_source'=>'unavailable',
                'reward_unavailable_reason'=>'trusted_server_event_unavailable',
            ]]);
        }
        $res = (new \app\common\model\TaskLog())->refreshCommentProgress($user_id);
        return json($res);
    }
}
