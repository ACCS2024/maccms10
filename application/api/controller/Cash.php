<?php

namespace app\api\controller;

use app\common\util\CashRead;
use app\common\util\MemberWrite;
use app\common\util\OrderAmount;
use app\common\util\PointsBalance;

/**
 * 提现管理 API
 *
 * 提供用户积分提现的申请、列表查询、删除等功能。
 * 个人记录需验证 Cookie 或已启用的 Bearer；配置接口提供公开的提现规则。
 */
class Cash extends Base
{
    use PublicApi;

    public function __construct()
    {
        $this->persistExpiredMemberGroup = false;
        parent::__construct();
        $this->check_config();
    }

    /**
     * 辅助：检查登录
     */
    private function _checkLogin()
    {
        $check = MemberWrite::identity();
        if ($check['code'] !== 1) {
            return ['ok' => false, 'user_id' => 0, 'response' => json($check)];
        }
        return ['ok' => true, 'user_id' => (int)$check['info']['user_id'], 'response' => null];
    }

    /**
     * 获取提现列表
     * GET /api.php/cash/get_list?page=1&limit=20
     *
     * 请求字段：  page    int  可选，页码，默认1
     * 请求字段：  limit   int  可选，每页条数，默认20，最大100
     * 请求字段：  status  int  可选，提现状态筛选（0=待审核，1=已审核）
     * 响应 JSON：{code:1, msg:'获取成功', info:{page, pagecount, limit, total, list:[...]}}
     */
    public function get_list(\think\Request $request)
    {
        if ($request->method(true) !== 'GET' || $request->method() !== 'GET') { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        $auth = $this->_checkLogin();
        if (!$auth['ok']) return $auth['response'];

        $param = CashRead::member($request->get());
        if ($param === null) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }

        $where = ['user_id' => $auth['user_id']];

        if ($param['status'] !== '') {
            $where['cash_status'] = $param['status'];
        }

        $order = 'cash_id desc';
        $res   = (new \app\common\model\Cash())->listData($where, $order, $param['page'], $param['limit']);
        if ($res['code'] !== 1) { return json($res); }

        return json([
            'code' => 1,
            'msg'  => '获取成功',
            'info' => $res,
        ]);
    }

    /**
     * 获取提现详情
     * GET /api.php/cash/get_detail?cash_id=1
     *
     * 请求字段：  cash_id  int  必填，提现记录ID
     * 响应 JSON：{code:1, msg:'获取成功', info:{...}}
     */
    public function get_detail(\think\Request $request)
    {
        if ($request->method(true) !== 'GET' || $request->method() !== 'GET') { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        $auth = $this->_checkLogin();
        if (!$auth['ok']) return $auth['response'];

        $cash_id = PointsBalance::amount($request->get()['cash_id'] ?? null);
        if ($cash_id === null) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }

        $where = [
            'cash_id' => $cash_id,
            'user_id' => $auth['user_id'],
        ];

        $res = (new \app\common\model\Cash())->infoData($where);
        return json($res);
    }

    /**
     * 提交提现申请
     * POST /api.php/cash/create
     *
     * 请求字段：  cash_money      float   必填，提现金额（单位：元）
     * 请求字段：  request_id      string  必填，64 位小写十六进制随机请求编号，重试必须沿用原编号
     * 请求字段：  cash_bank_name  string  必填，银行名称
     * 请求字段：  cash_bank_no    string  必填，银行账号
     * 请求字段：  cash_payee_name string  必填，收款人姓名
     * 响应 JSON：{code:1, msg:'保存成功'}
     *
     * 说明：
     * - 提现需后台开启提现功能（cash_status=1）
     * - 提现金额不能低于后台设置的最小提现金额（cash_min）
     * - 提现所需积分 = 提现金额 × 提现兑换比例（cash_ratio），不足一个积分向上取整
     * - 提现后对应积分会冻结，待管理员审核后正式扣除
     */
    public function create(\think\Request $request)
    {
        $identity = \app\common\util\MemberWrite::authorize($request);
        if ($identity['code'] !== 1) { return json($identity); }
        // 安全加固:按 IP 温和限流(默认开启),防刷提现请求垃圾/CPU 打满
        if (!mac_fe_write_throttle('fe_cash', 120, 10)) {
            return json(['code' => 1005, 'msg' => lang('frequently')]);
        }
        $res = (new \app\common\model\Cash())->saveRequestForUser($identity['info']['user_id'], $request->post());
        return json($res);
    }

    /**
     * 删除提现记录
     * POST /api.php/cash/del
     *
     * 请求字段：  ids  string  可选，提现记录ID列表，逗号分隔（与 all 二选一）
     * 请求字段：  all  string  可选，传 "1" 表示删除全部
     * 响应 JSON：{code:1, msg:'删除成功'}
     *
     * 说明：
     * - 仅能删除当前登录用户的提现记录
     * - 未审核的提现记录删除后，冻结积分会自动恢复
     */
    public function del(\think\Request $request)
    {
        $identity = \app\common\util\MemberWrite::authorize($request);
        if ($identity['code'] !== 1) { return json($identity); }
        $ids = \app\common\util\LogSelection::ids($request->post());
        if ($ids === null) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        $where = ['user_id'=>$identity['info']['user_id']];
        if ($ids !== []) { $where['cash_id'] = $ids; }
        return json((new \app\common\model\Cash())->delData($where, ['type'=>'user', 'id'=>$identity['info']['user_id']]));
    }

    /**
     * 获取提现配置信息
     * GET /api.php/cash/get_config
     *
     * 响应 JSON：{code:1, msg:'获取成功', info:{cash_status, cash_min, cash_ratio, cash_min_decimal, cash_ratio_decimal}}
     *
     * 说明：
     * - cash_status: 提现功能开关（0=关闭, 1=开启）
     * - cash_min: 最小提现金额（单位：元）
     * - cash_ratio: 兑换比例（1元 = 多少积分）
     * - *_decimal: 精确十进制字符串；新客户端应使用这些字段，积分扣减仍由服务端计算
     */
    public function get_config(\think\Request $request)
    {
        if ($request->method(true) !== 'GET' || $request->method() !== 'GET') { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        $user_config = $GLOBALS['config']['user'] ?? [];
        if (!is_array($user_config)) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        $user_config += ['cash_status'=>0, 'cash_min'=>null, 'cash_ratio'=>1];
        if (!in_array($user_config['cash_status'], [0,1,'0','1'], true)) {
            return json(['code'=>1001, 'msg'=>lang('param_err')]);
        }
        $minimum = OrderAmount::minimum($user_config['cash_min']);
        $rate = OrderAmount::rateDecimal($user_config['cash_ratio']);
        if ($minimum === null || $rate === null) { return json(['code'=>1001, 'msg'=>lang('param_err')]); }
        $money = OrderAmount::decimal($minimum);

        return json([
            'code' => 1,
            'msg'  => '获取成功',
            'info' => [
                'cash_status' => intval($user_config['cash_status'] ?? 0),
                'cash_min'    => (float)$money,
                'cash_ratio'  => str_contains($rate, '.') ? (float)$rate : (int)$rate,
                'cash_min_decimal' => $money,
                'cash_ratio_decimal' => $rate,
            ],
        ]);
    }
}
