<?php
namespace app\common\model;
use think\facade\Db;

class Order extends Base {
    // 设置数据表（不含前缀）
    protected $name = 'order';

    // 定义时间戳字段名
    protected $createTime = '';
    protected $updateTime = '';

    // 自动完成
    protected $auto       = [];
    protected $insert     = [];
    protected $update     = [];


    public function listData($where,$order,$page=1,$limit=20,$start=0)
    {
        $page = $page > 0 ? (int)$page : 1;
        $limit = $limit ? (int)$limit : 20;
        $start = $start ? (int)$start : 0;
        if(!is_array($where)){
            $where = json_decode($where,true);
        }
        $offset = ($limit * ($page-1) + $start);
        $total = $this->alias('o')->where($where)->count();
        $list = Db::name('Order')->alias('o')
            ->field('o.*,u.user_name')
            ->join(config('database.connections.mysql.prefix').'user u','o.user_id = u.user_id','left')
            ->where($where)
            ->order($order)
            ->limit($offset, $limit)
            ->select()->toArray();


        return ['code'=>1,'msg'=>lang('data_list'),'page'=>$page,'pagecount'=>ceil($total/$limit),'limit'=>$limit,'total'=>$total,'list'=>$list];
    }

    public function infoData($where,$field='*')
    {
        if(empty($where) || !is_array($where)){
            return ['code'=>1001,'msg'=>lang('param_err')];
        }
        $info = $this->field($field)->where($where)->find();

        if(empty($info)){
            return ['code'=>1002,'msg'=>lang('obtain_err')];
        }
        $info = $info->toArray();

        return ['code'=>1,'msg'=>lang('obtain_ok'),'info'=>$info];
    }

    public function saveData($data)
    {
        $validate = mac_validate('Order');
        if(!$validate->check($data)){
            return ['code'=>1001,'msg'=>lang('param_err').'：'.$validate->getError() ];
        }

        $data['order_time'] = time();
        try {
            if(!empty($data['order_id'])){
                $where=[];
                $where['order_id'] = $data['order_id'];
                $data = $this->filterFields($data);
                $res = $this->where($where)->update($data);
            }
            else{
                $data = $this->filterFields($data);
                $res = $this->insert($data);
            }
        } catch (\Throwable $e) {
            // Unique order-code conflicts and storage failures are controlled errors.
            // Never expose the SQL statement or an existing order's details.
            return ['code'=>1002,'msg'=>lang('save_err')];
        }
        if(false === $res){
            return ['code'=>1002,'msg'=>lang('save_err')];
        }
        return ['code'=>1,'msg'=>lang('save_ok')];
    }

    public function delData($where)
    {
        $res = $this->where($where)->delete();
        if($res===false){
            return ['code'=>1001,'msg'=>lang('del_err').'：'.$this->getError() ];
        }
        return ['code'=>1,'msg'=>lang('del_ok')];
    }

    public function fieldData($where,$col,$val)
    {
        if(!isset($col) || !isset($val)){
            return ['code'=>1001,'msg'=>lang('param_err')];
        }

        $data = [];
        $data[$col] = $val;
        $res = $this->where($where)->update($data);
        if($res===false){
            return ['code'=>1001,'msg'=>lang('set_err').'：'.$this->getError() ];
        }
        return ['code'=>1,'msg'=>lang('set_ok')];
    }

    /*
     * 充值回调函数接口
     * 任何充值接口，回调接口里直接调用该接口更新订单状态、用户积分
     * pay_type预留值alipay,weixin,bank，可以继续自定义最长10个字符
     * paid_yuan 必须是外部支付通知的实际金额；null 仅兼容可信内部自定义渠道。
     */
    public function notify($order_code, $pay_type, $paid_yuan = null)
    {
        if (!self::notificationText($order_code, 30) || !self::notificationText($pay_type, 10)) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        $failure = ['code'=>2004, 'msg'=>lang('save_err')];
        $success = ['code'=>1, 'msg'=>lang('model/order/pay_ok')];
        $mismatch = ['code'=>2005, 'msg'=>'order amount mismatch'];
        if (($blocked = \app\common\util\OrderTransaction::blockedResult()) !== null) { return $blocked; }
        // Only trusted custom/internal callers retain the historical omitted-amount contract.
        $paidMinor = $paid_yuan === null ? null : self::amountMinorUnits($paid_yuan);
        if (($paid_yuan !== null && $paidMinor === null) || ($paid_yuan === null
            && in_array(strtolower($pay_type), ['alipay', 'weixin', 'epay', 'codepay', 'zhapay', 'jeepay'], true))) {
            return $mismatch;
        }
        $scope = null;
        try {
            \app\common\util\FinancialTransaction::requireTables([Db::name('Order')->getTable(), Db::name('User')->getTable(), Db::name('Plog')->getTable()]);
            $scope = new \app\common\util\OrderTransaction();
            $scope->begin();
            // Lock the current writer row before selecting its beneficiary, points or membership intent.
            // Legacy databases without the required unique index must not settle ambiguous order codes.
            $orders = Db::name('Order')->master()->where('order_code', $order_code)->lock(true)->limit(2)->select()->toArray();
            if (count($orders) !== 1) { return $scope->rollback(['code'=>1002, 'msg'=>lang('obtain_err')]); }
            $order = $orders[0];
            $orderId = \app\common\util\PointsBalance::amount($order['order_id'] ?? null);
            $userId = \app\common\util\PointsBalance::amount($order['user_id'] ?? null);
            if ($orderId === null || $userId === null) { throw new \RuntimeException('Invalid stored payment identity'); }
            $scope->record($orderId, $userId);
            if ($paidMinor !== null && self::amountMinorUnits($order['order_price']) !== $paidMinor) {
                return $scope->rollback($mismatch);
            }
            if (in_array($order['order_status'], [1, '1'], true)) {
                return $scope->rollback(['code'=>1, 'msg'=>lang('model/order/pay_over')]);
            }
            if (!in_array($order['order_status'], [0, '0'], true)) { throw new \RuntimeException('Order is not pending'); }
            $points = \app\common\util\PointsBalance::amount($order['order_points'] ?? null);
            $user = Db::name('User')->master()->where('user_id', $userId)->lock(true)->find();
            $balance = $user ? \app\common\util\PointsBalance::amount($user['user_points'] ?? null, true) : null;
            if ($points === null || $points > 16777215 || $balance === null || $balance > \app\common\util\PointsBalance::MAX - $points) {
                return $scope->rollback(['code'=>2003, 'msg'=>lang('model/order/update_user_points_err')]);
            }
            $update = ['order_status'=>1, 'order_pay_time'=>time(), 'order_pay_type'=>$pay_type];
            if (Db::name('Order')->where('order_id', $orderId)->where('order_status', 0)->update($update) !== 1) {
                return $scope->rollback(['code'=>2002, 'msg'=>lang('model/order/update_status_err')]);
            }
            $scope->assertActive();
            if (!\app\common\util\PointsBalance::credit($userId, $points)) {
                return $scope->rollback(['code'=>2003, 'msg'=>lang('model/order/update_user_points_err')]);
            }
            $expectedBalance = $balance + $points;
            if ((string)Db::name('User')->master()->where('user_id', $userId)->value('user_points') !== (string)$expectedBalance) {
                throw new \RuntimeException('Payment balance was not stored exactly');
            }
            $scope->assertActive();
            $data = ['user_id'=>$userId, 'plog_type'=>1, 'plog_points'=>$points, 'plog_remarks'=>''];
            $ledger = new \app\common\model\Plog();
            if (($ledger->saveData($data)['code'] ?? null) !== 1) { throw new \RuntimeException('Order points log failed'); }
            $ledgerId = $ledger->getLastInsID();
            $scope->assertActive();
            $remarks = json_decode((string)($order['order_remarks'] ?? ''), true);
            if (is_array($remarks) && ($remarks['biz'] ?? '') === 'member_upgrade') {
                $upgrade = (new \app\common\model\User())->upgradeByPaidOrder($order, $user);
                if ($upgrade['code'] !== 1) {
                    return $scope->rollback(isset($upgrade['info']['outcome']) ? $failure : $upgrade);
                }
                $upgradePoints = \app\common\util\PointsBalance::amount($remarks['upgrade_points'] ?? null);
                if ($upgradePoints === null) { throw new \RuntimeException('Invalid membership charge'); }
                $expectedBalance -= $upgradePoints;
            }
            // Driver acknowledgements and affected-row counts do not prove exact storage in non-strict SQL.
            $storedOrder = Db::name('Order')->master()->where('order_id', $orderId)->find();
            foreach (array_merge(array_intersect_key($order, array_flip(['order_id','user_id','order_code','order_price','order_points','order_remarks'])), $update) as $field=>$expected) {
                if (!$storedOrder || (string)$storedOrder[$field] !== (string)$expected) { throw new \RuntimeException('Payment order was not stored exactly'); }
            }
            $storedLedger = Db::name('Plog')->master()->where('plog_id', $ledgerId)->find();
            foreach ($data as $field=>$expected) {
                if (!$storedLedger || (string)$storedLedger[$field] !== (string)$expected) { throw new \RuntimeException('Payment ledger was not stored exactly'); }
            }
            if ((string)Db::name('User')->master()->where('user_id', $userId)->value('user_points') !== (string)$expectedBalance) {
                throw new \RuntimeException('Final payment balance differs from its ledgers');
            }
            $scope->assertActive();
            return $scope->commit($success);
        } catch (\Throwable $error) {
            return $scope !== null ? $scope->rollback($failure) : $failure;
        }
    }

    /** Bound callback text to the installation columns before any query or implicit conversion. */
    private static function notificationText($value, int $characters): bool
    {
        return is_string($value) && $value !== '' && strlen($value) <= $characters * 4
            && mb_check_encoding($value, 'UTF-8') && mb_strlen($value, 'UTF-8') <= $characters
            && trim($value) !== '' && !preg_match('/[\x00-\x1f\x7f]/', $value);
    }

    /** Canonical positive minor units for the order_price DECIMAL(12,2) column. */
    private static function amountMinorUnits($amount): ?string
    {
        $minor = \app\common\util\OrderAmount::minorUnits($amount);
        return $minor === null ? null : (string)$minor;
    }

}
