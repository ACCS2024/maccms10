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
        if(false === $res){
            return ['code'=>1002,'msg'=>lang('save_err').'：'.$this->getError() ];
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
     */
    public function notify($order_code,$pay_type,$paid_yuan=null)
    {
        if(empty($order_code) || empty($pay_type)){
            return ['code'=>1001,'msg'=>lang('param_err')];
        }

        $where = [];
        $where['order_code'] = $order_code;
        $order = (new \app\common\model\Order())->infoData($where);
        if($order['code']>1){
            return $order;
        }
        if($order['info']['order_status'] == 1){
            return ['code'=>1,'msg'=>lang('model/order/pay_over')];
        }

        // 调用方提供金额时必须是有效正数；null 保留给未提供金额的旧渠道。
        // 不允许 0、非数字或非有限值绕过已经启用的金额核对。
        if ($paid_yuan !== null) {
            if (!is_numeric($paid_yuan) || !is_finite((float)$paid_yuan) || (float)$paid_yuan <= 0) {
                return ['code'=>2005,'msg'=>'order amount mismatch'];
            }
            $paid = round((float)$paid_yuan, 2);
            $expect = round((float)$order['info']['order_price'], 2);
            if ($paid > 0 && $expect > 0 && ($paid + 0.01) < $expect) {
                return ['code'=>2005,'msg'=>'order amount mismatch'];
            }
        }

        $where2=[];
        $where2['user_id'] = $order['info']['user_id'];
        $user = (new \app\common\model\User())->infoData($where2);
        if($user['code']>1){
            return $user;
        }

        Db::startTrans();
        try{
            $update = [];
            $update['order_status'] = 1;
            $update['order_pay_time'] = time();
            $update['order_pay_type'] = $pay_type;
            // 只有 pending -> paid 的唯一成功者可以入账。事务本身不能阻止
            // 两个请求在事务开始前同时读到 pending，必须检查条件更新行数。
            $res = $this->where('order_id', $order['info']['order_id'])
                ->where('order_status', 0)->update($update);
            if ($res !== 1) {
                Db::rollback();
                $current = $this->where('order_id', $order['info']['order_id'])->find();
                if ($res === 0 && $current && (int)$current['order_status'] === 1) {
                    return ['code'=>1,'msg'=>lang('model/order/pay_over')];
                }
                return ['code'=>2002,'msg'=>lang('model/order/update_status_err')];
            }

            $where2 = [];
            $where2['user_id'] = $user['info']['user_id'];
            $res = (new \app\common\model\User())->where($where2)->setInc('user_points',$order['info']['order_points']);
            if($res !== 1){
                Db::rollback();
                return ['code'=>2003,'msg'=>lang('model/order/update_user_points_err')];
            }

            //积分日志
            $data = [];
            $data['user_id'] = $user['info']['user_id'];
            $data['plog_type'] = 1;
            $data['plog_points'] = $order['info']['order_points'];
            $log = (new \app\common\model\Plog())->saveData($data);
            if ((int)($log['code'] ?? 0) !== 1) {
                throw new \RuntimeException('order points log failed');
            }

            $remarks = json_decode((string)($order['info']['order_remarks'] ?? ''), true);
            if(!empty($remarks) && is_array($remarks) && ($remarks['biz'] ?? '') === 'member_upgrade'){
                $user_latest = (new \app\common\model\User())->infoData(['user_id' => $user['info']['user_id']]);
                if($user_latest['code'] > 1){
                    Db::rollback();
                    return $user_latest;
                }
                $upgrade_res = (new \app\common\model\User())->upgradeByPaidOrder($order['info'], $user_latest['info']);
                if($upgrade_res['code'] > 1){
                    Db::rollback();
                    return $upgrade_res;
                }
            }

            Db::commit();
            return ['code'=>1,'msg'=>lang('model/order/pay_ok')];
        }catch (\Throwable $e){
            Db::rollback();
            return ['code'=>2004,'msg'=>lang('save_err')];
        }

    }

}
