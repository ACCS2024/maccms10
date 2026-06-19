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
            ->join('__USER__ u','o.user_id = u.user_id','left')
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
            $res = $this->where($where)->update($data);
        }
        else{
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

        // 安全加固:回调金额二次核对(防改价/低付高额到账)。仅当调用方传入可解析的正数金额、
        // 且明显低于订单应付额(order_price,单位:元;留 0.01 容差)时拒绝入账。无法判定
        // (null / 0 / 不可解析)一律放行——各渠道金额字段/单位不一,宁可漏挡也不误伤正常支付,
        // 故调用方只对“元”单位、且确无误的金额传值(微信 fen 已 /100,其余本就为元)。
        if ($paid_yuan !== null) {
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
            $res = $this->where($where)->update($update);
            if($res===false){
                Db::rollback();
                return ['code'=>2002,'msg'=>lang('model/order/update_status_err')];
            }

            $where2 = [];
            $where2['user_id'] = $user['info']['user_id'];
            $res = (new \app\common\model\User())->where($where2)->setInc('user_points',$order['info']['order_points']);
            if($res===false){
                Db::rollback();
                return ['code'=>2003,'msg'=>lang('model/order/update_user_points_err')];
            }

            //积分日志
            $data = [];
            $data['user_id'] = $user['info']['user_id'];
            $data['plog_type'] = 1;
            $data['plog_points'] = $order['info']['order_points'];
            (new \app\common\model\Plog())->saveData($data);

            $remarks = json_decode($order['info']['order_remarks'], true);
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
        }catch (\Exception $e){
            Db::rollback();
            return ['code'=>2004,'msg'=>$e->getMessage()];
        }

    }

}