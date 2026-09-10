<?php
namespace app\common\model;
use think\facade\Db;

class Cash extends Base {
    // 设置数据表（不含前缀）
    protected $name = 'cash';

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
        $total = $this->where($where)->count();
        $list = Db::name('Cash')->where($where)->order($order)->limit($offset, $limit)->select()->toArray();

        $user_ids=[];
        foreach($list as $k=>&$v){
            if($v['user_id'] >0){
                $user_ids[$v['user_id']] = $v['user_id'];
            }
        }

        if(!empty($user_ids)){
            $where2=[];
            $where2['user_id'] = $user_ids;
            $order='user_id desc';
            $user_list = (new \app\common\model\User())->listData($where2,$order,1,999);
            $user_list = mac_array_rekey($user_list['list'],'user_id');

            foreach($list as $k=>&$v){
                $list[$k]['user_name'] = $user_list[$v['user_id']]['user_name'] ?? '';
            }
        }

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

    public function saveData($param)
    {
        $settings = $GLOBALS['config']['user'] ?? [];
        if (($settings['cash_status'] ?? '0') != '1') {
            return ['code'=>1005,'msg'=>lang('model/cash/not_open')];
        }
        $money = $param['cash_money'] ?? null;
        $ratio = $settings['cash_ratio'] ?? null;
        if (!is_numeric($money) || !is_finite((float)$money) || (float)$money <= 0
            || !is_numeric($ratio) || !is_finite((float)$ratio) || (float)$ratio <= 0) {
            return ['code'=>1001,'msg'=>lang('param_err')];
        }
        // 数据库金额保留两位小数；按实际可存储金额计算积分。
        $money = round((float)$money, 2);
        if ($money <= 0) {
            return ['code'=>1001,'msg'=>lang('param_err')];
        }
        if ($money < (float)($settings['cash_min'] ?? 0)) {
            return ['code'=>1006,'msg'=>lang('model/cash/min_money_err').'：'.($settings['cash_min'] ?? 0)];
        }
        $rawPoints = $money * (float)$ratio;
        if (!is_finite($rawPoints) || $rawPoints >= PHP_INT_MAX || $rawPoints < 1) {
            return ['code'=>1001,'msg'=>lang('param_err')];
        }
        $points = (int)$rawPoints;
        if ($points > 65535) {
            return ['code'=>1001,'msg'=>lang('param_err')];
        }
        $userId = (int)($GLOBALS['user']['user_id'] ?? 0);
        if ($userId < 1) {
            return ['code'=>1002,'msg'=>lang('param_err')];
        }
        $data = [
            'cash_money' => $money,
            'user_id' => $userId,
            'cash_points' => $points,
            'cash_time' => time(),
            'cash_status' => 0,
        ];
        foreach (['cash_bank_name', 'cash_bank_no', 'cash_payee_name'] as $field) {
            if (!isset($param[$field]) || !is_scalar($param[$field])) {
                return ['code'=>1001,'msg'=>lang('param_err')];
            }
            $data[$field] = htmlspecialchars(urldecode(trim((string)$param[$field])));
        }
        $validate = mac_validate('Cash');
        if (!$validate->check($data)) {
            return ['code'=>1001,'msg'=>lang('param_err').'：'.$validate->getError()];
        }

        Db::startTrans();
        try {
            $user = Db::name('User')->where('user_id', $userId)->lock(true)->find();
            if (!$user || (int)$user['user_points'] < $points) {
                Db::rollback();
                return ['code'=>1007,'msg'=>lang('model/cash/mush_money_err')];
            }
            // 余额在数据库内检查并转为冻结积分，不能用请求开始时的全局快照覆盖。
            $changed = Db::name('User')->where('user_id', $userId)
                ->where('user_points', '>=', $points)
                ->dec('user_points', $points)->inc('user_points_froze', $points)->update();
            if ($changed !== 1) {
                Db::rollback();
                return ['code'=>1007,'msg'=>lang('model/cash/mush_money_err')];
            }
            $cashId = $this->insertGetId($this->filterFields($data));
            if ((int)$cashId < 1) {
                throw new \RuntimeException('cash insert failed');
            }
            // 老库 cash_points 是 SMALLINT，且连接允许 MySQL 静默截断。
            // 回读核实记账数值；兼容已扩容的库，并避免扣全额却只记录部分积分。
            $stored = $this->where('cash_id', $cashId)->find();
            $reserved = Db::name('User')->where('user_id', $userId)->find();
            if (!$stored || !$reserved || (int)$stored['cash_points'] !== $points
                || round((float)$stored['cash_money'], 2) !== $money
                || (int)$reserved['user_points'] !== (int)$user['user_points'] - $points
                || (int)$reserved['user_points_froze'] !== (int)$user['user_points_froze'] + $points) {
                throw new \RuntimeException('cash ledger values were truncated');
            }
            Db::commit();
        } catch (\Throwable $e) {
            Db::rollback();
            return ['code'=>1004,'msg'=>lang('save_err')];
        }
        return ['code'=>1,'msg'=>lang('save_ok')];
    }

    public function delData($where)
    {
        if (empty($where) || !is_array($where)) {
            return ['code'=>1001,'msg'=>lang('param_err')];
        }
        Db::startTrans();
        try {
            // 与审核使用相同的行锁顺序；退款、删除不可被另一个审核/删除请求穿插。
            $list = $this->where($where)->order('cash_id')->lock(true)->select()->toArray();
            foreach ($list as $row) {
                if ((int)$row['cash_status'] === 0) {
                    $points = (int)$row['cash_points'];
                    if ($points < 1) {
                        throw new \RuntimeException('invalid frozen points');
                    }
                    $changed = Db::name('User')->where('user_id', $row['user_id'])
                        ->where('user_points_froze', '>=', $points)
                        ->inc('user_points', $points)->dec('user_points_froze', $points)->update();
                    if ($changed !== 1) {
                        throw new \RuntimeException('cash refund failed');
                    }
                }
                if ($this->where('cash_id', $row['cash_id'])->delete() !== 1) {
                    throw new \RuntimeException('cash delete failed');
                }
            }
            Db::commit();
        } catch (\Throwable $e) {
            Db::rollback();
            return ['code'=>1005,'msg'=>lang('del_err')];
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

    public function auditData($where)
    {
        if (empty($where) || !is_array($where)) {
            return ['code'=>1001,'msg'=>lang('param_err')];
        }
        Db::startTrans();
        try {
            $list = $this->where($where)->where('cash_status', 0)
                ->order('cash_id')->lock(true)->select()->toArray();
            foreach ($list as $row) {
                $points = (int)$row['cash_points'];
                if ($points < 1) {
                    throw new \RuntimeException('invalid frozen points');
                }
                $changed = $this->where('cash_id', $row['cash_id'])->where('cash_status', 0)->update([
                    'cash_status' => 1,
                    'cash_time_audit' => time(),
                ]);
                if ($changed !== 1) {
                    throw new \RuntimeException('cash state changed');
                }
                $changed = Db::name('User')->where('user_id', $row['user_id'])
                    ->where('user_points_froze', '>=', $points)->setDec('user_points_froze', $points);
                if ($changed !== 1) {
                    throw new \RuntimeException('cash settlement failed');
                }
                $log = (new \app\common\model\Plog())->saveData([
                    'user_id' => $row['user_id'],
                    'plog_type' => 9,
                    'plog_points' => $points,
                ]);
                if ((int)($log['code'] ?? 0) !== 1) {
                    throw new \RuntimeException('cash points log failed');
                }
            }
            Db::commit();
        } catch (\Throwable $e) {
            Db::rollback();
            return ['code'=>1005,'msg'=>lang('save_err')];
        }
        return ['code'=>1,'msg'=>'审核成功'];
    }

}
