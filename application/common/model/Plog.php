<?php
namespace app\common\model;
use think\facade\Db;

class Plog extends Base {
    // 设置数据表（不含前缀）
    protected $name = 'plog';

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
        $list = Db::name('Plog')->where($where)->order($order)->limit($offset, $limit)->select()->toArray();

        $user_ids=[];
        foreach($list as $k=>&$v){
            if($v['user_id'] >0){
                $user_ids[$v['user_id']] = $v['user_id'];
            }
        }

        unset($v);
        if (!empty($user_ids)) {
            $userNames = Db::name('User')->whereIn('user_id', array_values($user_ids))->column('user_name', 'user_id');
            foreach ($list as $key => $row) {
                $list[$key]['user_name'] = $userNames[$row['user_id']] ?? '';
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

    public function saveData($data)
    {
        if (array_key_exists('plog_id', $data)) { return self::immutableResult(); }
        unset($data['plog_user_hidden']);
        $data['plog_time'] = time();

        $validate = mac_validate('Plog');
        if(!$validate->check($data)){
            return ['code'=>1001,'msg'=>lang('param_err').'：'.$validate->getError() ];
        }

        $plogType = (int)$data['plog_type'];
        if ($data['user_id'] == 0 || $plogType < 1 || $plogType > 11) {
            return ['code'=>1002,'msg'=>lang('param_err')];
        }

        $data = $this->filterFields($data);
        $res = $this->insert($data);
        if($res !== 1){
            return ['code'=>1004,'msg'=>lang('save_err').'：'.$this->getError() ];
        }
        return ['code'=>1,'msg'=>lang('save_ok')];
    }

    /** Administrative callers may read original ledgers but cannot erase them. */
    public function delData($where)
    {
        return self::immutableResult();
    }

    public function fieldData($where, $col, $val)
    {
        return self::immutableResult();
    }

    private static function immutableResult(): array
    {
        return ['code'=>1005, 'msg'=>'原始账变仅供查阅，不支持修改或删除'];
    }

    private function supportsUserHiding(): bool
    {
        return in_array('plog_user_hidden', Db::name('Plog')->getTableFields(), true);
    }

    /** Old databases remain readable until their explicit visibility migration runs. */
    public function listForUser($userId, array $where, $order, $page = 1, $limit = 20): array
    {
        $userId = \app\common\util\PointsBalance::amount($userId);
        if ($userId === null) { throw new \InvalidArgumentException('A valid ledger owner is required'); }
        $where['user_id'] = $userId;
        if ($this->supportsUserHiding()) { $where['plog_user_hidden'] = 0; }
        return $this->listData($where, $order, $page, $limit);
    }

    /** Hide the selected owner's rows without changing their financial fields. */
    public function hideForUser($userId, array $ids): array
    {
        $userId = \app\common\util\PointsBalance::amount($userId);
        if ($userId === null || count($ids) > 1000) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        foreach ($ids as $id) {
            if (\app\common\util\PointsBalance::amount($id) === null) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        }
        try {
            if (!$this->supportsUserHiding()) {
                return ['code'=>1006, 'msg'=>'账变隐藏功能尚未完成升级，原始记录已保留，请联系管理员'];
            }
            $query = Db::name('Plog')->where('user_id', $userId)->where('plog_user_hidden', 0);
            if ($ids !== []) { $query->whereIn('plog_id', $ids); }
            if ($query->update(['plog_user_hidden'=>1]) === false) {
                return ['code'=>1001, 'msg'=>lang('set_err')];
            }
            return ['code'=>1, 'msg'=>'已从我的账变中隐藏'];
        } catch (\Throwable $error) {
            return ['code'=>1001, 'msg'=>lang('set_err')];
        }
    }
}
