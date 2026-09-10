<?php
namespace app\common\model;
use think\facade\Db;

class Visit extends Base {
    // 设置数据表（不含前缀）
    protected $name = 'visit';

    // 定义时间戳字段名
    protected $createTime = '';
    protected $updateTime = '';

    // 自动完成
    protected $auto       = [];
    protected $insert     = [];
    protected $update     = [];

    public function countData($where)
    {
        $total = $this->where($where)->count();
        return $total;
    }

    public function listData($where,$order,$page=1,$limit=20,$start=0,$field='*',$addition=1,$totalshow=1)
    {
        $page = $page > 0 ? (int)$page : 1;
        $limit = $limit ? (int)$limit : 20;
        $start = $start ? (int)$start : 0;
        if(!is_array($where)){
            $where = json_decode($where,true);
        }
        $offset = ($limit * ($page-1) + $start);
        $total = 0;
        if($totalshow==1) {
            $total = $this->where($where)->count();
        }
        $list = Db::name('Visit')->field($field)->where($where)->order($order)->limit($offset, $limit)->select()->toArray();
        $userIds = array_values(array_unique(array_filter(array_column($list, 'user_id'))));
        $userNames = $userIds ? Db::name('User')->whereIn('user_id', $userIds)->column('user_name', 'user_id') : [];
        foreach($list as $k=>$v){
            $userId = $v['user_id'] ?? 0;
            $list[$k]['visit_mid'] = $userId == 0 ? 11 : 6;
            $list[$k]['user_name'] = $userNames[$userId] ?? '';
        }
        return ['code'=>1,'msg'=>lang('data_list'),'page'=>$page,'pagecount'=>ceil($total/$limit),'limit'=>$limit,'total'=>$total,'list'=>$list];
    }

    public function infoData($where,$field='*')
    {
        if(empty($where) || !is_array($where)){
            return ['code'=>1001,'msg'=>lang('param_err')];
        }

        $info = $this->field($field)->where($where)->find();
        if (empty($info)) {
            return ['code' => 1002, 'msg' => lang('obtain_err')];
        }
        $info = $info->toArray();

        return ['code'=>1,'msg'=>lang('obtain_ok'),'info'=>$info];
    }

    public function saveData($data)
    {
        if (!is_array($data)) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        foreach (array_keys($data) as $key) {
            if (is_string($key) && strcasecmp($key, 'visit_id') === 0) {
                return self::immutableResult();
            }
        }
        // Website referrals (user_id=0) remain appendable; existing evidence never changes.
        $data = array_intersect_key($data, array_flip(['user_id', 'visit_ip', 'visit_ly']));
        $data['visit_time'] = time();
        $validate = mac_validate('Visit');
        if(!$validate->check($data)){
            return ['code'=>1001,'msg'=>lang('param_err').'：'.$validate->getError() ];
        }

        try {
            if ($this->insert($data) !== 1) {
                return ['code'=>1002, 'msg'=>lang('save_err')];
            }
        } catch (\Throwable $error) {
            return ['code'=>1002, 'msg'=>lang('save_err')];
        }
        return ['code'=>1,'msg'=>lang('save_ok')];
    }

    public function delData($where)
    {
        return self::immutableResult();
    }

    public function fieldData($where,$col,$val)
    {
        return self::immutableResult();
    }

    private static function immutableResult(): array
    {
        return ['code'=>1005, 'msg'=>'访问凭证（含网站引荐）仅供查阅，不支持修改、删除或清空'];
    }
}
