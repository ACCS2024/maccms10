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
        $data['plog_time'] = time();

        $validate = mac_validate('Plog');
        if(!$validate->check($data)){
            return ['code'=>1001,'msg'=>lang('param_err').'：'.$validate->getError() ];
        }

        $plogType = (int)$data['plog_type'];
        if ($data['user_id'] == 0 || $plogType < 1 || $plogType > 11) {
            return ['code'=>1002,'msg'=>lang('param_err')];
        }

        if(!empty($data['plog_id'])){
            $where=[];
            $where['plog_id'] = $data['plog_id'];
            $data = $this->filterFields($data);
            $res = $this->where($where)->update($data);
        }
        else{
            $data = $this->filterFields($data);
            $res = $this->insert($data);
        }
        if(false === $res){
            return ['code'=>1004,'msg'=>lang('save_err').'：'.$this->getError() ];
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

}