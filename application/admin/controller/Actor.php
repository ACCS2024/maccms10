<?php
namespace app\admin\controller;
use think\facade\Db;
use app\common\util\Pinyin;

class Actor extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    public function data()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page'] ?? 0) < 1 ? 1 : $param['page'];
        $param['limit'] = intval($param['limit'] ?? 0) < 1 ? $this->_pagesize : $param['limit'];

        $where = [];
        if (!empty($param['type'])) {
            $_t = (int)$param['type'];
            $where[] = function($q) use ($_t) {
                $q->where('type_id', $_t)->whereOr('type_id_1', $_t);
            };
        }
        if (!empty($param['level'])) {
            $where['actor_level'] = $param['level'];
        }
        if (in_array($param['status'] ?? '', ['0', '1'])) {
            $where['actor_status'] = $param['status'];
        }
        if(!empty($param['pic'])){
            if($param['pic'] == '1'){
                $where['actor_pic'] = '';
            }
            elseif($param['pic'] == '2'){
                $where[] = ['actor_pic', 'like', 'http%'];
            }
            elseif($param['pic'] == '3'){
                $where[] = ['actor_pic', 'like', '%#err%'];
            }
        }
        if(!empty($param['wd'])){
            $param['wd'] = htmlspecialchars(urldecode($param['wd']));
            mac_apply_like_where($where, 'actor_name', $param['wd']);
        }

        $order='actor_time desc';
        $res = (new \app\common\model\Actor())->listData($where,$order,$param['page'],$param['limit']);

        $this->assign('list', $res['list']);
        $this->assign('total', $res['total']);
        $this->assign('page', $res['page']);
        $this->assign('limit', $res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param', $param);

        $type_tree = (new \app\common\model\Type())->getCache('type_tree');
        $this->assign('type_tree', $type_tree);

        $this->assign('title', lang('admin/actor/title'));
        return $this->fetch('admin@actor/index');
    }

    public function info()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::post();
            $res = (new \app\common\model\Actor())->saveData($param);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }

        $id = \think\facade\Request::param("id");
        $where=[];
        $where['actor_id'] = $id;
        $res = (new \app\common\model\Actor())->infoData($where);
        $info = $res['info'];
        $this->assign('info',$info);

        $type_tree = (new \app\common\model\Type())->getCache('type_tree');
        $this->assign('type_tree', $type_tree);

        $this->assign('title',lang('admin/actor/title'));
        return $this->fetch('admin@actor/info');
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];

        if(!empty($ids)){
            $where=[];
            $where['actor_id'] = $ids;
            $res = (new \app\common\model\Actor())->delData($where);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

    public function field()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        $col = $param['col'];
        $val = $param['val'];
        $start = $param['start'];
        $end = $param['end'];


        if(!empty($ids) && in_array($col,['actor_status','actor_lock','actor_level','type_id','actor_hits'])){
            $where=[];
            $update = [];
            $where['actor_id'] = $ids;
            if(empty($start)){
                $update[$col] = $val;
                if($col == 'type_id'){
                    $type_list = (new \app\common\model\Type())->getCache();
                    $id1 = intval($type_list[$val]['type_pid']);
                    $update['type_id_1'] = $id1;
                }
                $res = (new \app\common\model\Actor())->fieldData($where, $update);
            }
            else{
                if(empty($end)){$end = 9999;}
                $ids = explode(',',$ids);
                foreach($ids as $k=>$v){
                    $val = rand($start,$end);
                    $where['actor_id'] = $v;
                    $update[$col] = $val;
                    $res = (new \app\common\model\Actor())->fieldData($where, $update);
                }
            }
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

}
