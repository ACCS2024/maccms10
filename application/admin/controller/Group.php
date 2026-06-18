<?php
namespace app\admin\controller;
use think\facade\Db;

class Group extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    public function index()
    {
        $param = \think\facadeRequest::param();
        $where=[];

        if(in_array($param['status'],['0','1'],true)){
            $where['group_status'] = $param['status'];
        }
        if(!empty($param['wd'])){
            $param['wd'] = htmlspecialchars(urldecode($param['wd']));
            $where[] = ['group_name', 'like', '%'.$param['wd'].'%'];
        }

        $order='group_id asc';
        $res = (new \app\common\model\Group())->listData($where,$order);

        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);

        $this->assign('param',$param);
        $this->assign('title',lang('admin/group/title'));
        return $this->fetch('admin@group/index');
    }

    public function info()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::post();

            if($GLOBALS['config']['user']['reg_group'] == $param['group_id']){
                $param['group_status'] = 1;
            }
            $res = (new \app\common\model\Group())->saveData($param);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }

        $id = \think\facadeRequest::param("id");
        $where=[];
        $where['group_id'] = $id;
        $res = (new \app\common\model\Group())->infoData($where);

        $this->assign('info',$res['info']);


        $type_tree = (new \app\common\model\Type())->getCache('type_tree');
        $this->assign('type_tree',$type_tree);

        $this->assign('title',lang('admin/group/title'));
        return $this->fetch('admin@group/info');
    }

    public function del()
    {
        $param = \think\facadeRequest::param();
        $ids = $param['ids'];

        if(!empty($ids)){

            if(strpos(','.$ids.',', ','.$GLOBALS['config']['user']['reg_group'].',')!==false){
                return $this->error(lang('admin/group/reg_group_del_err'));
            }

            $where=[];
            $where['group_id'] = $ids;
            $res = (new \app\common\model\Group())->delData($where);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

    public function field()
    {
        $param = \think\facadeRequest::param();
        $ids = $param['ids'];
        $col = $param['col'];
        $val = $param['val'];

        if(!empty($ids) && in_array($col,['group_status']) && in_array($val,['0','1'])){
            $where=[];
            $where['group_id'] = $ids;

            $res = (new \app\common\model\Group())->fieldData($where,$col,$val);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }


}
