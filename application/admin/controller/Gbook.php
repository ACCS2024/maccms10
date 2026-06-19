<?php
namespace app\admin\controller;
use think\facade\Db;

class Gbook extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    public function data()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page']) <1 ? 1 : $param['page'];
        $param['limit'] = intval($param['limit']) <1 ? $this->_pagesize : $param['limit'];

        $where=[];
        if(in_array($param['status'],['0','1'],true)){
            $where['gbook_status'] = $param['status'];
        }
        if(in_array($param['type'],['1','2'])){
            if($param['type'] == 1){
                $where['gbook_rid'] = 0;
            }
            elseif($param['type'] ==2){
                $where[] = ['gbook_rid', '>', 0];
            }
        }
        if(!empty($param['reply'])){
            $where[] = ['gbook_reply_time', '>', 0];
        }
        if(!empty($param['uid'])){
            $where['user_id'] = $param['uid'] ;
        }
        if(!empty($param['wd'])){
            $param['wd'] = htmlspecialchars(urldecode($param['wd']));
            $_wd_like = '%' . $param['wd'] . '%';
            $where[] = function($q) use ($_wd_like) {
                $q->where('gbook_name', 'like', $_wd_like)->whereOr('gbook_content', 'like', $_wd_like);
            };
        }


        $order='gbook_id desc';
        $res = (new \app\common\model\Gbook())->listData($where,$order,$param['page'],$param['limit']);

        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);
        $this->assign('page',$res['page']);
        $this->assign('limit',$res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param',$param);
        $this->assign('title',lang('admin/gbook/title'));
        return $this->fetch('admin@gbook/index');
    }

    public function info()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::param();
            $res = (new \app\common\model\Gbook())->saveData($param);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }

        $id = \think\facade\Request::param("id");
        $where=[];
        $where['gbook_id'] = $id;
        $res = (new \app\common\model\Gbook())->infoData($where);

        $this->assign('info',$res['info']);
        $this->assign('title',lang('admin/gbook/title'));
        return $this->fetch('admin@gbook/info');
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        $all = $param['all'];

        if(!empty($ids) || !empty($all)){
            $where=[];
            $where['gbook_id'] = $ids;
            if($all==1){
                $where[] = ['gbook_id', '>', 0];
            }
            $res = (new \app\common\model\Gbook())->delData($where);
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

        if(!empty($ids) && in_array($col,['gbook_status']) ){
            $where=[];
            $where['gbook_id'] = $ids;

            $res = (new \app\common\model\Gbook())->fieldData($where,$col,$val);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

}
