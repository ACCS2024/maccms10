<?php
namespace app\admin\controller;
use think\facade\Db;

class Cash extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    public function index()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page'] ?? 0) <1 ? 1 : $param['page'];
        $param['limit'] = intval($param['limit'] ?? 0) <1 ? $this->_pagesize : $param['limit'];
        $where=[];
        if(($param['status'] ?? '')!=''){
            $where['cash_status'] = $param['status'];
        }
        if(!empty($param['uid'])){
            $where['user_id'] = $param['uid'] ;
        }
        if(!empty($param['wd'])){
            $param['wd'] = htmlspecialchars(urldecode($param['wd']));
            $where[] = ['cash_bank_no', 'like', '%'.$param['wd'].'%' ];
        }

        $order='cash_id desc';
        $res = (new \app\common\model\Cash())->listData($where,$order,$param['page'],$param['limit']);

        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);
        $this->assign('page',$res['page']);
        $this->assign('limit',$res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param',$param);

        $this->assign('title',lang('admin/cash/title'));
        return $this->fetch('admin@cash/index');
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        $all = $param['all'];
        if(!empty($ids)){
            $where=[];
            $where['cash_id'] = $ids;
            if($all==1){
                $where[] = ['cash_id', '>', 0];
            }
            $res = (new \app\common\model\Cash())->delData($where);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

    public function audit()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        if(!empty($ids)){
            $where=[];
            $where['cash_id'] = $ids;
            $res = (new \app\common\model\Cash())->auditData($where);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

}
