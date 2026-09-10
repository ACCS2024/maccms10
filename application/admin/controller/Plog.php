<?php
namespace app\admin\controller;
use think\facade\Db;

class Plog extends Base
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
        if(!empty($param['type'])){
            $where['plog_type'] = $param['type'];
        }
        if(!empty($param['uid'])){
            $where['user_id'] = $param['uid'] ;
        }

        $order='plog_id desc';
        $res = (new \app\common\model\Plog())->listData($where,$order,$param['page'],$param['limit']);

        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);
        $this->assign('page',$res['page']);
        $this->assign('limit',$res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param',$param);

        $this->assign('title',lang('admin/plog/title'));
        return $this->fetch('admin@plog/index');
    }

    public function del()
    {
        return $this->error('原始账变仅供查阅，不支持删除或清空');
    }
}
