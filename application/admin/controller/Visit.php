<?php
namespace app\admin\controller;
use think\facade\Db;

class Visit extends Base
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
        if(!empty($param['uid'])){
            $where['user_id'] = $param['uid'] ;
        }
        if(isset($param['time'])){
            $t = strtotime(date('Y-m-d',strtotime('-'.$param['time'] .' day')));
            $where[] = ['visit_time', '>=', intval($t) ];
        }
        if(!empty($param['wd'])){
            $a = $param['wd'];
            if(substr($a,5)==='http:'){
                $b = str_replace('http:','https:',$a);
            }
            elseif(substr($a,5)==='https'){
                $b = str_replace('https:','http:',$a);
            }
            else{
                $a = 'http://'.$param['wd'];
                $b  = 'https://'.$param['wd'];
            }
            $where[] = ['visit_ly', 'like', [$a.'%',$b.'%'],'OR'];
        }

        $order='visit_id desc';
        $res = (new \app\common\model\Visit())->listData($where,$order,$param['page'],$param['limit']);

        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);
        $this->assign('page',$res['page']);
        $this->assign('limit',$res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param',$param);

        $this->assign('title',lang('admin/visit/title'));
        return $this->fetch('admin@visit/index');
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        $all = $param['all'];
        if(!empty($ids)){
            $where=[];
            $where['visit_id'] = $ids;
            if($all==1){
                $where[] = ['visit_id', '>', 0];
            }
            $res = (new \app\common\model\Visit())->delData($where);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

}
