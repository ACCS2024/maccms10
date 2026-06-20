<?php
namespace app\admin\controller;
use think\facade\Db;

class Topic extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    public function data()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page'] ?? 0) <1 ? 1 : $param['page'];
        $param['limit'] = intval($param['limit'] ?? 0) <1 ? $this->_pagesize : $param['limit'];

        $where=[];
        if(in_array($param['status'] ?? '',['0','1'],true)){
            $where['topic_status'] = $param['status'];
        }
        if(!empty($param['wd'])){
            $param['wd'] = htmlspecialchars(urldecode($param['wd']));
            mac_apply_like_where($where, 'topic_name', $param['wd']);
        }

        $order='topic_time desc';
        $res = (new \app\common\model\Topic())->listData($where,$order,$param['page'],$param['limit']);

        foreach($res['list'] as $k=>&$v){
            $v['ismake'] = 1;
            if($GLOBALS['config']['view']['topic_detail'] >0 && $v['topic_time_make'] < $v['topic_time']){
                $v['ismake'] = 0;
            }
        }

        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);
        $this->assign('page',$res['page']);
        $this->assign('limit',$res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param',$param);
        $this->assign('title',lang('admin/topic/title'));
        return $this->fetch('admin@topic/index');
    }

    public function info()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::post();
            $res = (new \app\common\model\Topic())->saveData($param);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }


        $id = \think\facade\Request::param("id");
        $where=[];
        $where['topic_id'] = $id;
        $res = (new \app\common\model\Topic())->infoData($where);


        $this->assign('info',$res['info']);

        $config = config('maccms.site');
        $this->assign('install_dir',$config['install_dir']);
        $this->assign('title',lang('admin/topic/title'));
        return $this->fetch('admin@topic/info');
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];

        if(!empty($ids)){
            $where=[];
            $where['topic_id'] = $ids;
            $res = (new \app\common\model\Topic())->delData($where);
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

        if(!empty($ids) && in_array($col,['topic_status','topic_level']) ){
            $where=[];
            $where['topic_id'] = $ids;

            $res = (new \app\common\model\Topic())->fieldData($where,$col,$val);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

}
