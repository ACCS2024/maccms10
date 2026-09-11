<?php
namespace app\index\controller;
use \think\Request;

class Comment extends Base
{
    public function __construct()
    {
        parent::__construct();
        //关闭中
        if($GLOBALS['config']['comment']['status'] == 0){
            throw new \think\exception\HttpResponseException(\think\Response::create('comment is close'));
        }
    }

    public function index()
    {
        if (Request()->isPost()) {
            return $this->saveData();
        }
        $param = mac_param_url();
        $this->assign('param',$param);
        $this->assign('comment',$GLOBALS['config']['comment']);

        return $this->label_fetch('comment/index');
    }

    public function ajax() {
        $param = mac_param_url();
        $this->assign('param',$param);
        $this->assign('comment',$GLOBALS['config']['comment']);
        return $this->label_fetch('comment/ajax',0,'json');
    }

    public function saveData() {
        return \app\common\util\CommentSubmission::submit(request(), true);
    }

    public function report()
    {
        $param = \think\facade\Request::param();
        $id = intval($param['id']);

        if(empty($id) ) {
            return json(['code'=>1001,'msg'=>lang('param_err')]);
        }

        $cookie = 'comment-report-' . $id;
        if(!empty(cookie($cookie))){
            return json(['code'=>1002,'msg'=>lang('index/haved')]);
        }
        $where = [];
        $where['comment_id'] = $id;
        (new \app\common\model\Comment())->where($where)->setInc('comment_report');
        cookie($cookie, 't', $GLOBALS['config']['comment']['timespan']);

        return json(['code'=>1,'msg'=>lang('opt_ok')]);
    }

    public function digg()
    {
        $param = \think\facade\Request::param();
        $id = intval($param['id']);
        $type = $param['type'];

        if(empty($id) ||  empty($type) ) {
            return json(['code'=>1001,'msg'=>lang('param_err')]);
        }

        $pre = 'comment';
        $where = [];
        $where[$pre.'_id'] = $id;
        $field = $pre.'_up,'.$pre.'_down';
        $model = model($pre);

        if($type) {
            $cookie = $pre . '-digg-' . $id;
            if(!empty(cookie($cookie))){
                return json(['code'=>1002,'msg'=>lang('index/haved')]);
            }
            if ($type == 'up') {
                $model->where($where)->setInc($pre . '_up');
            } elseif ($type == 'down') {
                $model->where($where)->setInc($pre . '_down');
            }
            cookie($cookie, 't', $GLOBALS['config']['comment']['timespan']);
        }

        $res = $model->infoData($where,$field);
        if($res['code']>1) {
            return json($res);
        }
        $info = $res['info'];
        if ($info) {
            $data = $info;
        }
        else{
            $data[$pre.'_up'] = 0;
            $data[$pre.'_down'] = 0;
        }
        return json(['code'=>1,'msg'=>lang('opt_ok'),'data'=>$data]);
    }

}
