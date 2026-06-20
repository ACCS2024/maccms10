<?php
namespace app\admin\controller;
use think\facade\Db;

class Comment extends Base
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
            $where['comment_status'] = $param['status'];
        }
        if(in_array($param['mid'] ?? '',['1','2','3'])){
            $where['comment_mid'] = $param['mid'];
        }
        if(!empty($param['uid'])){
            $where['user_id'] = $param['uid'] ;
        }
        if(!empty($param['report'])){
            if($param['report'] == 1){
                $where['comment_report'] = 0;
            }
            else{
                $where[] = ['comment_report', '>', 0];
            }
        }
        if(!empty($param['wd'])){
            $param['wd'] = htmlspecialchars(urldecode($param['wd']));
            $_wd_like = '%' . $param['wd'] . '%';
            $where[] = function($q) use ($_wd_like) {
                $q->where('comment_name', 'like', $_wd_like)->whereOr('comment_content', 'like', $_wd_like);
            };
        }

        $order='comment_id desc';
        $res = (new \app\common\model\Comment())->listData($where,$order,$param['page'],$param['limit']);

        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);
        $this->assign('page',$res['page']);
        $this->assign('limit',$res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param',$param);
        $this->assign('title',lang('admin/comment/title'));
        return $this->fetch('admin@comment/index');
    }

    public function info()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::param();
            $res = (new \app\common\model\Comment())->saveData($param);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }

        $id = \think\facade\Request::param("id");
        $where=[];
        $where['comment_id'] = $id;
        $res = (new \app\common\model\Comment())->infoData($where);

        $this->assign('info',$res['info'] ?? []);
        $this->assign('title',lang('admin/comment/title'));
        return $this->fetch('admin@comment/info');
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        $all = $param['all'];

        if(!empty($ids) || !empty($all)){
            $where=[];
            $where['comment_id'] = $ids;
            if($all==1){
                $where[] = ['comment_id', '>', 0];
            }
            $res = (new \app\common\model\Comment())->delData($where);
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

        if(!empty($ids) && in_array($col,['comment_status']) ){
            $where=[];
            $where['comment_id'] = $ids;

            $res = (new \app\common\model\Comment())->fieldData($where,$col,$val);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

    /**
     * 黑名单关键字配置
     */
    public function blacklist()
    {
        if ($this->request->isPost()) {
            $keywords = $this->request->post('keywords');
            // 按行分割关键字
            $keywords_array = array_filter(explode("\n", $keywords));
            // 过滤空行
            $keywords_array = array_map('trim', $keywords_array);
            $blcaks = config('blacks');
            $blcaks['black_keyword_list'] = $keywords_array;
            $res = mac_arr2file( APP_PATH .'extra/blacks.php', $blcaks);
            if($res===false){
                return $this->error(lang('write_err_config'));
            }
            return $this->success(lang('save_ok'));
        }
        $blcaks = config('blacks');
        $black_keyword_list = implode("\n", $blcaks['black_keyword_list']);
        $this->assign('black_keyword_list', $black_keyword_list);
        return $this->fetch('admin@comment/blacklist');
    }
    /**
     * 黑名单IP配置
     */
    public function blacklist_ip()
    {
        if ($this->request->isPost()) {
            $keywords = $this->request->post('ip');
            // 按行分割关键字
            $keywords_array = array_filter(explode("\n", $keywords));
            // 过滤空行
            $keywords_array = array_map('trim', $keywords_array);
            //使用mac_string_is_ip方法过滤掉非ip的内容
            $keywords_array = array_filter($keywords_array, function ($value) {
                return mac_string_is_ip($value);
            });
            $blcaks = config('blacks');
            $blcaks['black_ip_list'] = $keywords_array;
            $res = mac_arr2file( APP_PATH .'extra/blacks.php', $blcaks);
            if($res===false){
                return $this->error(lang('write_err_config'));
            }
            return $this->success(lang('save_ok'));
        }
        $blcaks = config('blacks');
        $black_keyword_list = implode("\n", $blcaks['black_ip_list']);
        $this->assign('black_ip_list', $black_keyword_list);
        return $this->fetch('admin@comment/blacklist_ip');
    }

}
