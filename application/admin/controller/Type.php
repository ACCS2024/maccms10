<?php
namespace app\admin\controller;
use think\facade\Db;

class Type extends Base
{
    public function __construct()
    {
        parent::__construct();
        $this->assign('title',lang('admin/type/title'));
    }

    public function index()
    {
        $order='type_sort asc';
        $where=[];
        $res = (new \app\common\model\Type())->listData($where,$order,'tree');

        $list_count =[];
        //视频数量
        $tmp = (new \app\common\model\Vod())->field('type_id_1,type_id,count(vod_id) as cc')->where($where)->group('type_id_1,type_id')->select();
        foreach($tmp as $k=>$v){
            $list_count[$v['type_id_1']] += $v['cc'];
            $list_count[$v['type_id']] = $v['cc'];
        }
        //文章数量
        $tmp = (new \app\common\model\Art())->field('type_id_1,type_id,count(art_id) as cc')->where($where)->group('type_id_1,type_id')->select();
        foreach($tmp as $k=>$v){
            $list_count[$v['type_id_1']] += $v['cc'];
            $list_count[$v['type_id']] = $v['cc'];
        }

        //演员数量
        $tmp = (new \app\common\model\Actor())->field('type_id_1,type_id,count(actor_id) as cc')->where($where)->group('type_id_1,type_id')->select();
        foreach($tmp as $k=>$v){
            $list_count[$v['type_id_1']] += $v['cc'];
            $list_count[$v['type_id']] = $v['cc'];
        }
        //网址数量
        $tmp = (new \app\common\model\Website())->field('type_id_1,type_id,count(website_id) as cc')->where($where)->group('type_id_1,type_id')->select();
        foreach($tmp as $k=>$v){
            $list_count[$v['type_id_1']] += $v['cc'];
            $list_count[$v['type_id']] = $v['cc'];
        }

        //漫画数量
        $tmp = (new \app\common\model\Manga())->field('type_id_1,type_id,count(manga_id) as cc')->where($where)->group('type_id_1,type_id')->select();
        foreach($tmp as $k=>$v){
            $list_count[$v['type_id_1']] += $v['cc'];
            $list_count[$v['type_id']] = $v['cc'];
        }

        //重新整合
        foreach($res['list'] as $k=>$v){
            $res['list'][$k]['cc'] = intval($list_count[$v['type_id']]);
            foreach($v['child'] as $k2=>$v2){
                $res['list'][$k]['child'][$k2]['cc'] = intval($list_count[$v2['type_id']]);
            }
        }


        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);
        return $this->fetch('admin@type/index');
    }

    public function info()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::post();
            $validate = \think\Loader::validate('Token');
            if(!$validate->check($param)){
                return $this->error($validate->getError());
            }
            $res = (new \app\common\model\Type())->saveData($param);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            (new \app\common\model\Type())->setCache();
            return $this->success($res['msg']);
        }

        $id = \think\facadeRequest::param("id");
        $pid = \think\facadeRequest::param("pid");
        $where=[];
        $where['type_id'] = $id;
        $res = (new \app\common\model\Type())->infoData($where);

        $where=[];
        $where['type_id'] = $pid;
        $resp = (new \app\common\model\Type())->infoData($where);

        $this->assign('info',$res['info']);
        $this->assign('infop',$resp['info']);
        $this->assign('pid',$pid);

        $where=[];
        $where['type_pid'] = '0';
        $order='type_sort asc';
        $parent = (new \app\common\model\Type())->listData($where,$order);
        $this->assign('parent',$parent['list']);

        return $this->fetch('admin@type/info');
    }

    public function del()
    {
        $param = \think\facadeRequest::param();
        $ids = $param['ids'];

        if(!empty($ids)){
            $where=[];
            $where['type_id'] = $ids;
            $res = (new \app\common\model\Type())->delData($where);
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

        if(!empty($ids) && in_array($col,['type_status']) && in_array($val,['0','1'])){
            $where=[];
            $where['type_id'] = $ids;

            $res = (new \app\common\model\Type())->fieldData($where,$col,$val);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

    public function batch()
    {
        $param = \think\facadeRequest::param();
        $ids = $param['ids'];
        foreach ($ids as $k=>$id) {

            $data = [];
            $data['type_id'] = intval($id);
            $data['type_name'] = $param['type_name_'.$id];
            $data['type_sort'] = $param['type_sort_'.$id];
            $data['type_en'] = $param['type_en_'.$id];
            $data['type_tpl'] = $param['type_tpl_'.$id];
            $data['type_tpl_list'] = $param['type_tpl_list_'.$id];
            $data['type_tpl_detail'] = $param['type_tpl_detail_'.$id];

            if (empty($data['type_name'])) {
                $data['type_name'] = lang('unknown');
            }

            $res = (new \app\common\model\Type())->saveData($data);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
        }
        $this->success($res['msg']);
    }

    public function extend()
    {
        $param = \think\facadeRequest::param();
        if(!empty($param['id'])){
            $type_list = (new \app\common\model\Type())->getCache('type_list');
            $type_info = $type_list[$param['id']];
            if(!empty($type_info)){
                $type_mid = $type_info['type_mid'];
                $type_pid = $type_info['type_pid'];
                $type_pinfo = $type_list[$type_pid];
                $type_extend = $type_info['type_extend'];
                $type_pextend = $type_pinfo['type_extend'];

                $config = config('maccms.app');

                if($type_mid==2) {
                    if(empty($type_extend['class']) && !empty($type_pextend['class'])){
                        $type_extend['class'] = $type_pextend['class'];
                    }
                    elseif(empty($type_extend['class']) && !empty($config['art_extend_class'])){
                        $type_extend['class'] = $config['art_extend_class'];
                    }
                }
                else{
                    if(empty($type_extend['class']) && !empty($type_pextend['class'])){
                        $type_extend['class'] = $type_pextend['class'];
                    }
                    elseif(empty($type_extend['class']) && !empty($config['vod_extend_class'])){
                        $type_extend['class'] = $config['vod_extend_class'];
                    }

                    if(empty($type_extend['state']) && !empty($type_pextend['state'])){
                        $type_extend['state'] = $type_pextend['state'];
                    }
                    elseif(empty($type_extend['state']) && !empty($config['vod_extend_state'])){
                        $type_extend['state'] = $config['vod_extend_state'];
                    }

                    if(empty($type_extend['version']) && !empty($type_pextend['version'])){
                        $type_extend['version'] = $type_pextend['version'];
                    }
                    elseif(empty($type_extend['version']) && !empty($config['vod_extend_version'])){
                        $type_extend['version'] = $config['vod_extend_version'];
                    }

                    if(empty($type_extend['area']) && !empty($type_pextend['area'])){
                        $type_extend['area'] = $type_pextend['area'];
                    }
                    elseif(empty($type_extend['area']) && !empty($config['vod_extend_area'])){
                        $type_extend['area'] = $config['vod_extend_area'];
                    }

                    if(empty($type_extend['lang']) && !empty($type_pextend['lang'])){
                        $type_extend['lang'] = $type_pextend['lang'];
                    }
                    elseif(empty($type_extend['lang']) && !empty($config['vod_extend_lang'])){
                        $type_extend['lang'] = $config['vod_extend_lang'];
                    }

                    if(empty($type_extend['year']) && !empty($type_pextend['year'])){
                        $type_extend['year'] = $type_pextend['year'];
                    }
                    elseif(empty($type_extend['year']) && !empty($config['vod_extend_year'])){
                        $type_extend['year'] = $config['vod_extend_year'];
                    }
                }


                if(!empty($type_extend)){
                    foreach($type_extend as $key=>$value){
                        $options = '';
                        foreach(explode(',',$value) as $option){
                            $extend[$key][] = $option;
                        }
                    }
                }

                return $this->success('ok',null,$extend);
            }
            return $this->error(lang('get_info_err'));

        }
    }

    public function move()
    {
        $param = \think\facadeRequest::param();
        $ids = $param['ids'];
        $val = $param['val'];
        if(!empty($ids) && !empty($val)){
            $where=[];
            $where['type_id'] = $ids;
            $res = (new \app\common\model\Type())->moveData($where,$val);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

}
