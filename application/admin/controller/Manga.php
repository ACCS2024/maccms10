<?php
namespace app\admin\controller;
use think\facade\Db;
use app\common\util\Pinyin;

class Manga extends Base
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
            $where['manga_level'] = $param['level'];
        }
        if (in_array($param['status'] ?? '', ['0', '1'])) {
            $where['manga_status'] = $param['status'];
        }
        if (!empty($param['lock'])) {
            $where['manga_lock'] = $param['lock'];
        }
        if(!empty($param['pic'])){
            if($param['pic'] == '1'){
                $where['manga_pic'] = '';
            }
            elseif($param['pic'] == '2'){
                $where[] = ['manga_pic', 'like', 'http%'];
            }
            elseif($param['pic'] == '3'){
                $where[] = ['manga_pic', 'like', '%#err%'];
            }
        }
        if(!empty($param['wd'])){
            $param['wd'] = urldecode($param['wd']);
            $param['wd'] = mac_filter_xss($param['wd']);
            mac_apply_like_where($where, 'manga_name', $param['wd']);
        }
        if (!empty($param['recycle'])) {
            $where[] = ['manga_recycle_time', '>', 0];
        }

        if(!empty($param['url'])){
            if($param['url'] == '1'){
                $where['manga_chapter_url'] = '';
            }
        }
        if(!empty($param['points'])){
            if($param['points'] == '1'){
                $where[] = ['manga_points', '>', 0];
            }
        }

        if(!empty($param['repeat'])){
            if($param['page'] ==1){
                Db::execute('DROP TABLE IF EXISTS '.config('database.prefix').'tmpmanga');
                Db::execute('CREATE TABLE `'.config('database.prefix').'tmpmanga` (`id1` int unsigned DEFAULT NULL, `name1` varchar(1024) NOT NULL DEFAULT \'\') ENGINE=MyISAM');
                Db::execute('INSERT INTO `'.config('database.prefix').'tmpmanga` (SELECT min(manga_id)as id1,manga_name as name1 FROM '.config('database.prefix').'manga WHERE manga_recycle_time = 0 GROUP BY name1 HAVING COUNT(name1)>1)');
            }
            $order='manga_name asc';
            $res = (new \app\common\model\Manga())->listRepeatData($where,$order,$param['page'],$param['limit']);
        }
        else{
            $order='manga_time desc';
            $res = (new \app\common\model\Manga())->listData($where,$order,$param['page'],$param['limit']);
        }

        foreach($res['list'] as $k=>&$v){
            $v['ismake'] = 1;
            if($GLOBALS['config']['view']['manga_detail'] >0 && $v['manga_time_make'] < $v['manga_time']){
                $v['ismake'] = 0;
            }
        }

        $this->assign('list', $res['list']);
        $this->assign('total', $res['total']);
        $this->assign('page', $res['page']);
        $this->assign('limit', $res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param', $param);

        $type_tree = (new \app\common\model\Type())->getCache('type_tree');
        $this->assign('type_tree', $type_tree);

        $this->assign('title', lang('admin/manga/title'));
        return $this->fetch('admin@manga/index');
    }

    public function batch()
    {
        $param = \think\facade\Request::param();
        if (!empty($param)) {

            mac_echo('<style type="text/css">body{font-size:12px;color: #333333;line-height:21px;}span{font-weight:bold;color:#FF0000}</style>');

            if(empty($param['ck_del']) && empty($param['ck_level']) && empty($param['ck_status']) && empty($param['ck_lock']) && empty($param['ck_hits']) && empty($param['ck_replace']) ){
                return $this->error(lang('param_err'));
            }
            $where = $this->mangaBatchFilterWhere($param);
            if($param['ck_del'] == 1){
                $res = (new \app\common\model\Manga())->recycleData($where);
                mac_echo($res['code'] == 1 ? lang('recycle_ok') : $res['msg']);
                mac_jump( url('manga/batch') ,3);
                exit;
            }
            if($param['ck_del'] == 4){
                $res = (new \app\common\model\Manga())->delData($where);
                mac_echo(lang('multi_del_ok'));
                mac_jump( url('manga/batch') ,3);
                exit;
            }

            if(empty($param['page'])){
                $param['page'] = 1;
            }
            if(empty($param['limit'])){
                $param['limit'] = 100;
            }
            if(empty($param['total'])) {
                $param['total'] = (new \app\common\model\Manga())->countData($where);
                $param['page_count'] = ceil($param['total'] / $param['limit']);
            }

            if($param['page'] > $param['page_count']) {
                mac_echo(lang('multi_set_ok'));
                mac_jump( url('manga/batch') ,3);
                exit;
            }
            mac_echo( "<font color=red>".lang('admin/batch_tip',[$param['total'],$param['limit'],$param['page_count'],$param['page']])."</font>");

            $page = $param['page_count'] - $param['page'] + 1;
            $order='manga_id desc';
            $res = (new \app\common\model\Manga())->listData($where,$order,$page,$param['limit']);

            foreach($res['list'] as  $k=>$v){
                $where2 = [];
                $where2['manga_id'] = $v['manga_id'];

                $update = [];
                $des = $v['manga_id'].','.$v['manga_name'];

                if(!empty($param['ck_level']) && !empty($param['val_level'])){
                    $update['manga_level'] = $param['val_level'];
                    $des .= '&nbsp;'.lang('level').'：'.$param['val_level'].'；';
                }
                if(!empty($param['ck_status']) && isset($param['val_status'])){
                    $update['manga_status'] = $param['val_status'];
                    $des .= '&nbsp;'.lang('status').'：'.($param['val_status'] ==1 ? '['.lang('reviewed').']':'['.lang('reviewed_not').']') .'；';
                }
                if(!empty($param['ck_lock']) && isset($param['val_lock'])){
                    $update['manga_lock'] = $param['val_lock'];
                    $des .= '&nbsp;'.lang('lock').'：'.($param['val_lock']==1 ? '['.lang('lock').']':'['.lang('unlock').']').'；';
                }
                if(!empty($param['ck_hits']) && !empty($param['val_hits_min']) && !empty($param['val_hits_max']) ){
                    $update['manga_hits'] = rand($param['val_hits_min'],$param['val_hits_max']);
                    $des .= '&nbsp;'.lang('hits').'：'.$update['manga_hits'].'；';
                }
                // 新增：批量替换功能
                if(!empty($param['ck_replace']) && !empty($param['replace_field']) && isset($param['replace_search'])){
                    $field = $param['replace_field'];
                    $replaceres = $this->batch_replace($field,$v,$param['replace_search'],$param['replace_with'],'manga');
                    if(isset($replaceres[$field])) $update[$field] = $replaceres[$field];

                    if(!empty($replaceres['des'])) $des .= $replaceres['des'];
                }
                mac_echo($des);
                $res2 = (new \app\common\model\Manga())->where($where2)->update($update);

            }
            $param['page']++;
            $url = url('manga/batch') .'?'. http_build_query($param);
            mac_jump( $url ,3);
            exit;
        }

        $type_tree = (new \app\common\model\Type())->getCache('type_tree');
        $this->assign('type_tree',$type_tree);

        $this->assign('title',lang('admin/manga/title'));
        return $this->fetch('admin@manga/batch');
    }

    private function mangaBatchFilterWhere(&$param)
    {
        $where = [];
        if (!empty($param['type'])) {
            $where['type_id'] = $param['type'];
        }
        if (!empty($param['level'])) {
            $where['manga_level'] = $param['level'];
        }
        if (in_array($param['status'] ?? '', ['0', '1'])) {
            $where['manga_status'] = $param['status'];
        }
        if (!empty($param['lock'])) {
            $where['manga_lock'] = $param['lock'];
        }
        if (!empty($param['pic'])) {
            if ($param['pic'] == '1') {
                $where['manga_pic'] = '';
            } elseif ($param['pic'] == '2') {
                $where[] = ['manga_pic', 'like', 'http%'];
            } elseif ($param['pic'] == '3') {
                $where[] = ['manga_pic', 'like', '%#err%'];
            }
        }
        if (!empty($param['wd'])) {
            $param['wd'] = htmlspecialchars(urldecode($param['wd']));
            mac_apply_like_where($where, 'manga_name', $param['wd']);
        }
        if (!empty($param['recycle'])) {
            $where[] = ['manga_recycle_time', '>', 0];
        }
        return $where;
    }

    public function exportData()
    {
        $param = \think\facade\Request::param();
        $where = $this->mangaBatchFilterWhere($param);
        $this->base_export($param,'manga',$where);
    }

    public function importData()
    {
        $this->base_import('manga');
    }

    public function info()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::post();
            $res = (new \app\common\model\Manga())->saveData($param);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }

        $id = \think\facade\Request::param("id");
        $where=[];
        $where['manga_id'] = $id;
        $where['_recycle'] = 'all';
        $res = (new \app\common\model\Manga())->infoData($where);

        $info = $res['info'];
        if (empty($info)) {
            $info = [];
        }
        $this->assign('info',$info);
        $this->assign('manga_page_list', !empty($info['manga_page_list']) ? (array)$info['manga_page_list'] : []);

        $type_tree = (new \app\common\model\Type())->getCache('type_tree');
        $this->assign('type_tree',$type_tree);

        $this->assign('title',lang('admin/manga/title'));
        return $this->fetch('admin@manga/info');
    }

    public function restore()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        if (empty($ids)) {
            return $this->error(lang('param_err'));
        }
        $where = [['manga_id', 'in', $ids]];
        $res = (new \app\common\model\Manga())->restoreData($where);
        if ($res['code'] > 1) {
            return $this->error($res['msg']);
        }
        return $this->success($res['msg']);
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        $purge = !empty($param['purge']);

        if(!empty($ids)){
            $where=[];
            $where['manga_id'] = $ids;
            if ($purge) {
                $res = (new \app\common\model\Manga())->delData($where);
            } else {
                $res = (new \app\common\model\Manga())->recycleData($where);
            }
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        elseif(!empty($param['repeat'])){
            $st = ' not in ';
            if($param['retain']=='max'){
                $st=' in ';
            }
            $sql = 'delete from '.config('database.prefix').'manga where manga_name in(select name1 from '.config('database.prefix').'tmpmanga) and manga_id '.$st.'(select id1 from '.config('database.prefix').'tmpmanga)';
            $res = (new \app\common\model\Manga())->execute($sql);
            if($res===false){
                return $this->success(lang('del_err'));
            }
            return $this->success(lang('del_ok'));
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
        if ($col == 'type_id' && $val==''){
            return $this->error("请选择分类提交");
        }

        if(!empty($ids) && in_array($col,['manga_status','manga_lock','manga_level','manga_hits','type_id'])){
            $where=[];
            $where['manga_id'] = $ids;
            $update = [];
            if(empty($start)) {
                $update[$col] = $val;
                if($col == 'type_id'){
                    $type_list = (new \app\common\model\Type())->getCache();
                    $id1 = intval($type_list[$val]['type_pid']);
                    $update['type_id_1'] = $id1;
                }
                $res = (new \app\common\model\Manga())->fieldData($where, $update);
            }
            else{
                if(empty($end)){$end = 9999;}
                $ids = explode(',',$ids);
                foreach($ids as $k=>$v){
                    $val = rand($start,$end);
                    $where['manga_id'] = $v;
                    $update[$col] = $val;
                    $res = (new \app\common\model\Manga())->fieldData($where, $update);
                }
            }
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

    public function updateToday()
    {
        $param = \think\facade\Request::param();
        $flag = $param['flag'];
        $res = (new \app\common\model\Manga())->updateToday($flag);
        return json($res);
    }

    public function batchGenerateTag()
    {
        $ids = \think\facade\Request::post("ids", []);
        if(empty($ids)){
            return json(['code'=>0,'msg'=>lang('admin/tag/select_manga_tag')]);
        }
        
        $success = 0;
        $fail = 0;
        foreach($ids as $id){
            $info = (new \app\common\model\Manga())->where('manga_id',$id)->find();
            if($info){
                $tag = mac_get_tag($info['manga_name'], $info['manga_content']);
                if($tag !== false){
                    $res = (new \app\common\model\Manga())->where('manga_id',$id)->update(['manga_tag'=>$tag]);
                    if($res){
                        $success++;
                    }else{
                        $fail++;
                    }
                }else{
                    $fail++;
                }
            }
        }
        
        return json(['code'=>1,'msg'=>sprintf(lang('admin/tag/generate_tag_result'), $success, $fail)]);
    }

}
