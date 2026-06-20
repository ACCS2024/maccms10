<?php
namespace app\admin\controller;
use think\facade\Db;

class User extends Base
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

        if($param['page'] ==1){
            (new \app\common\model\User())->expire();
        }

        $where=[];
        if(in_array($param['status'] ?? '',['0','1'],true)){
            $where['user_status'] = $param['status'];
        }
        if(!empty($param['group'])){
            $where['group_id'] =  $param['group'];
        }
        if(!empty($param['wd'])){
            $param['wd'] = htmlspecialchars(urldecode($param['wd']));
            $where[] = ['user_name', 'like', '%'.$param['wd'].'%'];
        }

        $order='user_id desc';
        $res = (new \app\common\model\User())->listData($where,$order,$param['page'],$param['limit']);

        $group_list = (new \app\common\model\Group())->getCache('group_list');
        foreach($res['list'] as $k=>$v){
            $group_ids = explode(',', $v['group_id']);
            $names = [];
            foreach($group_ids as $gid){
                if(isset($group_list[$gid])){
                    $names[] = $group_list[$gid]['group_name'];
                }
            }
            $res['list'][$k]['group_name'] = implode(',', $names);
        }

        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);
        $this->assign('page',$res['page']);
        $this->assign('limit',$res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param',$param);

        $this->assign('group_list',$group_list);

        $this->assign('title',lang('admin/user/title'));
        return $this->fetch('admin@user/index');
    }

    public function reward()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page'] ?? 0) <1 ? 1 : $param['page'];
        $param['limit'] = intval($param['limit'] ?? 0) <1 ? $this->_pagesize : $param['limit'];
        $param['uid'] = intval($param['uid']);
        $where=[];
        if(!empty($param['level'])){
            if($param['level']=='1'){
                $where['user_pid'] = $param['uid'];
            }
            elseif($param['level']=='2'){
                $where['user_pid_2'] = $param['uid'];
            }
            elseif($param['level']=='3'){
                $where['user_pid_3'] = $param['uid'];
            }
        }
        else{
            $where['user_pid|user_pid_2|user_pid_3'] = intval($param['uid']) ;
        }

        if(!empty($param['wd'])){
            $param['wd'] = htmlspecialchars(urldecode($param['wd']));
            $where[] = ['user_name', 'like', '%'.$param['wd'].'%'];
        }

        $order='user_id desc';
        $res = (new \app\common\model\User())->listData($where,$order,$param['page'],$param['limit']);
        $group_list = (new \app\common\model\Group())->getCache('group_list');
        foreach($res['list'] as $k=>$v){
            $res['list'][$k]['group_name'] = $group_list[$v['group_id']]['group_name'];
        }

        $where2=[];
        $where2['user_pid'] = $param['uid'];
        $level_cc_1 = Db::name('User')->where($where2)->count();
        $where3 = [];
        $where3['user_id'] = $param['uid'];
        $where3['plog_type'] = 4;
        $points_cc_1 = Db::name('Plog')->where($where3)->sum('plog_points');

        $where2=[];
        $where2['user_pid_2'] = $param['uid'];
        $level_cc_2 = Db::name('User')->where($where2)->count();
        $where3 = [];
        $where3['user_id'] = $param['uid'];
        $where3['plog_type'] = 5;
        $points_cc_2 = Db::name('Plog')->where($where3)->sum('plog_points');

        $where2=[];
        $where2['user_pid_3'] = $param['uid'];
        $level_cc_3 = Db::name('User')->where($where2)->count();
        $where3 = [];
        $where3['user_id'] = $param['uid'];
        $where3['plog_type'] = 6;
        $points_cc_3 = Db::name('Plog')->where($where3)->sum('plog_points');

        $data=[];
        $data['level_cc_1'] = intval($level_cc_1);
        $data['level_cc_2'] = intval($level_cc_2);
        $data['level_cc_3'] = intval($level_cc_3);
        $data['points_cc_1'] = intval($points_cc_1);
        $data['points_cc_2'] = intval($points_cc_2);
        $data['points_cc_3'] = intval($points_cc_3);

        $this->assign('data',$data);
        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);
        $this->assign('page',$res['page']);
        $this->assign('limit',$res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param',$param);

        $this->assign('title',lang('admin/user/title'));
        return $this->fetch('admin@user/reward');
    }


    public function invite()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page'] ?? 0) <1 ? 1 : $param['page'];
        $param['limit'] = intval($param['limit'] ?? 0) <1 ? $this->_pagesize : $param['limit'];

        $where = [];
        
        $where[] = ['user_invite_count', '>', 0];
        
        if(!empty($param['wd'])){
            $wd = htmlspecialchars(urldecode($param['wd']));
            $wd = str_replace(['%', '_'], ['\\%', '\\_'], $wd);
            $where[] = ['user_name', 'like', '%'.$wd.'%'];
        }

        $order='user_invite_count desc, user_id desc';
        $res = (new \app\common\model\User())->listData($where,$order,$param['page'],$param['limit']);
        
        $group_list = (new \app\common\model\Group())->getCache('group_list');
        
        $user_ids = array_column($res['list'], 'user_id');
        $invited_users_map = [];
        if (!empty($user_ids)) {
            $invited_list = Db::name('User')
                ->field('user_id,user_name,user_reg_time,user_invite_code,user_pid')
                ->where('user_pid', 'in', $user_ids)
                ->select();
            foreach ($invited_list as $invited) {
                $invited_users_map[$invited['user_pid']][] = $invited;
            }
        }
        
        foreach($res['list'] as $k=>$v){
            $group_ids = explode(',', $v['group_id']);
            $names = [];
            foreach($group_ids as $gid){
                if(isset($group_list[$gid])){
                    $names[] = $group_list[$gid]['group_name'];
                }
            }
            $res['list'][$k]['group_name'] = implode(',', $names);
            $res['list'][$k]['invited_users'] = isset($invited_users_map[$v['user_id']]) 
                ? array_slice($invited_users_map[$v['user_id']], 0, 5) 
                : [];
        }

        $total_invite_count = Db::name('User')->sum('user_invite_count');
        $total_invite_users = Db::name('User')->where('user_invite_count', 'gt', 0)->count();

        $this->assign('total_invite_count', intval($total_invite_count));
        $this->assign('total_invite_users', intval($total_invite_users));
        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);
        $this->assign('page',$res['page']);
        $this->assign('limit',$res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param',$param);

        $this->assign('title','邀请统计');
        return $this->fetch('admin@user/invite');
    }


    public function info()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::post();
            if(isset($param['group_id']) && is_array($param['group_id'])) {
                $param['group_id'] = implode(',', $param['group_id']);
            }
            // 安全加固:后台编辑用户时,对自由文本字段做与前台注册/改料一致的 HTML 转义,
            // 维持"入库即转义"不变量。否则后台保存会把已转义值还原为原始字符
            // (表单回填时浏览器会把 &quot; 解码为 "，提交后按原始字符入库),
            // 这些字段随后在后台用户列表/详情与前台个人资料处被原样渲染,造成存储型 XSS。
            foreach (['user_name','user_nick_name','user_qq','user_phone','user_email'] as $__xss_f) {
                if (isset($param[$__xss_f]) && is_string($param[$__xss_f])) {
                    $param[$__xss_f] = htmlspecialchars(trim($param[$__xss_f]));
                }
            }
            $res = (new \app\common\model\User())->saveData($param);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }

        $id = (int)\think\facade\Request::param("id");
        $where=[];
        $where['user_id'] = $id;
        $res = (new \app\common\model\User())->infoData($where);
        $info = $res['info'];

        $group_list = (new \app\common\model\Group())->getCache('group_list');
        $group_ids = isset($info['group_id']) ? explode(',', $info['group_id']) : [];
        $has_vip_group = false;
        foreach($group_ids as $gid){
            if(intval($gid) > 2){
                $has_vip_group = true;
                break;
            }
        }
        $this->assign('info', $info);
        $this->assign('group_list', $group_list);
        $this->assign('has_vip_group', $has_vip_group);
        return $this->fetch('admin@user/info');
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];

        if(!empty($ids)){
            $where=[];
            $where['user_id'] = $ids;
            $res = (new \app\common\model\User())->delData($where);
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

        if(!empty($ids) && in_array($col,['user_status']) && in_array($val,['0','1'])){
            $where=[];
            $where['user_id'] = $ids;

            $res = (new \app\common\model\User())->fieldData($where,$col,$val);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

    public function generateInviteCode()
    {
        $count = 0;
        $model = (new \app\common\model\User());
        
        \think\facade\Db::name('User')
            ->where('user_invite_code', '=', '')
            ->chunk(500, function ($users) use ($model, &$count) {
                foreach ($users as $user) {
                    $invite_code = $model->generateUniqueInviteCode($user['user_id']);
                    \think\facade\Db::name('User')
                        ->where('user_id', $user['user_id'])
                        ->update(['user_invite_code' => $invite_code]);
                    $count++;
                }
            });
        
        return $this->success('共为 ' . $count . ' 个会员生成了邀请码');
    }


}
