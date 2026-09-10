<?php
namespace app\admin\controller;
use think\facade\Db;

class Admin extends Base
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
        if(!empty($param['wd'])){
            $param['wd'] = htmlspecialchars(urldecode($param['wd']));
            $where[] = ['admin_name', 'like', '%'.$param['wd'].'%'];
        }

        $order='admin_id desc';
        $res = (new \app\common\model\Admin())->listData($where,$order,$param['page'],$param['limit']);

        $this->assign('list',$res['list']);
        $this->assign('total',$res['total']);
        $this->assign('page',$res['page']);
        $this->assign('limit',$res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';

        $this->assign('admin',$this->_admin);

        $this->assign('param',$param);
        $this->assign('title',lang('admin/admin/title'));
        return $this->fetch('admin@admin/index');
    }

    public function info()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::post();
            if (isset($param['admin_id']) && (!is_scalar($param['admin_id'])
                || ((int)$param['admin_id'] === 1 && (int)$this->_admin['admin_id'] !== 1))) {
                return $this->error(lang('permission_denied'));
            }
            if ((int)($param['admin_id'] ?? 0) === 1 && isset($param['admin_status']) && (string)$param['admin_status'] !== '1') {
                return $this->error(lang('permission_denied'));
            }
            $param['admin_auth'] = $param['admin_auth'] ?? [];
            if (!is_array($param['admin_auth'])) {
                return $this->error(lang('param_err'));
            }
            foreach ($param['admin_auth'] as $auth) {
                if (!is_string($auth) || substr_count($auth, '/') !== 1) {
                    return $this->error(lang('param_err'));
                }
                [$controller, $action] = explode('/', $auth, 2);
                if (!$this->check_auth($controller, $action)) {
                    return $this->error(lang('permission_denied'));
                }
            }
            if(!in_array('index/welcome',$param['admin_auth'], true)){
                $param['admin_auth'][] = 'index/welcome';
            }
            $validate = mac_validate('Token');
            if(!$validate->check($param)){
                return $this->error($validate->getError());
            }
            $res = (new \app\common\model\Admin())->saveData($param);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }

        $id = \think\facade\Request::param("id");

        $where=[];
        $where['admin_id'] = $id;

        $res = (new \app\common\model\Admin())->infoData($where);
        $this->assign('info',$res['info']);

        //权限列表
        $menus = @include MAC_ADMIN_COMM . 'auth.php';

        // 已授权项：按整项比对,不能用 strpos 子串匹配
        // （'vod/del' 会被 'newvod/del' 误命中,表现为勾选状态显示错误）
        $granted = [];
        foreach (explode(',', (string)($res['info']['admin_auth'] ?? '')) as $one) {
            $one = trim($one);
            if ($one !== '') {
                $granted[$one] = true;
            }
        }

        foreach($menus as $k1=>$v1){
            $all = [];
            $cs = [];
            $menus[$k1]['ck'] = '';
            foreach($v1['sub'] as $k2=>$v2){
                $one = $v2['controller'] . '/' . $v2['action'];
                $menus[$k1]['sub'][$k2]['url'] = url($one);
                $menus[$k1]['sub'][$k2]['ck']= '';
                $all[] = $one;

                if(isset($granted[$one])){
                    $cs[] = $one;
                    $menus[$k1]['sub'][$k2]['ck'] = 'checked';
                }
                if($k2==11){
                    $menus[$k1]['sub'][$k2]['ck'] = ' checked  readonly="readonly" ';
                }
            }
            if($all == $cs){
                $menus[$k1]['ck'] = 'checked';
            }
        }
        $this->assign('menus',$menus);

        // 角色预设：把 roles.php 的分组声明展开成具体的 controller/action 清单,
        // 交给前端一键勾选。在服务端展开而不是前端硬编码,菜单增删项时预设自动跟随。
        $roleDefs = @include MAC_ADMIN_COMM . 'roles.php';
        $roles = [];
        if (is_array($roleDefs)) {
            foreach ($roleDefs as $key => $def) {
                $items   = [];
                $exclude = array_flip($def['exclude'] ?? []);
                foreach ($menus as $gid => $g) {
                    $wantAll = ($def['groups'] ?? []) === 'all';
                    if (!$wantAll && !in_array($gid, (array)($def['groups'] ?? []), true)) {
                        continue;
                    }
                    foreach ($g['sub'] as $s) {
                        $one = $s['controller'] . '/' . $s['action'];
                        if (!isset($exclude[$one])) {
                            $items[] = $one;
                        }
                    }
                }
                // 必须先去重再计数：同一个 controller/action 会在多个分组里重复出现
                // （如 vod/info 同时挂在「视频」与其它分组下，全树有 19 处这种重复），
                // 直接 count() 会让按钮上的数字比实际勾选数虚高。
                $items = array_values(array_unique($items));
                $roles[] = [
                    'key'   => $key,
                    'name'  => $def['name'] ?? $key,
                    'desc'  => $def['desc'] ?? '',
                    'count' => count($items),
                    'items' => $items,
                ];
            }
        }
        $this->assign('roles', $roles);
        $this->assign('roles_json', json_encode($roles, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));


        $this->assign('title',lang('admin/admin/title'));
        return $this->fetch('admin@admin/info');
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $ids = $this->requestedAdminIds($param['ids'] ?? null);

        if(!empty($ids)){
            if (in_array(1, $ids, true)) {
                return $this->error(lang('permission_denied'));
            }
            if(in_array((int)$this->_admin['admin_id'],$ids, true)){
                return $this->error(lang('admin/admin/del_cur_err'));
            }
            $where = [['admin_id', 'in', $ids]];
            $res = (new \app\common\model\Admin())->delData($where);
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
        $ids = $this->requestedAdminIds($param['ids'] ?? null);
        $col = $param['col'] ?? '';
        $val = $param['val'] ?? '';

        if(!empty($ids) && in_array($col,['admin_status']) && in_array($val,['0','1'])){
            if (in_array(1, $ids, true) || ($val == '0' && in_array((int)$this->_admin['admin_id'], $ids, true))) {
                return $this->error(lang('permission_denied'));
            }
            $where = [['admin_id', 'in', $ids]];

            $res = (new \app\common\model\Admin())->fieldData($where,$col,$val);
            if($res['code']>1){
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

    private function requestedAdminIds($input): ?array
    {
        if (is_int($input)) {
            $input = [$input];
        } elseif (is_string($input)) {
            $input = explode(',', $input);
        }
        if (!is_array($input) || $input === []) {
            return null;
        }
        $ids = [];
        foreach ($input as $id) {
            if ((!is_string($id) && !is_int($id)) || !ctype_digit((string)$id) || (int)$id < 1) {
                return null;
            }
            $ids[] = (int)$id;
        }
        return array_values(array_unique($ids));
    }

}
