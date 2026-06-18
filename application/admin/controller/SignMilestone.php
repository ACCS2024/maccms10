<?php
namespace app\admin\controller;
use think\facade\Db;

class SignMilestone extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    // 里程碑列表
    public function data()
    {
        $param = \think\facade\Request::param();
        $param['page'] = intval($param['page']) < 1 ? 1 : $param['page'];
        $param['limit'] = intval($param['limit']) < 1 ? $this->_pagesize : $param['limit'];

        $where = [];
        if (in_array($param['status'], ['0', '1'], true)) {
            $where['milestone_status'] = $param['status'];
        }

        $order = 'milestone_sort asc, milestone_days asc';
        $res = (new \app\common\model\SignMilestone())->listData($where, $order, $param['page'], $param['limit']);

        $this->assign('list', $res['list']);
        $this->assign('total', $res['total']);
        $this->assign('page', $res['page']);
        $this->assign('limit', $res['limit']);
        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param', $param);
        $this->assign('title', lang('milestone/admin_title'));
        return $this->fetch('admin@sign_milestone/index');
    }

    // 里程碑编辑
    public function info()
    {
        if (request()->isPost()) {
            $param = \think\facade\Request::param();
            $res = (new \app\common\model\SignMilestone())->saveData($param);
            if ($res['code'] > 1) {
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }

        $param = \think\facade\Request::param();
        $info = [];
        if (!empty($param['id'])) {
            $where = [];
            $where['milestone_id'] = $param['id'];
            $res = (new \app\common\model\SignMilestone())->infoData($where);
            if ($res['code'] == 1) {
                $info = $res['info'];
            }
        }
        $this->assign('info', $info);
        $this->assign('title', lang('milestone/admin_title'));
        return $this->fetch('admin@sign_milestone/info');
    }

    // 删除里程碑
    public function del()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        if (!empty($ids)) {
            $where = [];
            $where['milestone_id'] = $ids;
            $res = (new \app\common\model\SignMilestone())->delData($where);
            if ($res['code'] > 1) {
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

    // 修改状态
    public function field()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        $col = $param['col'];
        $val = $param['val'];
        if (!empty($ids) && in_array($col, ['milestone_status'])) {
            $where = [];
            $where['milestone_id'] = $ids;
            $res = (new \app\common\model\SignMilestone())->fieldData($where, $col, $val);
            if ($res['code'] > 1) {
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }
}
