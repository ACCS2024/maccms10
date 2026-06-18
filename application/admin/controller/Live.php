<?php
namespace app\admin\controller;

class Live extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    // ==================== 频道管理 ====================

    public function index()
    {
        $param = \think\facade\Request::param();
        $param['page']  = intval($param['page']) < 1 ? 1 : $param['page'];
        $param['limit'] = intval($param['limit']) < 1 ? $this->_pagesize : $param['limit'];
        $where = [];

        if (!empty($param['wd'])) {
            $param['wd'] = htmlspecialchars(urldecode($param['wd']));
            $where[] = ['live_name', 'like', '%' . $param['wd'] . '%'];
        }
        if (isset($param['cate_id']) && $param['cate_id'] !== '') {
            $where['cate_id'] = (int)$param['cate_id'];
        }
        if (isset($param['status']) && $param['status'] !== '') {
            $where['live_status'] = (int)$param['status'];
        }

        $order = 'live_sort desc, live_id desc';
        $res = (new \app\common\model\Live())->listData($where, $order, $param['page'], $param['limit']);

        // 分类列表（用于筛选下拉）
        $cate_list = (new \app\common\model\Live())->categoryList(['cate_status' => 1]);

        $this->assign('list', $res['list']);
        $this->assign('total', $res['total']);
        $this->assign('page', $res['page']);
        $this->assign('limit', $res['limit']);
        $this->assign('cate_list', $cate_list);

        $param['page']  = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param', $param);
        $this->assign('title', lang('admin/live/title'));
        return $this->fetch('admin@live/index');
    }

    public function info()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::param();
            $res = (new \app\common\model\Live())->saveData($param);
            if ($res['code'] > 1) {
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }

        $id = \think\facade\Request::param("id");
        $where = [];
        if (!empty($id)) {
            $where['live_id'] = $id;
        }
        $res = (new \app\common\model\Live())->infoData($where);

        $cate_list = (new \app\common\model\Live())->categoryList(['cate_status' => 1]);

        $this->assign('info', $res['info']);
        $this->assign('cate_list', $cate_list);
        $this->assign('title', lang('admin/live/title'));
        return $this->fetch('admin@live/info');
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];

        if (!empty($ids)) {
            $where = [];
            $where['live_id'] = $ids;
            $res = (new \app\common\model\Live())->delData($where);
            if ($res['code'] > 1) {
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

        // 安全加固(V18):列名白名单,与其它控制器一致,防止越权改写非预期字段
        if (!in_array($col, ['live_status', 'live_sort', 'live_hits'], true)) {
            return $this->error(lang('param_err'));
        }

        if (!empty($ids) && isset($col) && isset($val)) {
            $where = [];
            if (is_array($ids)) {
                $where['live_id'] = $ids;
            } else {
                $where['live_id'] = (int)$ids;
            }
            $res = (new \app\common\model\Live())->fieldData($where, $col, $val);
            if ($res['code'] > 1) {
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }

    // ==================== 分类管理 ====================

    public function category()
    {
        $cate_list = (new \app\common\model\Live())->categoryList();

        $this->assign('list', $cate_list);
        $this->assign('title', lang('admin/live/cate_title'));
        return $this->fetch('admin@live/category');
    }

    public function category_info()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::param();
            $res = (new \app\common\model\Live())->categorySave($param);
            if ($res['code'] > 1) {
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }

        $id = \think\facade\Request::param("id");
        $info = [];
        if (!empty($id)) {
            $res = (new \app\common\model\Live())->categoryInfo(['cate_id' => (int)$id]);
            $info = isset($res['info']) ? $res['info'] : [];
        }

        $this->assign('info', $info);
        $this->assign('title', lang('admin/live/cate_title'));
        return $this->fetch('admin@live/category_info');
    }

    public function category_del()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];

        if (!empty($ids)) {
            $res = (new \app\common\model\Live())->categoryDel($ids);
            if ($res['code'] > 1) {
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }
}
