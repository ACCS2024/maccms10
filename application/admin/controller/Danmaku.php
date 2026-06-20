<?php
namespace app\admin\controller;
use think\facade\Db;

class Danmaku extends Base
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
        // 分页硬上限，防止单次查询返回过多数据
        $param['limit'] = min(intval($param['limit']), 100);

        $where = [];
        if (isset($param['status']) && in_array($param['status'] ?? '', ['0', '1'], true)) {
            $where['danmaku_status'] = $param['status'];
        }
        if (!empty($param['vod_id'])) {
            $where['vod_id'] = $param['vod_id'];
        }
        if (!empty($param['uid'])) {
            $where['user_id'] = $param['uid'];
        }
        if (!empty($param['report'])) {
            if ($param['report'] == 1) {
                $where['danmaku_report'] = 0;
            } else {
                $where[] = ['danmaku_report', '>', 0];
            }
        }
        if (!empty($param['wd'])) {
            $param['wd'] = htmlspecialchars(urldecode($param['wd']));
            // 限制搜索关键字长度，防止超长字符串造成性能问题
            $param['wd'] = mb_substr($param['wd'], 0, 30);
            // LIKE '%xx%' 无法使用索引，需搭配 vod_id 或 user_id 前置过滤以缩小扫描范围
            if (empty($where['vod_id']) && empty($where['user_id'])) {
                // 无前置过滤时仅搜索 danmaku_text（单字段减轻负担）
                $where[] = ['danmaku_text', 'like', '%' . $param['wd'] . '%'];
            } else {
                $_wd_like = '%' . $param['wd'] . '%';
                $where[] = function($q) use ($_wd_like) {
                    $q->where('user_name', 'like', $_wd_like)->whereOr('danmaku_text', 'like', $_wd_like);
                };
            }
        }

        $order = 'danmaku_id desc';
        $res = (new \app\common\model\Danmaku())->listData($where, $order, $param['page'], $param['limit']);

        $this->assign('list', $res['list']);
        $this->assign('total', $res['total']);
        $this->assign('page', $res['page']);
        $this->assign('limit', $res['limit']);

        $param['page'] = '{page}';
        $param['limit'] = '{limit}';
        $this->assign('param', $param);
        $this->assign('title', lang('danmaku/title'));
        return $this->fetch('admin@danmaku/index');
    }

    public function del()
    {
        $param = \think\facade\Request::param();
        $ids = $param['ids'];
        $all = $param['all'];

        if (!empty($ids) || !empty($all)) {
            $where = [];
            $where['danmaku_id'] = $ids;
            if ($all == 1) {
                $where[] = ['danmaku_id', '>', 0];
            }
            $res = (new \app\common\model\Danmaku())->delData($where);
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

        if (!empty($ids) && in_array($col, ['danmaku_status'])) {
            $where = [];
            $where['danmaku_id'] = $ids;

            $res = (new \app\common\model\Danmaku())->fieldData($where, $col, $val);
            if ($res['code'] > 1) {
                return $this->error($res['msg']);
            }
            return $this->success($res['msg']);
        }
        return $this->error(lang('param_err'));
    }
}
