<?php

namespace app\api\controller;

use think\facade\Db;
use think\facade\Request;

class Comment extends Base
{
    use PublicApi;
    public function __construct()
    {
        parent::__construct();
        $this->check_config();

    }

    public function index()
    {

    }

    /**
     *  获取列表
     *
     * @param \think\Request $request
     * @return \think\response\Json
     */
    public function get_list(\think\Request $request)
    {
        $param = array_merge(
            [
                'offset'  => 0,
                'limit'   => 20,
                'orderby' => 'time',
            ],
            $request->param()
        );
        $validate = new \app\api\validate\Comment();
        if (!$validate->scene($request->action())->check($param)) {
            return json([
                'code' => 1001,
                'msg'  => '参数错误: ' . $validate->getError(),
            ]);
        }
        $offset = (int) $param['offset'];
        $limit = (int) $param['limit'];
        $rid = (int) $param['rid'];
        $mid = (int) $param['mid'];
        $orderbyKey = isset($param['orderby']) ? trim((string) $param['orderby']) : 'time';
        if (!in_array($orderbyKey, ['time', 'up', 'down', 'id'], true)) {
            $orderbyKey = 'time';
        }
        $orderField = $orderbyKey === 'id' ? 'comment_id' : 'comment_' . $orderbyKey;
        $order = $orderField . ' DESC, comment_id DESC';

        $where = [
            'comment_status' => 1,
            'comment_pid'    => 0,
            'comment_rid'    => $rid,
            'comment_mid'    => $mid,
        ];

        $total = (new \app\common\model\Comment())->getCountByCond($where);
        $list = [];
        if ($total > 0) {
            $list = (new \app\common\model\Comment())->getListByCond($offset, $limit, $where, $order, '*', []);

            // 收集所有父评论 ID，一次查询批量加载子评论（防止 N+1）
            $parentIds = array_column(is_array($list) ? $list : $list->toArray(), 'comment_id');
            $subMap = [];
            if (!empty($parentIds)) {
                $subRows = Db::name('Comment')
                    ->whereIn('comment_pid', $parentIds)
                    ->where('comment_status', 1)
                    ->order($order)
                    ->limit(200)  // 单批父评论下子评论合计上限，防止超大结果集
                    ->select();
                \app\common\util\UserPortrait::prefetch(array_merge(array_column($list, 'user_id'), array_column($subRows->toArray(), 'user_id')));
                foreach ($subRows as $row) {
                    $rowArr = is_array($row) ? $row : $row->toArray();
                    $subMap[(int)$rowArr['comment_pid']][] = $this->commentRowForApi($rowArr, true);
                }
            }

            \app\common\util\UserPortrait::prefetch(array_column($list, 'user_id'));
            foreach ($list as $k => $v) {
                $list[$k] = $this->commentRowForApi($v, false);
                $list[$k]['sub'] = $subMap[(int)$v['comment_id']] ?? [];
            }
        }

        $page = $limit > 0 ? (int) floor($offset / $limit) + 1 : 1;
        $pagecount = $limit > 0 ? (int) ceil($total / $limit) : 0;

        return json([
            'code' => 1,
            'msg'  => '获取成功',
            'info' => [
                'offset'    => $offset,
                'limit'     => $limit,
                'total'     => $total,
                'page'      => $page,
                'pagecount' => $pagecount,
                'rows'      => $list,
            ],
        ]);
    }

    /**
     * 单条评论输出给前端（含头像 URL、表情 HTML、时间展示文案）
     *
     * @param array $row
     * @param bool  $isReply
     */
    protected function commentRowForApi(array $row, $isReply)
    {
        $uid = isset($row['user_id']) ? (int) $row['user_id'] : 0;
        $row['user_portrait'] = mac_get_user_portrait($uid);
        $raw = isset($row['comment_content']) ? $row['comment_content'] : '';
        $row['comment_content'] = mac_em_replace(mac_restore_htmlfilter($raw));
        $ts = isset($row['comment_time']) ? (int) $row['comment_time'] : 0;
        $row['comment_time_iso'] = $ts > 0 ? date('c', $ts) : '';
        $row['comment_time_title'] = $ts > 0 ? date('Y-m-d H:i:s', $ts) : '';
        $row['comment_time_label'] = $ts > 0
            ? ($isReply ? date('H:i', $ts) : date('Y-m-d H:i:s', $ts))
            : '';
        return $row;
    }

    /**
     * 提交评论
     * api.php/comment/submit (POST)
     * 参数: comment_mid, comment_rid, comment_content, [comment_pid=0]
     */
    public function submit(\think\Request $request)
    {
        return json(\app\common\util\CommentSubmission::submit($request));
    }

    /**
     * 举报评论
     * api.php/comment/report?id=1
     */
    public function report(\think\Request $request)
    {
        $param = $request->param();
        $id = intval($param['id'] ?? 0);
        if ($id < 1) return json(['code' => 1001, 'msg' => '参数错误']);
        $cookie = 'comment-report-' . $id;
        if (!empty(cookie($cookie))) return json(['code' => 1002, 'msg' => lang('index/haved')]);
        (new \app\common\model\Comment())->where(['comment_id' => $id])->setInc('comment_report');
        cookie($cookie, 't', 86400);
        return json(['code' => 1, 'msg' => 'ok']);
    }

    /**
     * 评论顶/踩
     * api.php/comment/digg?id=1&type=up
     */
    public function digg(\think\Request $request)
    {
        $param = $request->param();
        $id = intval($param['id'] ?? 0);
        if ($id < 1) return json(['code' => 1001, 'msg' => '参数错误']);
        $type = trim($param['type'] ?? '');
        if ($type) {
            $cookie = 'comment-digg-' . $id;
            if (!empty(cookie($cookie))) return json(['code' => 1002, 'msg' => lang('index/haved')]);
            if ($type == 'up') { (new \app\common\model\Comment())->where(['comment_id'=>$id])->setInc('comment_up'); cookie($cookie,'t',30); }
            elseif ($type == 'down') { (new \app\common\model\Comment())->where(['comment_id'=>$id])->setInc('comment_down'); cookie($cookie,'t',30); }
        }
        $info = Db::name('comment')->field('comment_up,comment_down')->where(['comment_id'=>$id])->find();
        return json(['code'=>1,'msg'=>'ok','data'=>['up'=>$info['comment_up']??0,'down'=>$info['comment_down']??0]]);
    }
}
