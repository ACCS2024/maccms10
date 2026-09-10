<?php
namespace app\api\controller;

use think\facade\Request;
use think\facade\Db;

class Manga extends Base
{
    use PublicApi;
    public function __construct()
    {
        parent::__construct();
        $this->check_config();
    }

    public function get_list(\think\Request $request)
    {
        $param = $request->param();
        $validate = new \app\api\validate\Manga();
        if (!$validate->scene($request->action())->check($param)) {
            return json([
                'code' => 1001,
                'msg'  => '参数错误: ' . $validate->getError(),
            ]);
        }
        $param['page'] = max(1, (int)($param['page'] ?? 1));
        // limit 归一化到两档 {10,20}(防变参放大:任意 limit 收敛到极少数固定值,且每页≤20)
        $param['limit'] = mac_api_norm_limit($param['limit'] ?? 0);

        $where = [];
        $where['manga_status'] = 1;

        if (!empty($param['t'])) {
            $tid = (int)$param['t'];
            if ($tid > 0) {
                $where[] = function($q) use ($tid) {
                    $q->where('type_id', $tid)->whereOr('type_id_1', $tid);
                };
            }
        }
        if (!empty($param['ids'])) {
            $where['manga_id'] = $param['ids'];
        }
        if (!empty($param['wd'])) {
            $param['wd'] = trim($param['wd']);
            $where[] = ['manga_name', 'like', '%' . $param['wd'] . '%'];
        }

        $order = 'manga_time desc';
        if (!empty($param['order'])) {
            $order = $param['order'];
        }

        // 关键词搜索接 Meilisearch(manga_name);命中→manga_id IN(本页命中,Meili 已分页);未启用/无命中/异常→回退原 LIKE
        $meili = !empty($param['wd']) ? mac_meili_api_apply('manga', $where, $param['wd'], $param['page'], $param['limit'], $order, 0) : false;
        if ($meili !== false) {
            // Meili 已按 page/limit 分页;listData 以 page=1/start=0 取本页命中,避免二次分页,再用 Meili 总数覆盖
            $data = (new \app\common\model\Manga())->listData($meili[0], $meili[1], 1, $param['limit'], 0, '*', 1, 0);
            $data['page'] = $param['page'];
            if ($meili[2] !== null) {
                $data['total'] = (int)$meili[2];
                $data['pagecount'] = $param['limit'] > 0 ? (int)ceil($meili[2] / $param['limit']) : 0;
            }
        } else {
            $data = (new \app\common\model\Manga())->listData($where, $order, $param['page'], $param['limit']);
        }
        if (!empty($data['list']) && is_array($data['list'])) {
            foreach ($data['list'] as &$v) {
                if (!empty($v['manga_pic'])) {
                    $v['manga_pic'] = mac_url_img($v['manga_pic']);
                }
                $v['manga_link'] = mac_url_manga_detail($v);
                $v = \app\common\util\PublicContentView::detail('manga', $v);
            }
            unset($v);
        }
        return json($data);
    }

    public function get_detail(\think\Request $request)
    {
        $param = $request->param();
        $id = \app\common\util\ContentResource::positiveInt($param['id'] ?? null);
        if ($id === null || !\app\common\util\ContentResource::scalarParameters($param)) {
            return json(['code'=>1001, 'msg'=>lang('param_err')]);
        }
        $data = \app\common\util\MangaResourceReader::find(['manga_id'=>$id]);
        if ($data['code'] == 1 && !empty($data['info'])) {
            $info = &$data['info'];
            // 处理图片 URL
            $info['manga_pic'] = mac_url_img($info['manga_pic'] ?? '');
            $info['manga_pic_thumb'] = mac_url_img($info['manga_pic_thumb'] ?? '');
            $info['manga_pic_slide'] = mac_url_img($info['manga_pic_slide'] ?? '');
            $info['manga_link'] = mac_url_manga_detail($info);

            // 与前台模板一致：保留 model->infoData 生成的 manga_page_list（含 sid / urls / nid）
            if (!empty($info['manga_page_list']) && is_array($info['manga_page_list'])) {
                foreach ($info['manga_page_list'] as $sid => &$grp) {
                    if (empty($grp['urls']) || !is_array($grp['urls'])) {
                        continue;
                    }
                    foreach ($grp['urls'] as $nid => &$ep) {
                        if (is_array($ep)) {
                            $ep['play_link'] = mac_url_manga_play($info, ['sid' => (int)$sid, 'nid' => (int)$nid]);
                        }
                    }
                    unset($ep);
                }
                unset($grp);
            }

            unset($info['manga_chapter_url'], $info['manga_chapter_from']);
            unset($info['manga_play_server'], $info['manga_play_note']);

            $uid = (int) ($GLOBALS['user']['user_id'] ?? 0);
            $mid = (int) ($info['manga_id'] ?? 0);
            $fav = mac_user_fav_state($uid, 12, $mid);
            $info['is_fav'] = $fav['is_fav'];
            $info['fav_ulog_id'] = $fav['fav_ulog_id'];

            $data['info'] = \app\common\util\PublicContentView::detail('manga', $info);
        }
        return json($data);
    }

    /**
     * 单话阅读数据（供 uni-app / SPA 原生渲染，非 web-view）
     * GET api.php/manga/get_chapter 参数：id manga_id，sid nid 与前台 play 一致
     */
    public function get_chapter(\think\Request $request)
    {
        $param = $request->param();
        $id = \app\common\util\ContentResource::positiveInt($param['id'] ?? null);
        if ($id === null || !\app\common\util\ContentResource::scalarParameters($param)) {
            return json(['code'=>1001, 'msg'=>lang('param_err')]);
        }
        $data = \app\common\util\MangaResourceReader::find(['manga_id'=>$id]);
        if ($data['code'] !== 1) {
            return json(['code'=>1002, 'msg'=>$data['msg']]);
        }
        $info = $data['info'];
        $context = \app\common\util\ContentResource::mangaContext($info, $param);
        if ($context['code'] !== 1) {
            return json($context);
        }
        $access = $this->check_manga_resource_access($info, ['sid'=>$context['sid'], 'nid'=>$context['nid']]);
        return json(['code'=>1, 'msg'=>'ok', 'info'=>[
            'can_read'=>$access['can_access'] ? 1 : 0, 'deny_code'=>(int)$access['code'],
            'deny_msg'=>$access['can_access'] ? '' : (string)$access['msg'], 'points_hint'=>$context['points'],
            'password_required'=>$access['password_required'], 'password_verified'=>$access['password_verified'],
            'password_help_url'=>$access['password_help_url'], 'purchase_supported'=>$context['purchase_supported'],
            'purchase_sid'=>$context['purchase_sid'], 'purchase_nid'=>$context['purchase_nid'],
            'manga_id'=>$context['id'], 'manga_name'=>(string)$info['manga_name'],
            'sid'=>$context['sid'], 'nid'=>$context['nid'], 'episode_name'=>(string)($context['current']['name'] ?? ''),
            'episode_total'=>$context['episode_total'], 'has_prev'=>$context['previous_nid'] !== null,
            'has_next'=>$context['next_nid'] !== null, 'previous_nid'=>$context['previous_nid'], 'next_nid'=>$context['next_nid'],
            'previous_link'=>$context['previous_nid'] !== null ? \app\common\util\ContentResource::mangaReadLink($info, $context['sid'], $context['previous_nid']) : '',
            'next_link'=>$context['next_nid'] !== null ? \app\common\util\ContentResource::mangaReadLink($info, $context['sid'], $context['next_nid']) : '',
            'images'=>$access['can_access'] ? $context['images'] : [],
        ]]);
    }

    public function verify_pwd(\think\Request $request)
    {
        $param = $request->param();
        $id = \app\common\util\ContentResource::positiveInt($param['id'] ?? null);
        if ($id === null || !is_string($param['pwd'] ?? null)) {
            return json(['code'=>1001, 'msg'=>lang('param_err')]);
        }
        $data = \app\common\util\MangaResourceReader::find(['manga_id'=>$id]);
        if ($data['code'] !== 1) {
            return json(['code'=>1031, 'msg'=>$data['msg']]);
        }
        return json(\app\common\util\ContentPassword::verifyManga($data['info'], $param['pwd']));
    }

    /**
     * 获取热门漫画
     * 对应首页热门漫画区块，按月度点击量排序
     *
     * @param \think\Request $request
     * @return \think\response\Json
     *
     * 参数说明:
     *   num   - 可选，数量，默认6
     *   start - 可选，偏移量，默认0
     *   by    - 可选，排序字段，默认 hits_month，可选: hits,hits_day,hits_week,hits_month,time
     */
    public function get_hot(\think\Request $request)
    {
        $param = $request->param();
        $num = isset($param['num']) ? (int)$param['num'] : 6;
        $start = isset($param['start']) ? (int)$param['start'] : 0;
        $by = isset($param['by']) ? trim($param['by']) : 'hits_month';

        $allowBy = ['hits', 'hits_day', 'hits_week', 'hits_month', 'time'];
        if (!in_array($by, $allowBy)) {
            $by = 'hits_month';
        }

        $where = [];
        $where['manga_status'] = 1;

        $list = \app\common\util\PublicContentQuery::query('manga')
            ->field('manga_id,manga_name,manga_pic,manga_blurb,manga_remarks,manga_score,manga_time,manga_hits_month,type_id')
            ->where($where)
            ->order('manga_' . $by . ' desc')
            ->limit($start, $num)
            ->select()->toArray();

        foreach ($list as &$v) {
            $v['manga_pic'] = mac_url_img($v['manga_pic']);
            $v['manga_time_text'] = date('m-d', $v['manga_time']);
            $v['manga_link'] = mac_url_manga_detail($v);
        }
        unset($v);

        return json([
            'code' => 1,
            'msg'  => '获取成功',
            'info' => [
                'total' => count($list),
                'rows'  => $list,
            ],
        ]);
    }

    /**
     * 获取最新漫画
     * 对应首页最新漫画区块
     *
     * @param \think\Request $request
     * @return \think\response\Json
     *
     * 参数说明:
     *   num - 可选，数量，默认24
     */
    public function get_latest(\think\Request $request)
    {
        $param = $request->param();
        $num = isset($param['num']) ? (int)$param['num'] : 24;
        $start = isset($param['start']) ? max(0, (int)$param['start']) : 0;

        $where = [];
        $where['manga_status'] = 1;

        $list = \app\common\util\PublicContentQuery::query('manga')
            ->field('manga_id,manga_name,manga_pic,manga_blurb,manga_remarks,manga_score,manga_points,manga_time,type_id')
            ->where($where)
            ->order('manga_time desc')
            ->limit($start, $num)
            ->select()->toArray();

        foreach ($list as &$v) {
            $v['manga_pic'] = mac_url_img($v['manga_pic']);
            $v['manga_time_text'] = date('m-d', $v['manga_time']);
            $v['manga_link'] = mac_url_manga_detail($v);
        }
        unset($v);
        mac_append_type_is_vip_exclusive_for_rows($list);

        return json([
            'code' => 1,
            'msg'  => '获取成功',
            'info' => [
                'total' => count($list),
                'rows'  => $list,
            ],
        ]);
    }

    /**
     * 搜索建议/自动完成（与列表同一套 Meili + 已发布/回收过滤）
     * api.php/manga/suggest?wd=关键词&limit=10
     */
    public function suggest(\think\Request $request)
    {
        return $this->jsonSuggestByKind($request, 'manga');
    }
}
