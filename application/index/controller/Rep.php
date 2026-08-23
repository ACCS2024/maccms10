<?php
namespace app\index\controller;

use app\common\model\Rep as RepModel;

class Rep extends Base
{
    /**
     * 泛用：替换类型 → [前台分组名, 字段提示]。与 RepModel::$typeMap 一一对应，
     * 全是 maccms 通用概念，不含任何站点专属信息，任意站点直接复用。
     * 未列出的类型（含自定义）自动回退用类型名本身，不会漏显。
     */
    private static $groupMeta = [
        '视频播放地址' => ['播放域名',   'vod_play_url'],
        '视频封面替换' => ['封面域名',   'vod_pic'],
        '播放器替换'   => ['播放器解析', '后台播放器'],
        '文章图片替换' => ['文章图片',   'art_pic / art_content'],
        '域名替换'     => ['域名替换',   'vod / art 多字段'],
        '其他'         => ['其他',       ''],
    ];
    private static $order = ['视频播放地址', '视频封面替换', '播放器替换', '文章图片替换', '域名替换', '其他'];

    public function __construct()
    {
        parent::__construct();
        $cfg = $GLOBALS['config']['rep'] ?? [];
        if (($cfg['enabled'] ?? '1') === '0') {
            throw new \think\exception\HttpException(404, 'Not Found');
        }
    }

    public function index()
    {
        $list = RepModel::activeList();       // 全部启用记录（rep_id asc）
        $cats = $this->groupByType($list);    // 按类型分组 + 计算每类"当前生效值"
        $this->assign('cats', $cats);
        $this->assign('list', $list);         // 供前端 new/viewed 与统计用
        $this->assign('site_name', $GLOBALS['config']['site']['site_name'] ?? 'MacCMS');
        return $this->label_fetch('rep/index');
    }

    /**
     * 按 rep_type 分组；每组内按时间倒序（新→旧），当前生效值 = 最新一条的替换目标。
     * 纯数据处理，与站点无关。
     */
    private function groupByType(array $list): array
    {
        $groups = [];
        foreach ($list as $r) {
            $groups[$r['rep_type']][] = $r;
        }

        $ordered = [];
        $done    = [];
        $build = function ($type, $rows) use (&$ordered, &$done) {
            usort($rows, function ($a, $b) {
                if ((int)$a['rep_create_time'] !== (int)$b['rep_create_time']) {
                    return (int)$b['rep_create_time'] <=> (int)$a['rep_create_time'];
                }
                return (int)$b['rep_id'] <=> (int)$a['rep_id'];
            });
            $meta  = self::$groupMeta[$type] ?? [$type, ''];
            $count = count($rows);
            $ordered[] = [
                'type'    => $type,
                'name'    => $meta[0],
                'field'   => $meta[1],
                'records' => $rows,
                'current' => $rows[0] ?? null,
                'count'   => $count,
                'more'    => max(0, $count - 4),
            ];
            $done[$type] = true;
        };

        foreach (self::$order as $t) {
            if (!empty($groups[$t])) {
                $build($t, $groups[$t]);
            }
        }
        foreach ($groups as $t => $rows) {   // 兜底：不在预设顺序里的类型追加在后
            if (empty($done[$t])) {
                $build($t, $rows);
            }
        }
        return $ordered;
    }
}
