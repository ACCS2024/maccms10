<?php
namespace app\common\validate;
use think\Validate;

class Vod extends Validate
{
    protected $rule =   [
        'vod_name'  => 'require',
        'type_id'  => 'require',
    ];

    protected $message  =   [
        'vod_name.require' => 'validate/require_name',
        'type_id.require' => 'validate/require_type',
    ];

    protected $scene = [
        'add'  =>  ['vod_name','type_id'],
        'edit'  =>  ['vod_name','type_id'],
    ];


    // xss过滤、长度裁剪
    public static function formatDataBeforeDb($data)
    {
        $filter_fields = [
            'vod_name'           => 255,
            'vod_sub'            => 255,
            'vod_en'             => 255,
            'vod_color'          => 6,
            'vod_tag'            => 100,
            'vod_class'          => 255,
            'vod_pic'            => 1024,
            'vod_pic_thumb'      => 1024,
            'vod_pic_slide'      => 1024,
            'vod_pic_original'   => 1024,
            'vod_pic_screenshot' => 65535,
            'vod_actor'          => 255,
            'vod_director'       => 255,
            'vod_writer'         => 100,
            'vod_behind'         => 100,
            'vod_blurb'          => 255,
            'vod_remarks'        => 100,
            'vod_pubdate'        => 100,
            'vod_serial'         => 20,
            'vod_tv'             => 30,
            'vod_weekday'        => 30,
            'vod_area'           => 20,
            'vod_lang'           => 10,
            'vod_year'           => 10,
            'vod_version'        => 30,
            'vod_state'          => 30,
            'vod_author'         => 60,
            'vod_jumpurl'        => 150,
            'vod_tpl'            => 30,
            'vod_tpl_play'       => 30,
            'vod_tpl_down'       => 30,
            'vod_duration'       => 10,
            'vod_reurl'          => 255,
            'vod_rel_vod'        => 255,
            'vod_rel_art'        => 255,
            'vod_pwd'            => 10,
            'vod_pwd_url'        => 255,
            'vod_pwd_play'       => 10,
            'vod_pwd_play_url'   => 255,
            'vod_pwd_down'       => 10,
            'vod_pwd_down_url'   => 255,
            'vod_play_from'      => 255,
            'vod_play_server'    => 255,
            'vod_play_note'      => 255,
            'vod_down_from'      => 255,
            'vod_down_server'    => 255,
            'vod_down_note'      => 255,
        ];
        foreach ($filter_fields as $field => $length) {
            if (!isset($data[$field])) {
                continue;
            }
            $data[$field] = mac_filter_xss($data[$field]);
            $data[$field] = mb_substr($data[$field], 0, $length);
        }

        // ── 数字/decimal 列格式化(补 formatDataBeforeDb 原本只管字符串的缺口)──────────
        // 采集方常发空串或超范围值,严格模式(MySQL 8 默认)会 1366/1264 直接 500。
        // 这里空串/非数字 → 0,转对类型,钳到列上限,让数据本身就干净,不靠放宽 sql_mode。
        // 注:type_id 只保证是合法 smallint;落到哪个分类仍取决于 interface.vodtype
        //     采集↔本地映射(未配时会被钳成 32767=不存在的分类,内容进库但前台不可见)。
        $int_fields = [
            // tinyint unsigned 0..255
            'vod_status' => [0, 255], 'vod_isend' => [0, 255], 'vod_lock' => [0, 255],
            'vod_level' => [0, 255], 'vod_copyright' => [0, 255], 'vod_plot' => [0, 255],
            // smallint signed -32768..32767
            'type_id' => [-32768, 32767],
            // smallint unsigned 0..65535
            'type_id_1' => [0, 65535], 'group_id' => [0, 65535], 'vod_points' => [0, 65535],
            'vod_points_play' => [0, 65535], 'vod_points_down' => [0, 65535], 'vod_trysee' => [0, 65535],
            // mediumint unsigned 0..16777215
            'vod_total' => [0, 16777215], 'vod_hits' => [0, 16777215], 'vod_hits_day' => [0, 16777215],
            'vod_hits_week' => [0, 16777215], 'vod_hits_month' => [0, 16777215], 'vod_up' => [0, 16777215],
            'vod_down' => [0, 16777215], 'vod_score_all' => [0, 16777215], 'vod_score_num' => [0, 16777215],
            // int unsigned 0..4294967295
            'vod_time' => [0, 4294967295], 'vod_time_add' => [0, 4294967295], 'vod_time_hits' => [0, 4294967295],
            'vod_time_make' => [0, 4294967295], 'vod_recycle_time' => [0, 4294967295], 'vod_douban_id' => [0, 4294967295],
        ];
        foreach ($int_fields as $field => $range) {
            if (!array_key_exists($field, $data)) {
                continue;
            }
            $n = is_numeric($data[$field]) ? (int)$data[$field] : 0;
            $data[$field] = max($range[0], min($range[1], $n));
        }
        // decimal(3,1) unsigned 0..99.9
        foreach (['vod_score', 'vod_douban_score'] as $field) {
            if (!array_key_exists($field, $data)) {
                continue;
            }
            $n = is_numeric($data[$field]) ? round((float)$data[$field], 1) : 0.0;
            $data[$field] = max(0, min(99.9, $n));
        }

        return $data;
    }

}