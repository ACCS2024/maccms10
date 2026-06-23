<?php
namespace app\common\model;

use think\Model;

class Rep extends Model
{
    protected $name = 'rep';
    protected $pk   = 'rep_id';

    // type → [table => [fields]]
    public static $typeMap = [
        '文章图片替换' => ['art' => ['art_pic', 'art_content']],
        '视频封面替换' => ['vod' => ['vod_pic']],
        '视频播放地址' => ['vod' => ['vod_play_url']],
        '播放器替换'   => ['vod' => ['vod_play_from', 'vod_play_server']],
        '域名替换'     => ['vod' => ['vod_play_url', 'vod_pic'], 'art' => ['art_content', 'art_pic']],
    ];

    public static function activeList()
    {
        return self::where('rep_status', 1)->order('rep_id', 'asc')->select()->toArray();
    }

    public static function allList()
    {
        return self::order('rep_id', 'desc')->select()->toArray();
    }

    // Returns [ 'sql' => string, 'tables' => [ [table,field], ... ] ]
    public static function buildSql($type, $original, $replacement)
    {
        $map = self::$typeMap[$type] ?? null;
        if (!$map) {
            return ['sql' => '', 'tables' => []];
        }
        $sqls   = [];
        $tables = [];
        foreach ($map as $table => $fields) {
            foreach ($fields as $field) {
                $sqls[]   = "UPDATE mac_{$table} SET {$field} = REPLACE({$field}, '" . addslashes($original) . "', '" . addslashes($replacement) . "');";
                $tables[] = [$table, $field];
            }
        }
        return ['sql' => implode("\n", $sqls), 'tables' => $tables];
    }
}
