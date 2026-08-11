<?php
namespace app\common\model;

use think\Model;

class Rep extends Model
{
    protected $name = 'rep';
    protected $pk   = 'rep_id';

    // Single source of truth for type → [table => [fields]] mapping
    public static $typeMap = [
        '文章图片替换' => ['art' => ['art_pic', 'art_content']],
        '视频封面替换' => ['vod' => ['vod_pic']],
        '视频播放地址' => ['vod' => ['vod_play_url']],
        '播放器替换'   => ['vod' => ['vod_play_from', 'vod_play_server']],
        '域名替换'     => ['vod' => ['vod_play_url', 'vod_pic'], 'art' => ['art_content', 'art_pic']],
        '其他'         => [],
    ];

    public static function activeList()
    {
        return self::where('rep_status', 1)->order('rep_id', 'asc')->limit(500)->select()->toArray();
    }

    public static function allList()
    {
        return self::order('rep_id', 'desc')->limit(500)->select()->toArray();
    }

    /**
     * 执行前的硬校验。返回错误说明；返回空串表示可以执行。
     *
     * 这几条不是形式主义 —— 每一条都对应一种「一旦放过去就得从备份里捞回来」的事故：
     *  - 类型不在 typeMap（含「其他」这种映射为空的）：不知道该改哪张表哪个字段;
     *  - 原文与替换后相同：白跑 448 批全表扫描，纯粹浪费;
     *  - 原文过短：REPLACE 是无边界的子串替换。把 'a' 换成 'b' 会命中 mac_art
     *    里每一篇正文的每一个字母,38892 行 759M 数据当场全毁。四个字符是经验下限
     *    (够放下 '.com' / 'http' 这类最短的真实替换目标)。
     */
    public static function checkExecutable($type, $original, $replacement)
    {
        $map = self::$typeMap[$type] ?? null;
        if ($map === null) {
            return "类型「{$type}」不在支持列表里，无法自动执行";
        }
        if (!$map) {
            return "类型「{$type}」没有配置对应的表字段，只能手工处理";
        }
        if ($original === '') {
            return '原内容为空';
        }
        if ($original === $replacement) {
            return '原内容与替换内容相同，无需执行';
        }
        if (mb_strlen($original) < self::MIN_ORIG_LEN) {
            return '原内容少于 ' . self::MIN_ORIG_LEN . ' 个字符，太短了。'
                 . 'REPLACE() 是无边界子串替换，这么短的串会在正文里命中海量无关位置，'
                 . '请填写更完整的片段（例如带上域名或协议头）';
        }
        return '';
    }

    /** 原内容的最小长度，见 checkExecutable() 里的说明 */
    const MIN_ORIG_LEN = 4;

    /**
     * 把一条替换记录展开成可分批执行的「执行单元」列表。
     * 每个单元 = 一张表的一个字段，带上主键名与主键区间 —— 分批就是在主键上开窗口。
     *
     * 为什么按主键开窗口而不是 LIMIT：LIKE 匹配 longtext 用不上索引，
     * 「WHERE field LIKE ... LIMIT 1000」每批都要从头全表扫。
     * 主键区间 (pk > lo AND pk <= lo+step) 走的是聚簇索引，
     * 每批稳定只碰 step 行，且天然可续跑（游标就是一个整数）。
     */
    public static function plan($type)
    {
        $map   = self::$typeMap[$type] ?? [];
        $pre   = config('database.connections.mysql.prefix');
        $units = [];
        foreach ($map as $table => $fields) {
            $full = $pre . $table;
            $keys = \think\facade\Db::query("SHOW KEYS FROM `{$full}` WHERE Key_name = 'PRIMARY'");
            if (empty($keys[0]['Column_name'])) {
                continue;   // 没主键就没法开窗口,跳过而不是猜一个
            }
            $pk  = $keys[0]['Column_name'];
            $mm  = \think\facade\Db::query("SELECT MIN(`{$pk}`) AS lo, MAX(`{$pk}`) AS hi FROM `{$full}`");
            $lo  = (int)($mm[0]['lo'] ?? 0);
            $hi  = (int)($mm[0]['hi'] ?? 0);
            foreach ($fields as $field) {
                $units[] = [
                    'table'    => $full,
                    'field'    => $field,
                    'pk'       => $pk,
                    'min'      => $lo,
                    'max'      => $hi,
                    'cursor'   => $lo - 1,   // 游标是「已处理到的主键」,开区间起点
                    'affected' => 0,
                    'done'     => $hi <= 0,  // 空表直接算完成
                ];
            }
        }
        return $units;
    }

    /**
     * 把用户输入的原文转成 LIKE 模式。
     * % 和 _ 在 LIKE 里是通配符,URL 里出现 _ 很常见（例如 play_url 这种路径片段）,
     * 不转义就会把匹配范围放大到完全不相干的行。反斜杠要先转,否则会吃掉后面的转义。
     */
    public static function likePattern($original)
    {
        return '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $original) . '%';
    }

    // Only for SQL display copy (not execution). Uses proper escaping for single-quoted literals.
    public static function buildSql($type, $original, $replacement)
    {
        $map = self::$typeMap[$type] ?? null;
        if (!$map) {
            return ['sql' => '', 'tables' => []];
        }
        $esc    = fn($v) => addcslashes($v, "\x00\x1a\\'");
        $sqls   = [];
        $tables = [];
        foreach ($map as $table => $fields) {
            foreach ($fields as $field) {
                $sqls[]   = "UPDATE mac_{$table} SET {$field} = REPLACE({$field}, '{$esc($original)}', '{$esc($replacement)}');";
                $tables[] = [$table, $field];
            }
        }
        return ['sql' => implode("\n", $sqls), 'tables' => $tables];
    }
}
