<?php

namespace app\api\controller;

trait PublicApi
{
    protected function check_config(): void
    {
        \app\common\util\ApiAccess::enforce($GLOBALS['config']['api']['publicapi'] ?? null);
    }

    /**
     * SQL 安全过滤：剥除常见 SQL 关键字、限定可接受字符集，并压缩空白。
     *
     * 注意：使用 Unicode 字符类 \p{L}\p{N} 而非 \w，以保留中日韩等 CJK 字符；
     * 原先的 \w 仅匹配 [A-Za-z0-9_]，会把中文关键字整段清空（例如 "海贼王" -> ""），
     * 导致 Vod/Art/Manga 等列表接口的 name/tag/blurb 过滤参数对 CJK 全部失效。
     */
    protected function format_sql_string($str)
    {
        $str = preg_replace('/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|FROM|JOIN|INTO|VALUES|SET|AND|OR|NOT|EXISTS|HAVING|GROUP BY|ORDER BY|LIMIT|OFFSET)\b/i', '', $str);
        // 保留 unicode 字母 / 数字 / 空白 / 连字号 / 点（支持 CJK）
        $str = preg_replace('/[^\p{L}\p{N}\s\-\.]/u', '', $str);
        $str = trim(preg_replace('/\s+/', ' ', $str));
        return $str;
    }
}
