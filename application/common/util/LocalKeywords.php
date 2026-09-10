<?php
declare(strict_types=1);

namespace app\common\util;

/** Deterministic local tag suggestions; titles and prose are never sent to a third party. */
final class LocalKeywords
{
    public static function extract($title, $content): string|false
    {
        if (!is_string($title) || !is_string($content)) { return false; }
        $clean = static function (string $text, int $limit): string {
            $text = mb_substr($text, 0, $limit, 'UTF-8');
            $text = preg_replace('#<(script|style)\b[^>]*>.*?</\1\s*>#is', ' ', $text);
            return html_entity_decode(strip_tags($text), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        };
        $title = $clean($title, 512);
        $content = $clean($content, 8192);
        $stop = array_fill_keys(['the', 'and', 'for', 'that', 'this', 'with', 'from', 'are', 'was', 'has', 'have',
            'into', 'you', 'your', 'its', 'not', 'but', 'www', 'http', 'https', 'com',
            '一个', '我们', '他们', '以及', '这个', '那个', '进行', '可以', '已经', '没有'], true);
        $scores = [];
        $labels = [];
        foreach ([[$title, 10], [$content, 1]] as [$text, $weight]) {
            preg_match_all('/[\p{L}\p{N}][\p{L}\p{N}_-]*/u', $text, $matches);
            foreach ($matches[0] as $term) {
                $length = mb_strlen($term, 'UTF-8');
                if ($length < 2 || $length > 32 || ctype_digit($term)) { continue; }
                $key = mb_strtolower($term, 'UTF-8');
                if (isset($stop[$key])) { continue; }
                $labels[$key] ??= $term;
                $scores[$key] = ($scores[$key] ?? 0) + $weight;
            }
        }
        arsort($scores, SORT_NUMERIC);
        $tags = [];
        foreach (array_slice(array_keys($scores), 0, 5) as $key) { $tags[] = $labels[$key]; }
        return $tags === [] ? false : implode(',', $tags);
    }
}
