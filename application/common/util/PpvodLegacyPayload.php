<?php
namespace app\common\util;

final class PpvodLegacyPayload
{
    public static function enabled(array $config): bool
    {
        return (string)($config['legacy_compat'] ?? '0') === '1';
    }

    /**
     * Reproduce old Yzm.php field semantics without its unsafe SQL and URL handling.
     */
    public static function build(array $payload, array $config, array $collect, array $categoryMap): array
    {
        $videoPath = self::videoPath($payload['rpath'] ?? '');
        $domain = self::baseUrl($payload, 'domain');
        $picDomain = self::baseUrl($payload, 'picdomain', $domain);
        $mp4Domain = self::baseUrl($payload, 'mp4domain', $domain);
        $shareId = self::pathToken($payload['shareid'] ?? '', 'shareid', true);
        $path = self::pathToken($payload['path'] ?? '', 'path', true);

        $playName = trim((string)($config['play_name'] ?? '')) ?: '在线播放';
        $m3u8 = $playName . '$' . $domain . $videoPath . '/index.m3u8';
        $share = $playName . '$' . $domain . '/share/' . $shareId;
        $mode = (string)($config['addr_mode'] ?? 'm3u8');
        if ($mode === 'share') {
            $playUrl = $share;
        } elseif ($mode === 'all') {
            $playUrl = $m3u8 . '$$$' . $share;
        } else {
            $playUrl = $m3u8;
        }

        $category = self::scalarString($payload['category'] ?? '', 'category');
        $typeId = (int)($categoryMap[$category] ?? 0);
        if ($typeId <= 0) {
            $typeId = max(1, (int)($config['legacy_fallback_type_id'] ?? 20));
        }

        return [
            'video_path' => $videoPath,
            'vod_pic' => $picDomain . $videoPath . '/1.jpg',
            'vod_play_url' => $playUrl,
            'vod_down_url' => $mp4Domain . $videoPath . '/mp4/' . $path . '.mp4',
            'vod_status' => (int)($collect['status'] ?? 0),
            'type_id' => $typeId,
        ];
    }

    private static function baseUrl(array $payload, string $key, string $fallback = ''): string
    {
        $value = self::scalarString($payload[$key] ?? '', $key);
        if ($value === '') {
            $value = $fallback;
        }
        $value = rtrim($value, '/');
        $parts = parse_url($value);
        if (
            $value === '' || filter_var($value, FILTER_VALIDATE_URL) === false ||
            !is_array($parts) || !in_array(strtolower((string)($parts['scheme'] ?? '')), ['http', 'https'], true) ||
            empty($parts['host']) || isset($parts['user']) || isset($parts['pass']) ||
            isset($parts['query']) || isset($parts['fragment'])
        ) {
            throw new \InvalidArgumentException($key);
        }
        return $value;
    }

    private static function videoPath($value): string
    {
        $value = str_replace('\\', '/', self::scalarString($value, 'rpath'));
        if (
            $value === '' || preg_match('/[\x00-\x1F\x7F?#]/', $value) ||
            !preg_match('#^/?[A-Za-z0-9._~%/-]+$#D', $value)
        ) {
            throw new \InvalidArgumentException('rpath');
        }
        foreach (explode('/', $value) as $segment) {
            if ($segment === '.' || $segment === '..') {
                throw new \InvalidArgumentException('rpath');
            }
        }
        return substr_count($value, '/') >= 2 ? $value : '/' . $value;
    }

    private static function pathToken($value, string $field, bool $allowEmpty = false): string
    {
        $value = self::scalarString($value, $field);
        if ($value === '') {
            // 老 Yzm 对空 path/shareid 不校验、照样入库（构造出 .../mp4/.mp4 或 .../share/）。
            // 复刻该宽容度：仅因可选字段为空不整条丢弃；非空仍严格校验挡穿越/注入。
            if ($allowEmpty) {
                return '';
            }
            throw new \InvalidArgumentException($field);
        }
        if (!preg_match('/^[A-Za-z0-9._~-]+$/D', $value)) {
            throw new \InvalidArgumentException($field);
        }
        return $value;
    }

    private static function scalarString($value, string $field): string
    {
        if (!is_scalar($value) && $value !== null) {
            throw new \InvalidArgumentException($field);
        }
        $value = trim((string)$value);
        if (preg_match('/[\x00-\x1F\x7F]/', $value)) {
            throw new \InvalidArgumentException($field);
        }
        return $value;
    }
}
