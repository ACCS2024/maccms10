<?php
declare(strict_types=1);
namespace app\common\util;

use think\facade\Db;

/** Read only managed, owner-specific local avatars, retaining the historical fixed-file fallback. */
final class UserPortrait
{
    private static ?\WeakMap $requests = null;

    private static function context(): object
    {
        return request();
    }

    /** Call once with the actual result IDs before rendering a list of avatars. */
    public static function prefetch(array $ids): void
    {
        if ($ids === []) { return; }
        $context = self::context();
        self::$requests ??= new \WeakMap();
        $cache = self::$requests[$context] ?? [];
        $missing = [];
        foreach ($ids as $raw) {
            $id = PointsBalance::amount($raw);
            if ($id !== null && !array_key_exists($id, $cache)) { $missing[$id] = $id; }
        }
        foreach (array_chunk($missing, 500) as $chunk) {
            foreach ($chunk as $id) { $cache[$id] = ''; }
            try {
                $rows = Db::name('User')->master()->field('user_id,user_portrait')->whereIn('user_id', $chunk)->select()->toArray();
                foreach ($rows as $row) {
                    $id = PointsBalance::amount($row['user_id'] ?? null);
                    if ($id !== null && isset($missing[$id]) && self::isManagedPath($id, $row['user_portrait'] ?? null)) {
                        $cache[$id] = $row['user_portrait'];
                    }
                }
            } catch (\Throwable $error) {
                // A missing/unavailable legacy database must not turn a public avatar into a page error.
            }
        }
        self::$requests[$context] = $cache;
    }

    public static function forget(int $id): void
    {
        $context = self::context();
        if (self::$requests !== null && isset(self::$requests[$context])) {
            $cache = self::$requests[$context];
            unset($cache[$id]);
            self::$requests[$context] = $cache;
        }
    }

    public static function isManagedPath(int $id, mixed $path): bool
    {
        return PointsBalance::amount($id) !== null && is_string($path)
            && preg_match('~^upload/user/' . ($id % 10) . '/' . $id . '-[0-9a-f]{32}\\.jpg$~D', $path) === 1;
    }

    public static function url(mixed $raw = null): string
    {
        $id = PointsBalance::amount($raw ?? ($GLOBALS['user']['user_id'] ?? null));
        $default = MAC_PATH . 'static_new/images/touxiang.png';
        if ($id === null) { return $default; }
        self::prefetch([$id]);
        $path = self::$requests[self::context()][$id] ?? '';
        if ($path !== '' && self::exists($path)) { return MAC_PATH . $path; }
        $legacy = 'upload/user/' . ($id % 10) . '/' . $id . '.jpg';
        return self::exists($legacy) ? MAC_PATH . $legacy : $default;
    }

    private static function exists(string $relative): bool
    {
        $path = rtrim(ROOT_PATH, '/\\');
        foreach (explode('/', $relative) as $component) {
            $path .= '/' . $component;
            if (is_link($path)) { return false; }
        }
        return is_file($path) && is_readable($path);
    }
}
