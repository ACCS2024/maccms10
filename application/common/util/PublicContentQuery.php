<?php
namespace app\common\util;

use think\facade\Db;

/** Read-only publication policy for public media endpoints, never an admin/model default. */
final class PublicContentQuery
{
    public static function query(string $kind): \think\db\Query
    {
        $conditions = self::conditions($kind);
        return Db::name($kind)->where($conditions);
    }

    /** Include these guards in both the count query and its existing cache key. */
    public static function conditions(string $kind): array
    {
        if (!in_array($kind, ['vod', 'art', 'manga'], true)) {
            throw new \InvalidArgumentException('Unsupported public content kind');
        }
        // Numeric condition tuples remain AND constraints if callers add their own filters.
        $conditions = [[$kind . '_status', '=', 1]];
        $recycle = $kind . '_recycle_time';
        if (in_array($recycle, Db::name($kind)->getTableFields(), true)) {
            $conditions[] = [$recycle, '=', 0];
        }
        return $conditions;
    }

    /** A cached public list is reusable only while every listed ID is still publicly visible. */
    public static function cachedRowsVisible(string $kind, mixed $rows, int $maximum = 1000): bool
    {
        $query = self::query($kind);
        if (!is_array($rows) || $maximum < 0 || count($rows) > $maximum) {
            return false;
        }
        $ids = [];
        foreach ($rows as $row) {
            if (!is_array($row)) {
                return false;
            }
            $id = $row[$kind . '_id'] ?? null;
            if ((!is_int($id) && !is_string($id)) || !preg_match('/^[1-9][0-9]{0,9}$/D', (string)$id)
                || (int)$id > 4294967295 || isset($ids[(int)$id])) {
                return false;
            }
            $ids[(int)$id] = true;
        }
        return $ids === [] || (int)$query->whereIn($kind . '_id', array_keys($ids))->count() === count($ids);
    }
}
