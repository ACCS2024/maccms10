<?php
declare(strict_types=1);
namespace app\common\util;

use think\facade\Db;

/** Atomic credits for the installed user_points INT UNSIGNED column. */
final class PointsBalance
{
    public const MAX = 4294967295;

    public static function amount($value): ?int
    {
        if (PHP_INT_SIZE < 8 || (!is_int($value) && !is_string($value))
            || !preg_match('/^[0-9]{1,10}$/D', (string)$value)) { return null; }
        $value = (int)$value;
        return $value > 0 && $value <= self::MAX ? $value : null;
    }

    /**
     * Caller owns the transaction and must roll it back on false or exception.
     * An upper bound in the same UPDATE prevents non-strict SQL from clipping credits.
     */
    public static function credit($userId, $points): bool
    {
        $userId = self::amount($userId);
        $points = self::amount($points);
        if ($userId === null || $points === null) { return false; }
        return Db::name('User')->where('user_id', $userId)
            ->where('user_points', '<=', self::MAX - $points)
            ->setInc('user_points', $points) === 1;
    }
}
