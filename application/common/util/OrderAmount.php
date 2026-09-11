<?php
declare(strict_types=1);
namespace app\common\util;

/** Exact DECIMAL(12,2) prices and unsigned MEDIUMINT order points on 64-bit PHP. */
final class OrderAmount
{
    public const MAX_POINTS = 16777215;
    public const MAX_MINOR = 999999999999;

    /** Accept existing numeric callers only when the supplied float round-trips exactly. */
    public static function minorUnits($amount, bool $allowZero = false): ?int
    {
        if (PHP_INT_SIZE < 8) { return null; }
        if (is_float($amount)) {
            if (!is_finite($amount) || $amount < 0 || $amount > 9999999999.99) { return null; }
            $decimal = number_format($amount, 2, '.', '');
            if ((float)$decimal !== $amount) { return null; }
            $amount = $decimal;
        } elseif (is_int($amount)) {
            $amount = (string)$amount;
        } elseif (!is_string($amount)) {
            return null;
        }
        if (!preg_match('/^([0-9]{1,10})(?:\.([0-9]{1,2}))?$/D', $amount, $parts)) { return null; }
        $minor = (int)($parts[1] . str_pad($parts[2] ?? '', 2, '0', STR_PAD_RIGHT));
        return $minor > 0 || $allowZero ? $minor : null;
    }

    public static function decimal(int $minor): string
    {
        if ($minor < 0 || $minor > self::MAX_MINOR) { throw new \InvalidArgumentException('Price outside order storage range'); }
        return intdiv($minor, 100) . '.' . str_pad((string)($minor % 100), 2, '0', STR_PAD_LEFT);
    }

    /** A bounded positive decimal exchange rate, preserving fractional configuration. */
    private static function rate($scale): ?array
    {
        if (PHP_INT_SIZE < 8) { return null; }
        if (is_float($scale)) {
            if (!is_finite($scale) || $scale <= 0 || $scale >= 10000000000) { return null; }
            $decimal = number_format($scale, 8, '.', '');
            if ((float)$decimal !== $scale) { return null; }
            $scale = $decimal;
        } elseif (is_int($scale)) {
            $scale = (string)$scale;
        } elseif (!is_string($scale)) {
            return null;
        }
        if (!preg_match('/^([0-9]{1,10})(?:\.([0-9]{1,8}))?$/D', $scale, $parts)) { return null; }
        $fraction = rtrim($parts[2] ?? '', '0');
        $numerator = (int)($parts[1] . $fraction);
        if ($numerator < 1) { return null; }
        return [$numerator, 10 ** strlen($fraction)];
    }

    public static function validRate($scale): bool
    {
        return self::rate($scale) !== null;
    }

    public static function points($points, bool $allowZero = false): ?int
    {
        if ((!is_int($points) && !is_string($points)) || !preg_match('/^[0-9]{1,8}$/D', (string)$points)) { return null; }
        $value = (int)$points;
        return $value <= self::MAX_POINTS && ($value > 0 || $allowZero) ? $value : null;
    }

    /** Recharge retains floor(yuan * scale), but never sells zero or overflowing points. */
    public static function recharge($price, $scale): ?array
    {
        $minor = self::minorUnits($price);
        $rate = self::rate($scale);
        if ($minor === null || $rate === null) { return null; }
        [$numerator, $denominator] = $rate;
        $divisor = 100 * $denominator;
        // Bound before multiplication: the largest possible product is < 1.68e17,
        // well inside signed 64-bit integers even for eight-place fractional rates.
        $ceiling = (self::MAX_POINTS + 1) * $divisor - 1;
        if ($numerator > intdiv($ceiling, $minor)) { return null; }
        $points = intdiv($minor * $numerator, $divisor);
        if ($points < 1) { return null; }
        return ['order_price'=>self::decimal($minor), 'order_points'=>$points];
    }

    /** Withdrawal debits round up: fractional points cannot fund an extra cash payment. */
    public static function withdrawal($price, $scale): ?array
    {
        $minor = self::minorUnits($price);
        $rate = self::rate($scale);
        if ($minor === null || $rate === null) { return null; }
        [$numerator, $denominator] = $rate;
        $divisor = 100 * $denominator;
        $ceiling = self::MAX_POINTS * $divisor;
        if ($numerator > intdiv($ceiling, $minor)) { return null; }
        $product = $minor * $numerator;
        $points = intdiv($product, $divisor) + ($product % $divisor === 0 ? 0 : 1);
        return ['order_price'=>self::decimal($minor), 'order_points'=>$points];
    }

    /** Membership keeps its configured point snapshot; cash is round-half-up to cents. */
    public static function membership($points, $scale, bool $allowFree = false): ?array
    {
        $points = self::points($points, $allowFree);
        if ($points === null) { return null; }
        if ($points === 0) { return ['order_price'=>'0.00', 'order_points'=>0]; }
        $rate = self::rate($scale);
        if ($rate === null) { return null; }
        [$numerator, $denominator] = $rate;
        $dividend = $points * 100 * $denominator;
        $minor = intdiv($dividend, $numerator);
        if ($dividend % $numerator >= intdiv($numerator, 2) + $numerator % 2) { ++$minor; }
        if ($minor < 1 || $minor > self::MAX_MINOR) { return null; }
        return ['order_price'=>self::decimal($minor), 'order_points'=>$points];
    }

    /** Empty/missing minimum means no extra floor, while malformed configuration fails closed. */
    public static function minimum($minimum): ?int
    {
        return $minimum === null || $minimum === '' ? 0 : self::minorUnits($minimum, true);
    }
}
