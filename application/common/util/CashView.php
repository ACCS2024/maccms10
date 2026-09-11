<?php
declare(strict_types=1);
namespace app\common\util;

/** Display only: derive a feasible single-request amount with the actual debit rule. */
final class CashView
{
    public static function maximumMoney($available, $rate): ?string
    {
        $available = PointsBalance::amount($available, true);
        if ($available === null || !OrderAmount::validRate($rate)) { return null; }
        $available = min($available, \app\common\model\Cash::MAX_POINTS);
        $low = 0;
        $high = OrderAmount::MAX_MINOR;
        while ($low < $high) {
            $middle = $low + intdiv($high - $low + 1, 2);
            $quote = OrderAmount::withdrawal(OrderAmount::decimal($middle), $rate);
            if ($quote !== null && $quote['order_points'] <= $available) { $low = $middle; }
            else { $high = $middle - 1; }
        }
        return OrderAmount::decimal($low);
    }

    public static function data($settings, $user): array
    {
        $settings = is_array($settings) ? $settings : [];
        $user = is_array($user) ? $user : [];
        $rate = $settings['cash_ratio'] ?? null;
        $minimum = OrderAmount::minimum($settings['cash_min'] ?? null);
        $maximum = self::maximumMoney($user['user_points'] ?? null, $rate);
        if ($maximum !== null && (!in_array($settings['cash_status'] ?? null, [1, '1'], true)
            || $minimum === null || OrderAmount::minorUnits($maximum, true) < $minimum)) { $maximum = '0.00'; }
        return [
            'rate'=>OrderAmount::validRate($rate) ? (is_float($rate) ? rtrim(rtrim(number_format($rate, 8, '.', ''), '0'), '.') : (string)$rate) : '--',
            'minimum'=>$minimum === null ? '--' : OrderAmount::decimal($minimum),
            'available'=>PointsBalance::amount($user['user_points'] ?? null, true) ?? '--',
            'frozen'=>PointsBalance::amount($user['user_points_froze'] ?? null, true) ?? '--',
            'maximum'=>$maximum ?? '--',
        ];
    }
}
