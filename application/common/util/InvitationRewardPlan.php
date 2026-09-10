<?php
declare(strict_types=1);
namespace app\common\util;

/** Validate configured invitation tiers and calculate their cumulative effect without performing writes. */
final class InvitationRewardPlan
{
    public const DURATIONS = ['day'=>86400, 'week'=>604800, 'month'=>2592000, 'year'=>31536000];

    public static function tiers(array $configuration): array
    {
        $enabled = array_key_exists('invite_reward_status', $configuration) ? $configuration['invite_reward_status'] : 0;
        if (!in_array($enabled, [0,1,'0','1'], true)) { throw new \InvalidArgumentException('Invalid invitation reward switch'); }
        if ((int)$enabled === 0) { return []; }
        $configured = array_key_exists('invite_reward', $configuration) ? $configuration['invite_reward'] : [];
        if (!is_array($configured) || count($configured) > 100) { throw new \InvalidArgumentException('Invalid invitation tiers'); }
        $tiers = [];
        foreach ($configured as $threshold=>$reward) {
            $threshold = PointsBalance::amount($threshold);
            $group = is_array($reward) ? PointsBalance::amount($reward['group_id'] ?? null, true) : null;
            $points = is_array($reward) ? PointsBalance::amount($reward['points'] ?? null, true) : null;
            $duration = is_array($reward) ? ($reward['long'] ?? null) : null;
            if ($threshold === null || isset($tiers[$threshold]) || $group === null || $group > 32767
                || $points === null || !is_string($duration) || !isset(self::DURATIONS[$duration])) {
                throw new \InvalidArgumentException('Invalid invitation tier');
            }
            $tiers[$threshold] = ['group_id'=>$group, 'points'=>$points, 'long'=>$duration];
        }
        ksort($tiers, SORT_NUMERIC);
        return $tiers;
    }

    /** Group rows are loaded from the writer connection by the transaction owner. */
    public static function calculate(array $user, array $tiers, array $groups, int $now): array
    {
        $count = PointsBalance::amount($user['user_invite_count'] ?? null, true);
        $level = PointsBalance::amount($user['user_invite_reward_level'] ?? null, true);
        $balance = PointsBalance::amount($user['user_points'] ?? null, true);
        $end = PointsBalance::amount($user['user_end_time'] ?? null, true);
        if ($count === null || $level === null || $balance === null || $end === null
            || PointsBalance::amount($now) === null || !is_string($user['group_id'] ?? null)
            || !preg_match('/^[0-9]+(?:,[0-9]+)*$/D', $user['group_id'])) {
            throw new \InvalidArgumentException('Invalid invitation beneficiary state');
        }
        $memberships = [];
        foreach (explode(',', $user['group_id']) as $group) {
            $id = PointsBalance::amount($group);
            if ($id === null || $id > 32767) { throw new \InvalidArgumentException('Invalid membership group'); }
            $memberships[$id] = $id;
        }
        $maximumGroup = max($memberships);
        $points = 0;
        $events = [];
        foreach ($tiers as $threshold=>$reward) {
            if ($threshold <= $level || $threshold > $count) { continue; }
            if ($reward['points'] > PointsBalance::MAX - $balance - $points) {
                throw new \OverflowException('Invitation points exceed the account capacity');
            }
            $points += $reward['points'];
            if ($reward['group_id'] >= 2) {
                if (!isset($groups[$reward['group_id']]) || (int)$groups[$reward['group_id']]['group_status'] !== 1) {
                    throw new \InvalidArgumentException('Invitation group is unavailable');
                }
                $seconds = self::DURATIONS[$reward['long']];
                $end = max($end, $now);
                if ($seconds > PointsBalance::MAX - $end) { throw new \OverflowException('Invitation expiry exceeds the account capacity'); }
                $end += $seconds;
                if ($reward['group_id'] > $maximumGroup) {
                    $maximumGroup = $reward['group_id'];
                    $memberships[$maximumGroup] = $maximumGroup;
                }
            }
            $level = $threshold;
            $events[] = ['threshold'=>$threshold] + $reward;
        }
        sort($memberships, SORT_NUMERIC);
        $membership = implode(',', $memberships);
        if (strlen($membership) > 255) { throw new \OverflowException('Invitation groups exceed the account column'); }
        return ['points'=>$points, 'group_id'=>$membership, 'user_end_time'=>$end,
            'user_invite_reward_level'=>$level, 'events'=>$events];
    }
}
