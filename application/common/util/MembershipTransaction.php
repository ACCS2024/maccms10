<?php
declare(strict_types=1);
namespace app\common\util;

final class MembershipTransaction extends FinancialTransaction
{
    public function __construct(int $userId, int $groupId, int $points)
    {
        parent::__construct(['user_id'=>$userId, 'group_id'=>$groupId, 'points'=>$points, 'kind'=>'membership_upgrade'],
            static fn(string $reference): string => lang('model/financial/outcome_unknown', [$reference]),
            ['code'=>1009, 'msg'=>lang('model/user/update_group_err')], true);
    }
}
