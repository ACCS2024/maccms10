<?php
declare(strict_types=1);
namespace app\common\util;

final class RewardTransaction extends FinancialTransaction
{
    public function __construct(int $sourceUserId, int $points)
    {
        parent::__construct(['user_id'=>$sourceUserId, 'fee_points'=>$points, 'kind'=>'referral_reward'],
            static fn(string $reference): string => lang('model/financial/outcome_unknown', [$reference]),
            ['code'=>2003, 'msg'=>lang('model/user/reward_err')], true);
    }
}
