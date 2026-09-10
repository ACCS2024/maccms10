<?php
declare(strict_types=1);
namespace app\common\util;

/** Standalone redemption; diagnostic context never contains the card number or password. */
final class CardTransaction extends FinancialTransaction
{
    public function __construct(int $userId)
    {
        parent::__construct(['kind'=>'card_redemption', 'user_id'=>$userId],
            static fn(string $reference): string => lang('model/financial/outcome_unknown', [$reference]),
            ['code'=>1004, 'msg'=>lang('model/card/update_card_status_err')], false);
    }

    public function record(int $cardId, int $points): void
    {
        $this->context['card_id'] = $cardId;
        $this->context['points'] = $points;
    }
}
