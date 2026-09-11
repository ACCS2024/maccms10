<?php
declare(strict_types=1);
namespace app\common\util;

/** Cash reservation, refund and settlement each own an independent physical transaction. */
final class CashTransaction extends FinancialTransaction
{
    public function __construct(string $operation, ?int $userId, array $failure)
    {
        parent::__construct(['kind'=>'cash_'.$operation, 'user_id'=>$userId],
            static fn(string $reference): string => lang('model/financial/outcome_unknown', [$reference]),
            $failure, false);
    }
}
