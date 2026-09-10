<?php
declare(strict_types=1);
namespace app\common\util;

/** A payment callback may acknowledge success only after owning a physical settlement transaction. */
final class OrderTransaction extends FinancialTransaction
{
    public function __construct()
    {
        parent::__construct(['kind'=>'order_payment'],
            static fn(string $reference): string => lang('model/financial/outcome_unknown', [$reference]),
            ['code'=>2004, 'msg'=>lang('save_err')], false);
    }

    public function record(int $orderId, int $userId): void
    {
        $this->context['order_id'] = $orderId;
        $this->context['user_id'] = $userId;
    }
}
