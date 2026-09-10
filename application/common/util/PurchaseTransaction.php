<?php
declare(strict_types=1);
namespace app\common\util;

/** Content-specific messages and coordinates over the shared financial owner/caller mechanics. */
final class PurchaseTransaction extends FinancialTransaction
{
    public function __construct(int $userId, int $resourceMid, bool $allowCaller = false)
    {
        parent::__construct(['user_id'=>$userId, 'ulog_mid'=>$resourceMid],
            static fn(string $reference): string => lang('index/buy_popedom_outcome_unknown', [$reference]),
            ['code'=>2003, 'msg'=>lang('index/buy_popedom2')], $allowCaller);
    }

    /** Only normalized server-priced coordinates belong in the diagnostic event. */
    public function record(array $record): void
    {
        foreach (['ulog_type','ulog_rid','ulog_sid','ulog_nid','ulog_points'] as $key) {
            if (isset($record[$key]) && is_int($record[$key])) { $this->context[$key] = $record[$key]; }
        }
    }

}
