<?php
declare(strict_types=1);
namespace app\common\util;

/** Each intent transition owns its transaction before a business reference can be published. */
final class StorageTransaction extends FinancialTransaction
{
    public function __construct(string $phase, string $id)
    {
        parent::__construct(['kind'=>'storage_intent', 'phase'=>$phase, 'intent_id'=>$id],
            static fn(string $reference): string => 'Storage transaction requires inspection: ' . $reference,
            ['code'=>0], false);
    }
}
