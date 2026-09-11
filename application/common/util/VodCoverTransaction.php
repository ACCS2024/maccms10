<?php
declare(strict_types=1);
namespace app\common\util;

/** Reuse the original-PDO transaction protocol for an independent cover restore. */
final class VodCoverTransaction extends FinancialTransaction
{
    public function __construct(int $id)
    {
        parent::__construct(['kind'=>'vod_cover_restore', 'vod_id'=>$id],
            static fn(string $reference): string => lang('admin/ai_cover/msg_outcome_unknown', [$reference]),
            ['code'=>0, 'msg'=>lang('save_err')], false);
    }
}
