<?php
declare(strict_types=1);
namespace app\common\util;

final class StorageOutcomeUnknown extends \RuntimeException
{
    public function __construct(public readonly array $details, ?\Throwable $previous = null)
    {
        parent::__construct('Storage transaction outcome requires inspection', 0, $previous);
    }
}
