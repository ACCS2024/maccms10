<?php
declare(strict_types=1);
namespace app\common\util;

final class VodCoverOutcomeUnknown extends \RuntimeException
{
    public function __construct(public readonly string $reference, \Throwable $previous)
    {
        parent::__construct('Cover transaction outcome requires inspection', 0, $previous);
    }
}
