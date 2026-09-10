<?php
declare(strict_types=1);
namespace app\common\util;

/** Internal sub-operations preserve uncertainty when their existing contract requires an exception. */
final class FinancialOperationException extends \RuntimeException
{
    public function __construct(private array $result, ?\Throwable $previous = null)
    {
        parent::__construct($result['msg'], $result['code'], $previous);
    }

    public function result(): array { return $this->result; }
}
