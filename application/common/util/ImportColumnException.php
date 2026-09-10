<?php
namespace app\common\util;

/** Safe source coordinates for a rejected mapping; never contains cell content or a filesystem path. */
final class ImportColumnException extends \RuntimeException
{
    public function __construct(public readonly int $row, public readonly int $column)
    {
        parent::__construct('Ambiguous import column mapping');
    }
}
