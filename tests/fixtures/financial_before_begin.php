<?php
/** Deterministic competing work at the actual connector BEGIN boundary, before its native transaction. */
require dirname(__DIR__,2).'/vendor/autoload.php';
trait FinancialBeforeBegin
{
    public function startTrans(): void
    {
        $hook = $GLOBALS['financial_before_begin'] ?? null;
        unset($GLOBALS['financial_before_begin']);
        if ($hook !== null) { $hook(); }
        parent::startTrans();
    }
}
class FinancialBeforeBeginMysql extends think\db\connector\Mysql { use FinancialBeforeBegin; }
class FinancialBeforeBeginSqlite extends think\db\connector\Sqlite { use FinancialBeforeBegin; }
