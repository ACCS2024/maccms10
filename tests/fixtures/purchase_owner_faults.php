<?php
/** Ordinary acknowledgement failures surrounding actual PDO/ORM transaction operations. */
declare(strict_types=1);
class PurchaseOwnerFault
{
    public static array $rules = [], $calls = [], $trace = [];
    public static function reset(array $rules = []): void
    {
        self::$rules = $rules; self::$calls = []; self::$trace = [];
    }
    public static function hit(string $stage): void
    {
        self::$trace[] = $stage;
        $count = self::$calls[$stage] = (self::$calls[$stage] ?? 0) + 1;
        $rule = self::$rules[$stage] ?? null;
        if ($rule === 'always' || $rule === $count) { throw new RuntimeException('Isolated purchase acknowledgement failure: ' . $stage); }
    }
    public static function wrap(string $operation, callable $action): mixed
    {
        self::hit($operation . '_before');
        $result = $action();
        self::hit($operation . '_after');
        return $result;
    }
}
class PurchaseOwnerPdo extends PDO
{
    public function exec(string $statement): int|false
    {
        foreach (['ROLLBACK TO SAVEPOINT'=>'caller_rollback', 'RELEASE SAVEPOINT'=>'caller_release', 'SAVEPOINT'=>'caller_savepoint'] as $prefix=>$stage) {
            if (str_starts_with($statement, $prefix . ' mac_purchase_')) {
                return PurchaseOwnerFault::wrap($stage, fn()=>parent::exec($statement));
            }
        }
        return parent::exec($statement);
    }
    public function beginTransaction(): bool { return PurchaseOwnerFault::wrap('pdo_begin', fn()=>parent::beginTransaction()); }
    public function commit(): bool { return PurchaseOwnerFault::wrap('pdo_commit', fn()=>parent::commit()); }
    public function rollBack(): bool { return PurchaseOwnerFault::wrap('pdo_rollback', fn()=>parent::rollBack()); }
}
trait PurchaseOwnerConnectorFaults
{
    protected function createPdo($dsn, $username, $password, $params)
    {
        return new PurchaseOwnerPdo($dsn, $username, $password, $params);
    }
    public function startTrans(): void
    {
        PurchaseOwnerFault::wrap($this->transTimes === 0 ? 'orm_begin' : 'orm_nested_begin', fn()=>parent::startTrans());
    }
    public function commit(): void
    {
        PurchaseOwnerFault::wrap($this->transTimes <= 1 ? 'orm_commit' : 'orm_nested_commit', fn()=>parent::commit());
    }
    public function rollback(): void
    {
        PurchaseOwnerFault::wrap($this->transTimes <= 1 ? 'orm_rollback' : 'orm_nested_rollback', fn()=>parent::rollback());
    }
}
class PurchaseOwnerSqlite extends think\db\connector\Sqlite { use PurchaseOwnerConnectorFaults; }
class PurchaseOwnerMysql extends think\db\connector\Mysql { use PurchaseOwnerConnectorFaults; }
