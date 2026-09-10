<?php
declare(strict_types=1);
namespace app\common\util;

use think\facade\Db;

/** One transaction-owned purchase. Caller-owned savepoints use a separate contract. */
final class PurchaseTransaction
{
    private static ?\WeakMap $uncertainRequests = null;
    private \think\db\PDOConnection $connection;
    private \PDO $pdo;
    private bool $beginAttempted = false;
    private bool $beginConfirmed = false;
    private bool $integrityLost = false;
    private ?array $result = null;
    private array $context;
    private object $request;
    private string $reference;
    private string $uncertainMessage;

    private static function requestContext(): object
    {
        return \think\Container::getInstance()->make('request');
    }

    /** An uncertain payment must not be automatically repeated within the same request. */
    public static function blockedResult(): ?array
    {
        $previous = (self::$uncertainRequests ??= new \WeakMap())[self::requestContext()] ?? null;
        if ($previous === null) { return null; }
        $previous['code'] = 2005;
        $previous['info']['outcome'] = 'request_blocked';
        return $previous;
    }

    public function __construct(int $userId, int $resourceMid)
    {
        $this->context = ['user_id'=>$userId, 'ulog_mid'=>$resourceMid];
        $this->request = self::requestContext();
        // Prepare the diagnostic identity and translation before any financial transaction begins.
        $this->reference = bin2hex(random_bytes(12));
        $this->uncertainMessage = lang('index/buy_popedom_outcome_unknown', [$this->reference]);
        $connection = Db::connect();
        if (!$connection instanceof \think\db\PDOConnection || $connection->getConfig('break_reconnect')) {
            throw new \RuntimeException('Purchase owner requires a PDO connection without automatic reconnect');
        }
        $connection->query('SELECT 1', [], true);
        $pdo = $connection->getPdo();
        if (!$pdo instanceof \PDO || $pdo->inTransaction()) {
            throw new \RuntimeException('Purchase must own its original writer transaction');
        }
        $this->connection = $connection;
        $this->pdo = $pdo;
    }

    public function begin(): void
    {
        $this->beginAttempted = true;
        $this->connection->startTrans();
        $this->beginConfirmed = true;
        $this->assertActive();
    }

    /** Only normalized server-priced coordinates belong in the diagnostic event. */
    public function record(array $record): void
    {
        foreach (['ulog_type','ulog_rid','ulog_sid','ulog_nid','ulog_points'] as $key) {
            if (isset($record[$key]) && is_int($record[$key])) { $this->context[$key] = $record[$key]; }
        }
    }

    private function sameConnection(): bool
    {
        try { return Db::connect() === $this->connection && $this->connection->getPdo() === $this->pdo; }
        catch (\Throwable $error) { return false; }
    }

    public function assertActive(): void
    {
        try { $active = $this->sameConnection() && $this->pdo->inTransaction(); }
        catch (\Throwable $error) { $active = false; }
        if (!$active) {
            $this->integrityLost = true;
            throw new \RuntimeException('Purchase transaction identity changed');
        }
    }

    public function rollback(array $result): array
    {
        if ($this->result !== null) { return $this->result; }
        if (!$this->beginAttempted) { return $this->result = $result; }
        $repair = false;
        $ended = false;
        if (!$this->sameConnection()) { $this->integrityLost = true; }
        try {
            if ($this->beginConfirmed && !$this->pdo->inTransaction()) { $this->integrityLost = true; }
            if ($this->connection->getPdo() !== $this->pdo) {
                throw new \RuntimeException('Original purchase PDO was replaced');
            }
            // A rollback failure may already have changed the ORM nesting depth. Do not call it twice.
            $this->connection->rollback();
            $ended = !$this->pdo->inTransaction();
        } catch (\Throwable $error) { $repair = true; }
        if (!$ended) {
            $repair = true;
            $ended = $this->rollbackOriginalPdo();
        }
        if ($repair) { $this->discardOriginalConnection(); }
        return $this->result = $ended && !$this->integrityLost ? $result
            : $this->unknown($this->integrityLost ? 'transaction_changed' : 'cleanup_unknown');
    }

    public function commit(array $result): array
    {
        if ($this->result !== null) { return $this->result; }
        $this->assertActive();
        try {
            $this->connection->commit();
            if (!$this->sameConnection() || $this->pdo->inTransaction()) {
                throw new \RuntimeException('Purchase commit completion was not confirmed');
            }
            return $this->result = $result;
        } catch (\Throwable $error) {
            // Once COMMIT was attempted, successful cleanup cannot establish whether payment committed.
            $this->rollbackOriginalPdo();
            $this->discardOriginalConnection();
            return $this->result = $this->unknown('commit_unknown');
        }
    }

    private function rollbackOriginalPdo(): bool
    {
        try {
            if ($this->pdo->inTransaction()) { $this->pdo->rollBack(); }
            return !$this->pdo->inTransaction();
        } catch (\Throwable $error) { return false; }
    }

    private function discardOriginalConnection(): void
    {
        // close resets the damaged connector depth; it does not prove a retained external PDO was rolled back.
        try {
            if ($this->connection->getPdo() === $this->pdo) { $this->connection->close(); }
        } catch (\Throwable $error) { /* Preserve the uncertain result and block another purchase in this request. */ }
    }

    private function unknown(string $outcome): array
    {
        $result = ['code'=>$outcome === 'commit_unknown' ? 2004 : 2005,
            'msg'=>$this->uncertainMessage,
            'info'=>['outcome'=>$outcome, 'retryable'=>false, 'reference'=>$this->reference]];
        self::$uncertainRequests ??= new \WeakMap();
        self::$uncertainRequests[$this->request] = $result;
        try {
            error_log('Purchase transaction outcome unknown: ' . json_encode([
                'reference'=>$this->reference, 'outcome'=>$outcome, 'purchase'=>$this->context,
            ], JSON_UNESCAPED_SLASHES));
        } catch (\Throwable $error) { /* Logging cannot turn an uncertain payment into another attempt. */ }
        return $result;
    }
}
