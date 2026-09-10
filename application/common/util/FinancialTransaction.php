<?php
declare(strict_types=1);
namespace app\common\util;

use think\facade\Db;

/** Shared owner/caller transaction mechanics; domain adapters prepare messages and bounded diagnostic context. */
abstract class FinancialTransaction
{
    private static ?\WeakMap $uncertainRequests = null;
    private \think\db\PDOConnection $connection;
    private \PDO $pdo;
    private bool $beginAttempted = false;
    private bool $beginConfirmed = false;
    private bool $integrityLost = false;
    private ?array $result = null;
    protected array $context;
    private object $request;
    private string $reference;
    private string $uncertainMessage;
    private string $failureMessage;
    private ?int $callerDepth = null;
    private string $savepoint;
    private bool $savepointConfirmed = false;

    private static function requestContext(): object
    {
        $container = \think\Container::getInstance();
        // Plain ORM/CLI clients have no HTTP binding; retain their fence for the container lifetime.
        return $container->has('request') ? $container->make('request') : $container;
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

    protected function __construct(array $context, callable $unknownMessage, string $failureMessage, bool $allowCaller)
    {
        $this->context = $context;
        $this->request = self::requestContext();
        // Prepare the diagnostic identity and translation before any financial transaction begins.
        $this->reference = bin2hex(random_bytes(12));
        $this->uncertainMessage = $unknownMessage($this->reference);
        $this->failureMessage = $failureMessage;
        $this->savepoint = 'mac_financial_' . $this->reference;
        $connection = Db::connect();
        if (!$connection instanceof \think\db\PDOConnection || $connection->getConfig('break_reconnect')) {
            throw new \RuntimeException('Financial owner requires a PDO connection without automatic reconnect');
        }
        $connection->query('SELECT 1', [], true);
        $pdo = $connection->getPdo();
        if (!$pdo instanceof \PDO) {
            throw new \RuntimeException('Financial must own its original writer transaction');
        }
        $depth = (new \ReflectionProperty(\think\db\PDOConnection::class, 'transTimes'))->getValue($connection);
        if ($pdo->inTransaction()) {
            if (!$allowCaller || !is_int($depth) || $depth < 1
                || !in_array($connection->getConfig('type'), ['mysql', 'sqlite'], true)) {
                throw new \RuntimeException('Financial requires a managed caller transaction');
            }
            $this->callerDepth = $depth;
        } elseif ($depth !== 0) {
            throw new \RuntimeException('Financial writer has stale transaction nesting');
        }
        $this->connection = $connection;
        $this->pdo = $pdo;
    }

    public function begin(): void
    {
        $this->beginAttempted = true;
        if ($this->callerDepth !== null) {
            // This private target survives the ORM's nesting-counter changes on acknowledgement faults.
            $this->savepointCommand('SAVEPOINT');
            $this->savepointConfirmed = true;
        }
        $this->connection->startTrans();
        $this->beginConfirmed = true;
        $this->assertActive();
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
        if ($active && $this->callerDepth !== null) {
            $active = $this->depth() === $this->callerDepth + 1;
        }
        if (!$active) {
            $this->integrityLost = true;
            throw new \RuntimeException('Financial transaction identity changed');
        }
    }

    public function rollback(array $result): array
    {
        if ($this->result !== null) { return $this->result; }
        if ($this->callerDepth !== null) { return $this->rollbackCaller($result); }
        if (!$this->beginAttempted) { return $this->result = $result; }
        $repair = false;
        $ended = false;
        if (!$this->sameConnection()) { $this->integrityLost = true; }
        try {
            if ($this->beginConfirmed && !$this->pdo->inTransaction()) { $this->integrityLost = true; }
            if ($this->connection->getPdo() !== $this->pdo) {
                throw new \RuntimeException('Original financial PDO was replaced');
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
        if ($this->callerDepth !== null) { return $this->commitCaller($result); }
        $this->assertActive();
        try {
            $this->connection->commit();
            if (!$this->sameConnection() || $this->pdo->inTransaction()) {
                throw new \RuntimeException('Financial commit completion was not confirmed');
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

    private function depth(): int
    {
        return (new \ReflectionProperty(\think\db\PDOConnection::class, 'transTimes'))->getValue($this->connection);
    }

    private function callerActive(): bool
    {
        try { return $this->sameConnection() && $this->pdo->inTransaction(); }
        catch (\Throwable $error) { return false; }
    }

    private function savepointCommand(string $command): void
    {
        if ($this->pdo->exec($command . ' ' . $this->savepoint) === false) {
            throw new \RuntimeException('Financial savepoint command was not acknowledged');
        }
    }

    private function rollbackCaller(array $result): array
    {
        if (!$this->beginAttempted) { return $this->result = $result; }
        if (!$this->callerActive()) { return $this->result = $this->unknown('caller_transaction_changed'); }
        if (!$this->savepointConfirmed) {
            // No business operation or ORM BEGIN ran before the private SAVEPOINT was acknowledged.
            return $this->result = $this->depth() === $this->callerDepth ? $result : $this->unknown('caller_cleanup_unknown');
        }
        try {
            // Never invoke ORM rollback or full PDO rollback for a transaction owned by somebody else.
            $this->savepointCommand('ROLLBACK TO SAVEPOINT');
            if (!$this->callerActive()) { throw new \RuntimeException('Caller changed during savepoint rollback'); }
            // Only an acknowledged rollback of our entire scope permits restoring its nesting metadata.
            (new \ReflectionProperty(\think\db\PDOConnection::class, 'transTimes'))->setValue($this->connection, $this->callerDepth);
            try { $this->savepointCommand('RELEASE SAVEPOINT'); }
            catch (\Throwable $releaseError) { /* Retained private savepoint has no financial effects after confirmed rollback. */ }
            if (!$this->callerActive()) { throw new \RuntimeException('Caller changed during savepoint release'); }
            return $this->result = $result;
        } catch (\Throwable $error) {
            return $this->result = $this->unknown('caller_cleanup_unknown');
        }
    }

    private function commitCaller(array $result): array
    {
        try {
            $this->assertActive();
            $this->connection->commit(); // Nested ORM completion only; the caller still owns the physical commit.
            if (!$this->callerActive() || $this->depth() !== $this->callerDepth) {
                throw new \RuntimeException('Caller nesting completion was not confirmed');
            }
            $this->savepointCommand('RELEASE SAVEPOINT');
            if (!$this->callerActive()) { throw new \RuntimeException('Caller changed during savepoint release'); }
            return $this->result = $result;
        } catch (\Throwable $error) {
            return $this->rollbackCaller(['code'=>2003, 'msg'=>$this->failureMessage]);
        }
    }

    private function discardOriginalConnection(): void
    {
        // close resets the damaged connector depth; it does not prove a retained external PDO was rolled back.
        try {
            if ($this->connection->getPdo() === $this->pdo) { $this->connection->close(); }
        } catch (\Throwable $error) { /* Preserve the uncertain result and block another financial in this request. */ }
    }

    private function unknown(string $outcome): array
    {
        $result = ['code'=>$outcome === 'commit_unknown' ? 2004 : 2005,
            'msg'=>$this->uncertainMessage,
            'info'=>['outcome'=>$outcome, 'retryable'=>false, 'reference'=>$this->reference]];
        if ($this->callerDepth !== null) { $result['info']['caller_rollback_required'] = true; }
        self::$uncertainRequests ??= new \WeakMap();
        self::$uncertainRequests[$this->request] = $result;
        try {
            error_log('Financial transaction outcome unknown: ' . json_encode([
                'reference'=>$this->reference, 'outcome'=>$outcome, 'operation'=>$this->context,
            ], JSON_UNESCAPED_SLASHES));
        } catch (\Throwable $error) { /* Logging cannot turn an uncertain payment into another attempt. */ }
        return $result;
    }
}
