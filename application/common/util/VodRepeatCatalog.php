<?php
declare(strict_types=1);
namespace app\common\util;

use think\facade\Db;
use think\facade\Cache;
use think\db\PDOConnection;

/** Derived duplicate data must never cause DDL or a transaction boundary during a video save. */
final class VodRepeatCatalog
{
    public const CACHE_KEY = 'vod_repeat_table_created_time';

    public static function afterSave(array $names, int $id): bool
    {
        try {
            $connection = Db::connect();
            if (self::inTransaction($connection)) {
                self::invalidate();
                return false;
            }
            foreach (array_unique($names) as $name) { self::refresh($name); }
            return true;
        } catch (\Throwable $error) {
            self::invalidate();
            try { error_log('Video saved; duplicate catalog refresh pending for id=' . $id . ' (' . get_class($error) . ')'); }
            catch (\Throwable $loggingError) { /* The acknowledged primary write is not a failed insert. */ }
            return false;
        }
    }

    public static function refresh($name): void
    {
        if (!is_string($name) || $name === '') { throw new \InvalidArgumentException('Invalid duplicate name'); }
        [$connection, $pdo] = self::writer();
        $table = $connection->newQuery()->name('VodRepeat')->getTable();
        if (!self::tableExists($connection, $table)) { throw new \RuntimeException('Duplicate catalog requires a rebuild'); }
        self::assertWriter($connection, $pdo);
        $connection->newQuery()->name('VodRepeat')->where('name1', $name)->delete();
        self::assertWriter($connection, $pdo);
        self::insertGroups($connection, $table, $name);
        self::assertWriter($connection, $pdo);
        // A single-name refresh is not evidence that the entire catalog was rebuilt.
    }

    public static function rebuild(): void
    {
        try { self::rebuildCatalog(); }
        catch (\Throwable $error) { self::invalidate(); throw $error; }
    }

    private static function rebuildCatalog(): void
    {
        [$connection, $pdo] = self::writer();
        $table = $connection->newQuery()->name('VodRepeat')->getTable();
        $exists = self::tableExists($connection, $table);
        self::assertWriter($connection, $pdo);
        $quoted = self::quoteTable($table);
        if (!$exists) {
            $connection->execute('CREATE TABLE IF NOT EXISTS ' . $quoted . " (`id1` int unsigned DEFAULT NULL, `name1` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT '', KEY `name1` (`name1`(100))) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci");
            self::assertWriter($connection, $pdo);
        }
        // Explicit rebuilds retain existing columns, indexes and triggers. Never DROP on an error.
        $connection->execute('TRUNCATE TABLE ' . $quoted);
        self::assertWriter($connection, $pdo);
        self::insertGroups($connection, $table);
        self::assertWriter($connection, $pdo);
        if (!Cache::set(self::CACHE_KEY, time())) { throw new \RuntimeException('Duplicate catalog timestamp unavailable'); }
    }

    private static function insertGroups(PDOConnection $connection, string $table, ?string $name = null): void
    {
        $query = $connection->newQuery()->name('Vod')->master()
            ->field('MIN(vod_id) AS id1,vod_name AS name1')->where('vod_recycle_time', 0)
            ->group('vod_name')->having('COUNT(*) > 1');
        if ($name !== null) { $query->where('vod_name', $name); }
        $query->selectInsert(['id1', 'name1'], $table);
    }

    private static function writer(): array
    {
        $connection = Db::connect();
        if (!$connection instanceof \think\db\connector\Mysql || self::inTransaction($connection)) {
            throw new \RuntimeException('Duplicate catalog maintenance requires an independent MySQL context');
        }
        $connection->query('SELECT 1', [], true);
        $pdo = $connection->getPdo();
        if (!$pdo instanceof \PDO) { throw new \RuntimeException('Duplicate writer unavailable'); }
        self::assertWriter($connection, $pdo);
        return [$connection, $pdo];
    }

    private static function inTransaction($connection): bool
    {
        if (!$connection instanceof PDOConnection) { return true; }
        // The pinned ORM has no public nesting getter. Read only; never repair a caller's depth here.
        $depth = (new \ReflectionProperty(PDOConnection::class, 'transTimes'))->getValue($connection);
        $pdo = $connection->getPdo();
        return $depth !== 0 || ($pdo instanceof \PDO && $pdo->inTransaction());
    }

    private static function assertWriter(PDOConnection $connection, \PDO $pdo): void
    {
        if (Db::connect() !== $connection || $connection->getPdo() !== $pdo || self::inTransaction($connection)) {
            throw new \RuntimeException('Duplicate catalog writer context changed');
        }
    }

    private static function tableExists(PDOConnection $connection, string $table): bool
    {
        self::quoteTable($table);
        $parts = explode('.', $table);
        $bindings = count($parts) === 2 ? $parts : [$parts[0]];
        $schema = count($parts) === 2 ? '?' : 'DATABASE()';
        $rows = $connection->query('SELECT TABLE_TYPE FROM information_schema.TABLES WHERE TABLE_SCHEMA=' . $schema . ' AND TABLE_NAME=? LIMIT 1', $bindings, true);
        if ($rows === []) { return false; }
        if (($rows[0]['TABLE_TYPE'] ?? '') !== 'BASE TABLE') { throw new \RuntimeException('Duplicate catalog is not a base table'); }
        return true;
    }

    private static function quoteTable(string $table): string
    {
        $parts = explode('.', $table);
        if (count($parts) > 2) { throw new \RuntimeException('Invalid duplicate table name'); }
        foreach ($parts as $part) {
            if (strlen($part) > 64 || !preg_match('/^[a-zA-Z0-9_]+$/D', $part)) { throw new \RuntimeException('Invalid duplicate table identifier'); }
        }
        return '`' . implode('`.`', $parts) . '`';
    }

    private static function invalidate(): void
    {
        try { Cache::delete(self::CACHE_KEY); }
        catch (\Throwable $error) { /* The response still reports pending maintenance when cache is unavailable. */ }
    }
}
