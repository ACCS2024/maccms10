<?php
declare(strict_types=1);
namespace app\common\util;

use think\facade\Db;

/** Immutable financial snapshots; callers own the same physical transaction as the refund. */
final class CashArchive
{
    public const MAX_PAYLOAD_BYTES = 16384;

    public static function actor($actor): ?array
    {
        if ($actor === null) { return ['cash_actor_type'=>'internal', 'cash_actor_id'=>0]; }
        if (!is_array($actor) || !in_array($actor['type'] ?? null, ['user','admin'], true)) { return null; }
        $id = PointsBalance::amount($actor['id'] ?? null);
        return $id === null ? null : ['cash_actor_type'=>$actor['type'], 'cash_actor_id'=>$id];
    }

    public static function store(array $row, array $actor): array
    {
        $cashId = PointsBalance::amount($row['cash_id'] ?? null);
        $userId = PointsBalance::amount($row['user_id'] ?? null, true);
        $time = PointsBalance::amount($row['cash_time'] ?? null, true);
        $status = $row['cash_status'] ?? null;
        if ($cashId === null || $userId === null || $time === null || !in_array($status, [0,1,'0','1'], true)
            || ($actor['cash_actor_type'] === 'user' && $actor['cash_actor_id'] !== $userId)) {
            throw new \RuntimeException('Invalid cash archive identity');
        }
        $payload = json_encode($row, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR);
        if (strlen($payload) > self::MAX_PAYLOAD_BYTES) { throw new \RuntimeException('Cash archive payload exceeds budget'); }
        $record = $actor + ['cash_id'=>$cashId, 'user_id'=>$userId, 'cash_status'=>(int)$status === 0 ? 2 : 1,
            'cash_time'=>$time, 'cash_time_archive'=>time(), 'cash_payload'=>$payload, 'cash_payload_hash'=>hash('sha256', $payload)];
        if (Db::name('CashHistory')->insert($record) !== 1) { throw new \RuntimeException('Cash archive not stored'); }
        self::assertStored($record);
        return $record;
    }

    public static function assertStored(array $expected): void
    {
        $row = Db::name('CashHistory')->master()->where('cash_id', $expected['cash_id'])->lock(true)->find();
        foreach ($expected as $field=>$value) {
            if (!is_array($row) || (string)($row[$field] ?? '') !== (string)$value) { throw new \RuntimeException('Cash archive changed'); }
        }
    }

    /** Recover original fields only after checking the archived identity and payload. */
    public static function original(array $record): array
    {
        $payload = $record['cash_payload'] ?? null;
        $hash = $record['cash_payload_hash'] ?? null;
        if (!is_string($payload) || strlen($payload) > self::MAX_PAYLOAD_BYTES || !is_string($hash)
            || !hash_equals(hash('sha256', $payload), $hash)) { throw new \RuntimeException('Invalid cash archive payload'); }
        $row = json_decode($payload, true, 32, JSON_THROW_ON_ERROR);
        $cashId = PointsBalance::amount($record['cash_id'] ?? null);
        $userId = PointsBalance::amount($record['user_id'] ?? null, true);
        $time = PointsBalance::amount($record['cash_time'] ?? null, true);
        if (!is_array($row) || $cashId === null || $userId === null || $time === null
            || PointsBalance::amount($row['cash_id'] ?? null) !== $cashId
            || PointsBalance::amount($row['user_id'] ?? null, true) !== $userId
            || PointsBalance::amount($row['cash_time'] ?? null, true) !== $time
            || !in_array($row['cash_status'] ?? null, [0,1,'0','1'], true)
            || (int)($record['cash_status'] ?? 0) !== ((int)$row['cash_status'] === 0 ? 2 : 1)) {
            throw new \RuntimeException('Cash archive identity changed');
        }
        return $row;
    }
}
