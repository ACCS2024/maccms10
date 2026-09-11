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
            || !in_array($record['cash_status'] ?? null, [1,2,'1','2'], true)
            || (int)($record['cash_status'] ?? 0) !== ((int)$row['cash_status'] === 0 ? 2 : 1)) {
            throw new \RuntimeException('Cash archive identity changed');
        }
        return $row;
    }

    /** Read-only administrative projection; the original JSON is never rendered directly. */
    public static function listData(array $where, $page = 1, $limit = 20, string $keyword = ''): array
    {
        $paging = CashRead::pagination($page, $limit);
        if ($paging === null || strlen($keyword) > 200 || preg_match('//u', $keyword) !== 1) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        try {
            $query = Db::name('CashHistory')->master()->where($where);
            if ($keyword !== '') {
                $fragment = substr(json_encode($keyword, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), 1, -1);
                $query->whereRaw("cash_payload LIKE :cash_archive_keyword ESCAPE '!'",
                    ['cash_archive_keyword'=>'%'.strtr($fragment, ['!'=>'!!', '%'=>'!%', '_'=>'!_']).'%']);
            }
            $total = (clone $query)->count();
            $records = $query->order('cash_id desc')
                ->limit($paging['offset'], $paging['limit'])->select()->toArray();
            $list = [];
            foreach ($records as $record) {
                $row = self::original($record);
                $points = PointsBalance::amount($row['cash_points'] ?? null, true);
                $money = OrderAmount::minorUnits($row['cash_money'] ?? null, true);
                $auditTime = PointsBalance::amount($row['cash_time_audit'] ?? 0, true);
                $archiveTime = PointsBalance::amount($record['cash_time_archive'] ?? null);
                $actorId = PointsBalance::amount($record['cash_actor_id'] ?? null, true);
                $actorType = $record['cash_actor_type'] ?? null;
                if ($points === null || $points > 65535 || $money === null || $auditTime === null || $archiveTime === null
                    || $actorId === null || !in_array($actorType, ['internal','admin','user'], true)
                    || ($actorType === 'internal' ? $actorId !== 0 : $actorId === 0)
                    || ($actorType === 'user' && $actorId !== (int)$row['user_id'])) {
                    throw new \RuntimeException('Invalid cash archive display metadata');
                }
                foreach (['cash_bank_name','cash_bank_no','cash_payee_name'] as $field) {
                    if (!is_string($row[$field] ?? null)) { throw new \RuntimeException('Invalid cash archive payee'); }
                }
                if (isset($row['cash_remarks']) && !is_string($row['cash_remarks'])) { throw new \RuntimeException('Invalid cash archive remarks'); }
                $list[] = ['cash_id'=>(int)$record['cash_id'], 'user_id'=>(int)$record['user_id'],
                    'cash_status'=>(int)$record['cash_status'], 'cash_points'=>$points, 'cash_money'=>OrderAmount::decimal($money),
                    'cash_bank_name'=>$row['cash_bank_name'], 'cash_bank_no'=>$row['cash_bank_no'], 'cash_payee_name'=>$row['cash_payee_name'],
                    'cash_remarks'=>$row['cash_remarks'] ?? '', 'cash_time'=>(int)$record['cash_time'], 'cash_time_audit'=>$auditTime,
                    'cash_time_archive'=>$archiveTime, 'cash_actor_type'=>$actorType, 'cash_actor_id'=>$actorId];
            }
            $ids = array_values(array_unique(array_column($list, 'user_id')));
            $names = $ids === [] ? [] : Db::name('User')->master()->whereIn('user_id', $ids)->column('user_name', 'user_id');
            foreach ($list as &$row) { $row['user_name'] = $names[$row['user_id']] ?? ''; }
            unset($row);
            return ['code'=>1, 'msg'=>lang('data_list'), 'page'=>$paging['page'], 'limit'=>$paging['limit'],
                'total'=>$total, 'pagecount'=>(int)ceil($total / $paging['limit']), 'list'=>$list];
        } catch (\Throwable $error) {
            return ['code'=>1002, 'msg'=>lang('admin/cash/archive_unavailable')];
        }
    }
}
