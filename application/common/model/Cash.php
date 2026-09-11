<?php
namespace app\common\model;
use app\common\util\PointsBalance;
use app\common\util\CashTransaction;
use app\common\util\OrderAmount;
use app\common\util\CashRequest;
use app\common\util\CashArchive;
use think\facade\Db;

class Cash extends Base {
    public const MAX_POINTS = 65535;
    public const MAX_BATCH = 1000;
    // 设置数据表（不含前缀）
    protected $name = 'cash';

    // 定义时间戳字段名
    protected $createTime = '';
    protected $updateTime = '';

    // 自动完成
    protected $auto       = [];
    protected $insert     = [];
    protected $update     = [];


    public function listData($where,$order,$page=1,$limit=20,$start=0)
    {
        $page = $page > 0 ? (int)$page : 1;
        $limit = $limit ? (int)$limit : 20;
        $start = $start ? (int)$start : 0;
        if(!is_array($where)){
            $where = json_decode($where,true);
        }
        $offset = ($limit * ($page-1) + $start);
        $total = $this->master()->where($where)->count();
        $list = Db::name('Cash')->master()->where($where)->order($order)->limit($offset, $limit)->select()->toArray();

        $user_ids=[];
        foreach($list as $k=>&$v){
            $v['user_name'] = '';
            if($v['user_id'] >0){
                $user_ids[$v['user_id']] = $v['user_id'];
            }
        }

        unset($v);
        if (!empty($user_ids)) {
            $userNames = Db::name('User')->master()->whereIn('user_id', array_values($user_ids))->column('user_name', 'user_id');
            foreach ($list as $key => $row) {
                $list[$key]['user_name'] = $userNames[$row['user_id']] ?? '';
            }
        }

        return ['code'=>1,'msg'=>lang('data_list'),'page'=>$page,'pagecount'=>ceil($total/$limit),'limit'=>$limit,'total'=>$total,'list'=>$list];
    }

    public function infoData($where,$field='*')
    {
        if(empty($where) || !is_array($where)){
            return ['code'=>1001,'msg'=>lang('param_err')];
        }
        $info = $this->master()->field($field)->where($where)->find();

        if(empty($info)){
            return ['code'=>1002,'msg'=>lang('obtain_err')];
        }
        $info = $info->toArray();

        return ['code'=>1,'msg'=>lang('obtain_ok'),'info'=>$info];
    }

    public function saveData($param)
    {
        return $this->saveForUser($GLOBALS['user']['user_id'] ?? null, $param);
    }

    /** Compatibility entry for trusted internal callers without a browser request. */
    public function saveForUser($ownerId, $param)
    {
        return $this->reserveForUser($ownerId, $param, null);
    }

    /** Public financial ingress always carries a stable request ID. */
    public function saveRequestForUser($ownerId, $param)
    {
        $key = is_array($param) ? CashRequest::key($param['request_id'] ?? null) : null;
        if ($key === null) { return ['code'=>1001, 'msg'=>lang('param_err')]; }
        return $this->reserveForUser($ownerId, $param, $key);
    }

    private function reserveForUser($ownerId, $param, ?string $requestKey)
    {
        if (($blocked = CashTransaction::blockedResult()) !== null) { return $blocked; }
        if (!is_array($param) || ($fields = CashRequest::fields($param)) === null) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        $userId = PointsBalance::amount($ownerId);
        if ($userId === null) { return ['code'=>1002, 'msg'=>lang('param_err')]; }
        $eligibility = self::reservationQuote($fields['cash_money']);
        if ($requestKey === null && $eligibility['code'] !== 1) { return $eligibility; }
        $fingerprint = CashRequest::fingerprint($fields);

        $scope = null;
        $failure = ['code'=>1004,'msg'=>lang('save_err')];
        try {
            CashTransaction::requireTables(array_map(static fn(string $name): string => Db::name($name)->getTable(), $requestKey === null ? ['Cash','User'] : ['Cash','User','CashRequest']));
            $scope = new CashTransaction('reserve', $userId, $failure);
            $scope->begin();
            $user = Db::name('User')->master()->where('user_id', $userId)->lock(true)->find();
            if (!$user || (string)($user['user_status'] ?? '') !== '1') {
                return $scope->rollback(['code'=>1007,'msg'=>lang('model/cash/mush_money_err')]);
            }
            if ($requestKey !== null) {
                $receipts = Db::name('CashRequest')->master()->where(['user_id'=>$userId, 'request_id'=>$requestKey])->lock(true)->limit(2)->select()->toArray();
                if (count($receipts) > 1) { throw new \RuntimeException('Duplicate cash request receipts'); }
                if ($receipts !== []) {
                    $receipt = $receipts[0];
                    $cashId = PointsBalance::amount($receipt['cash_id']);
                    if ($cashId === null || !is_string($receipt['payload_hash'])) { throw new \RuntimeException('Invalid cash receipt'); }
                    if (!hash_equals($receipt['payload_hash'], $fingerprint)) {
                        return $scope->rollback(['code'=>1009, 'msg'=>lang('model/cash/request_conflict'),
                            'info'=>['request_id'=>$requestKey, 'cash_id'=>$cashId, 'retryable'=>false]]);
                    }
                    return $scope->rollback(CashRequest::acknowledgement($cashId, $requestKey));
                }
            }
            if ($eligibility['code'] !== 1) { return $scope->rollback($eligibility); }
            $points = $eligibility['points'];
            $data = $fields + ['user_id'=>$userId, 'cash_points'=>$points, 'cash_time'=>time(), 'cash_status'=>0, 'cash_time_audit'=>0];
            $validate = mac_validate('Cash');
            if (!$validate->check($data)) { return $scope->rollback(['code'=>1001, 'msg'=>lang('param_err').'：'.$validate->getError()]); }
            [$available, $frozen] = self::balances($user);
            if ($available < $points || $frozen > PointsBalance::MAX - $points) {
                return $scope->rollback(['code'=>1007,'msg'=>lang('model/cash/mush_money_err')]);
            }
            $scope->assertActive();
            $changed = Db::name('User')->where('user_id', $userId)->where('user_status', 1)
                ->where('user_points', $available)->where('user_points_froze', $frozen)
                ->dec('user_points', $points)->inc('user_points_froze', $points)->update();
            if ($changed !== 1) { throw new \RuntimeException('Cash reservation changed'); }
            $cashId = PointsBalance::amount(Db::name('Cash')->insertGetId($data));
            if ($cashId === null) { throw new \RuntimeException('Cash identity was not stored'); }
            self::assertCash($cashId, $data + ['cash_id'=>$cashId]);
            self::assertBalances($userId, $available - $points, $frozen + $points);
            if ($requestKey !== null) {
                $receipt = ['user_id'=>$userId, 'request_id'=>$requestKey, 'payload_hash'=>$fingerprint, 'cash_id'=>$cashId, 'created_at'=>$data['cash_time']];
                $scope->assertActive();
                if (Db::name('CashRequest')->insert($receipt) !== 1) { throw new \RuntimeException('Cash receipt not stored'); }
                $stored = Db::name('CashRequest')->master()->where(['user_id'=>$userId, 'request_id'=>$requestKey])->lock(true)->find();
                foreach ($receipt as $field=>$value) {
                    if (!is_array($stored) || (string)($stored[$field] ?? '') !== (string)$value) { throw new \RuntimeException('Cash receipt changed'); }
                }
                // Receipt triggers must not alter the financial rows after their earlier readback.
                self::assertCash($cashId, $data + ['cash_id'=>$cashId]);
                self::assertBalances($userId, $available - $points, $frozen + $points);
            }
            $scope->assertActive();
            return $scope->commit($requestKey === null ? ['code'=>1,'msg'=>lang('save_ok')] : CashRequest::acknowledgement($cashId, $requestKey));
        } catch (\Throwable $e) {
            return $scope !== null ? $scope->rollback($failure) : $failure;
        }
    }

    private static function reservationQuote(string $money): array
    {
        $settings = $GLOBALS['config']['user'] ?? [];
        if (!is_array($settings) || !in_array($settings['cash_status'] ?? '0', [1, '1'], true)) {
            return ['code'=>1005, 'msg'=>lang('model/cash/not_open')];
        }
        $quote = OrderAmount::withdrawal($money, $settings['cash_ratio'] ?? null);
        $minimum = OrderAmount::minimum($settings['cash_min'] ?? null);
        if ($quote === null || $minimum === null || $quote['order_points'] > self::MAX_POINTS) {
            return ['code'=>1001, 'msg'=>lang('param_err')];
        }
        if (OrderAmount::minorUnits($money) < $minimum) {
            return ['code'=>1006, 'msg'=>lang('model/cash/min_money_err').'：'.OrderAmount::decimal($minimum)];
        }
        return ['code'=>1, 'points'=>$quote['order_points']];
    }

    public function delData($where, $actor = null)
    {
        if (($blocked = CashTransaction::blockedResult()) !== null) { return $blocked; }
        if (empty($where) || !is_array($where) || ($actor = CashArchive::actor($actor)) === null) {
            return ['code'=>1001,'msg'=>lang('param_err')];
        }
        $scope = null;
        $failure = ['code'=>1005,'msg'=>lang('del_err')];
        try {
            CashTransaction::requireTables(array_map(static fn(string $name): string => Db::name($name)->getTable(), ['Cash','User','CashHistory']));
            $scope = new CashTransaction('refund', null, $failure);
            $scope->begin();
            // Lock cash rows first, then capture every affected account before changing any balance.
            $list = Db::name('Cash')->master()->where($where)->order('cash_id')->lock(true)->limit(self::MAX_BATCH + 1)->select()->toArray();
            if (count($list) > self::MAX_BATCH) { return $scope->rollback(['code'=>1008, 'msg'=>lang('model/cash/batch_limit')]); }
            $archives = [];
            $balances = [];
            $owners = [];
            foreach ($list as $row) {
                $status = (int)$row['cash_status'];
                if ($status !== 0 && $status !== 1) {
                    throw new \RuntimeException('invalid cash state');
                }
                $userId = PointsBalance::amount($row['user_id'], $status === 1);
                if ($userId === null) { throw new \RuntimeException('Invalid cash owner'); }
                $owners[$userId] = $userId;
            }
            sort($owners, SORT_NUMERIC);
            foreach ($owners as $userId) {
                $user = Db::name('User')->master()->where('user_id', $userId)->lock(true)->find();
                if ($user !== null) { $balances[$userId] = self::balances($user); }
            }
            foreach ($list as $row) {
                $status = (int)$row['cash_status'];
                $userId = (int)$row['user_id'];
                if (isset($balances[$userId])) { self::assertBalances($userId, ...$balances[$userId]); }
                if ($status === 0) {
                    $points = PointsBalance::amount($row['cash_points']);
                    if ($points === null) {
                        throw new \RuntimeException('invalid frozen points');
                    }
                    if (!isset($balances[$userId])) { throw new \RuntimeException('Cash owner missing'); }
                    [$available, $frozen] = $balances[$userId];
                    if ($frozen < $points || $available > PointsBalance::MAX - $points) {
                        throw new \RuntimeException('Cash refund exceeds available capacity');
                    }
                    $scope->assertActive();
                    $changed = Db::name('User')->where('user_id', $userId)
                        ->where('user_points', $available)->where('user_points_froze', $frozen)
                        ->inc('user_points', $points)->dec('user_points_froze', $points)->update();
                    if ($changed !== 1) { throw new \RuntimeException('Cash refund changed'); }
                    $balances[$userId] = [$available + $points, $frozen - $points];
                    self::assertBalances($userId, ...$balances[$userId]);
                    self::assertCash((int)$row['cash_id'], $row);
                }
                $scope->assertActive();
                $archives[] = CashArchive::store($row, $actor);
                self::assertCash((int)$row['cash_id'], $row);
                if (Db::name('Cash')->where('cash_id', $row['cash_id'])->delete() !== 1
                    || Db::name('Cash')->master()->where('cash_id', $row['cash_id'])->find() !== null) {
                    throw new \RuntimeException('cash delete failed');
                }
            }
            foreach ($archives as $archive) { CashArchive::assertStored($archive); }
            foreach ($balances as $userId=>$expected) { self::assertBalances($userId, ...$expected); }
            $scope->assertActive();
            return $scope->commit(['code'=>1,'msg'=>lang('del_ok')]);
        } catch (\Throwable $e) {
            return $scope !== null ? $scope->rollback($failure) : $failure;
        }
    }

    public function fieldData($where,$col,$val)
    {
        return ['code'=>1001, 'msg'=>lang('param_err')];
    }

    public function auditData($where)
    {
        if (($blocked = CashTransaction::blockedResult()) !== null) { return $blocked; }
        if (empty($where) || !is_array($where)) {
            return ['code'=>1001,'msg'=>lang('param_err')];
        }
        $scope = null;
        $failure = ['code'=>1005,'msg'=>lang('save_err')];
        try {
            CashTransaction::requireTables(array_map(static fn(string $name): string => Db::name($name)->getTable(), ['Cash','User','Plog']));
            $scope = new CashTransaction('settle', null, $failure);
            $scope->begin();
            $list = Db::name('Cash')->master()->where($where)->where('cash_status', 0)
                ->order('cash_id')->lock(true)->limit(self::MAX_BATCH + 1)->select()->toArray();
            if (count($list) > self::MAX_BATCH) { return $scope->rollback(['code'=>1008, 'msg'=>lang('model/cash/batch_limit')]); }
            foreach ($list as $row) {
                $points = PointsBalance::amount($row['cash_points']);
                $userId = PointsBalance::amount($row['user_id']);
                if ($points === null || $userId === null) { throw new \RuntimeException('Invalid cash reservation'); }
                $user = Db::name('User')->master()->where('user_id', $userId)->lock(true)->find();
                [$available, $frozen] = self::balances($user);
                if ($frozen < $points) { throw new \RuntimeException('Missing frozen reservation'); }
                $update = ['cash_status'=>1, 'cash_time_audit'=>time()];
                $scope->assertActive();
                if (Db::name('Cash')->where('cash_id', $row['cash_id'])->where('cash_status', 0)->update($update) !== 1) {
                    throw new \RuntimeException('Cash state changed');
                }
                if (Db::name('User')->where('user_id', $userId)->where('user_points', $available)
                    ->where('user_points_froze', $frozen)->dec('user_points_froze', $points)->update() !== 1) {
                    throw new \RuntimeException('Cash settlement changed');
                }
                $expected = ['user_id'=>$userId, 'plog_type'=>9, 'plog_points'=>$points];
                $ledger = new \app\common\model\Plog();
                $started = time();
                if (($ledger->saveData($expected)['code'] ?? null) !== 1) { throw new \RuntimeException('Cash ledger rejected'); }
                $scope->assertActive();
                $ledgerId = PointsBalance::amount($ledger->getLastInsID());
                $stored = $ledgerId === null ? null : Db::name('Plog')->master()->where('plog_id', $ledgerId)->find();
                foreach ($expected as $field=>$value) {
                    if (!$stored || PointsBalance::amount($stored[$field] ?? null) !== $value) {
                        throw new \RuntimeException('Cash ledger was not stored exactly');
                    }
                }
                $storedTime = PointsBalance::amount($stored['plog_time'] ?? null);
                if ($storedTime === null || $storedTime < $started || $storedTime > time()) { throw new \RuntimeException('Cash ledger time changed'); }
                self::assertCash((int)$row['cash_id'], array_replace($row, $update));
                self::assertBalances($userId, $available, $frozen - $points);
            }
            $scope->assertActive();
            return $scope->commit(['code'=>1,'msg'=>'审核成功']);
        } catch (\Throwable $e) {
            return $scope !== null ? $scope->rollback($failure) : $failure;
        }
    }

    private static function balances(?array $user): array
    {
        $available = PointsBalance::amount($user['user_points'] ?? null, true);
        $frozen = PointsBalance::amount($user['user_points_froze'] ?? null, true);
        if ($available === null || $frozen === null) { throw new \RuntimeException('Invalid cash owner balances'); }
        return [$available, $frozen];
    }

    private static function assertBalances(int $id, int $available, int $frozen): void
    {
        if (self::balances(Db::name('User')->master()->where('user_id', $id)->find()) !== [$available, $frozen]) {
            throw new \RuntimeException('Cash balances were not stored exactly');
        }
    }

    private static function assertCash(int $id, array $expected): void
    {
        $row = Db::name('Cash')->master()->where('cash_id', $id)->find();
        foreach ($expected as $field=>$value) {
            if (!$row || !array_key_exists($field, $row)) { throw new \RuntimeException('Cash record disappeared'); }
            $equal = $field === 'cash_money' ? OrderAmount::minorUnits($row[$field], true) === OrderAmount::minorUnits($value, true)
                : (is_int($value) ? PointsBalance::amount($row[$field], true) === $value : $row[$field] === $value);
            if (!$equal) { throw new \RuntimeException('Cash record was not stored exactly'); }
        }
    }

}
