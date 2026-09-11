<?php
declare(strict_types=1);
namespace app\common\util;

use think\facade\Db;

/** Durable transfer attempts. Intent/transfer changes own their transaction; references join the caller's transaction. */
final class StorageIntent
{
    public static function prepare(string $path, StoragePublicUrl $policy, string $scope='attachment', int $owner=0): array
    {
        if (!in_array($scope,['attachment','avatar','download','ai_cover'],true)
            || PointsBalance::amount($owner,true)===null || ($scope==='avatar' && !UserPortrait::isManagedPath($owner,$path))
            || ($scope==='ai_cover' && $owner===0)) {
            throw new \InvalidArgumentException('Invalid storage owner');
        }
        $source=self::source($path);
        $row=['intent_id'=>bin2hex(random_bytes(16)), 'provider'=>$policy->provider,
            'destination_hash'=>$policy->fingerprint,'scope'=>$scope,'owner_id'=>$owner,
            'local_path'=>$path,'source_bytes'=>$source['bytes'],'source_sha256'=>$source['sha256'],
            'expected_url'=>$policy->expected($path),'remote_url'=>'','transfer_state'=>'prepared',
            'reference_state'=>'pending','annex_id'=>0,'result_code'=>'','created_at'=>time(),'updated_at'=>time()];
        return self::independent('prepare', $row['intent_id'], static function () use($row): array {
            if (Db::name('StorageIntent')->insert($row)!==1) { throw new \RuntimeException('Storage intent was not inserted'); }
            return self::exact($row['intent_id'],$row);
        });
    }

    public static function inspect(string $id): array
    {
        self::id($id);
        $rows=Db::name('StorageIntent')->master()->where('intent_id',$id)->limit(2)->select()->toArray();
        if (count($rows)!==1) { throw new \RuntimeException('Storage intent not found or ambiguous'); }
        return $rows[0];
    }

    /** Claim once before the SDK is invoked. A previous in-flight/unknown attempt is never silently retried. */
    public static function claim(string $id, StoragePublicUrl $policy): array
    {
        self::id($id);
        return self::independent('claim', $id, static function () use($id,$policy): array {
            $row=Db::name('StorageIntent')->master()->where('intent_id',$id)->lock(true)->find();
            if (!$row || $row['transfer_state']!=='prepared' || $row['reference_state']!=='pending'
                || $row['provider']!==$policy->provider || !hash_equals($row['destination_hash'],$policy->fingerprint)
                || $row['expected_url']!==$policy->expected($row['local_path'])) {
                throw new \RuntimeException('Storage intent cannot be claimed');
            }
            self::sameSource($row);
            $update=['transfer_state'=>'attempting','updated_at'=>time()];
            if (Db::name('StorageIntent')->where('intent_id',$id)->where('transfer_state','prepared')->update($update)!==1) {
                throw new \RuntimeException('Storage intent was already claimed');
            }
            return self::exact($id,array_replace($row,$update));
        });
    }

    public static function finish(string $id, StoragePublicUrl $policy, ?string $remoteUrl, string $reason): array
    {
        self::id($id);
        if (!in_array($reason,['remote_confirmed','local_fallback','provider_exception','invalid_result','invalid_url','source_changed'],true)) {
            throw new \InvalidArgumentException('Invalid transfer result code');
        }
        return self::independent('finish', $id, static function () use($id,$policy,$remoteUrl,$reason): array {
            $row=Db::name('StorageIntent')->master()->where('intent_id',$id)->lock(true)->find();
            if (!$row || $row['transfer_state']!=='attempting' || $row['reference_state']!=='pending'
                || $row['provider']!==$policy->provider || !hash_equals($row['destination_hash'],$policy->fingerprint)
                || ($remoteUrl===null && $reason==='remote_confirmed')
                || ($remoteUrl!==null && !in_array($reason,['remote_confirmed','source_changed'],true))
                || ($remoteUrl!==null && !$policy->accepts($remoteUrl,$row['local_path']))) {
                throw new \RuntimeException('Storage intent result is not valid');
            }
            $update=['transfer_state'=>$remoteUrl===null?'outcome_unknown':'remote_confirmed',
                'remote_url'=>$remoteUrl??'','result_code'=>$reason,'updated_at'=>time()];
            if (Db::name('StorageIntent')->where('intent_id',$id)->where('transfer_state','attempting')->update($update)!==1) {
                throw new \RuntimeException('Storage intent result was not saved');
            }
            return self::exact($id,array_replace($row,$update));
        });
    }

    /** Caller must roll back its transaction on any exception. No commit or filesystem deletion is performed here. */
    public static function recordReferences(array $references): void
    {
        if (!$references || count($references)>32 || !self::masterPdo(Db::connect())->inTransaction()) {
            throw new \RuntimeException('Reference records require a bounded caller-owned transaction');
        }
        self::transactionalTables(Db::connect(), ['StorageIntent','Annex']);
        $updates=[];
        foreach ($references as $id=>$annexId) {
            self::id($id);$annexId=PointsBalance::amount($annexId);
            $row=Db::name('StorageIntent')->master()->where('intent_id',$id)->lock(true)->find();
            $annex=$annexId===null?null:Db::name('Annex')->master()->where('annex_id',$annexId)->lock(true)->find();
            if (!$row || !$annex || $row['reference_state']!=='pending'
                || !in_array($row['transfer_state'],['remote_confirmed','outcome_unknown'],true) || $row['result_code']==='source_changed'
                || !in_array($annex['annex_type']??null,['image','file','media'],true)
                || ($row['scope']==='avatar' && ($annex['annex_type']??null)!=='image')
                || PointsBalance::amount($annex['annex_size']??null,true)!==PointsBalance::amount($row['source_bytes'],true)
                || ($annex['annex_file']!==$row['local_path']
                    && ($row['transfer_state']!=='remote_confirmed' || $annex['annex_file']!==$row['remote_url']))) {
                throw new \RuntimeException('Stored attachment does not match its transfer intent');
            }
            if ($annex['annex_file']===$row['local_path']) { self::sameSource($row); }
            if ($row['scope']==='avatar') {
                self::transactionalTables(Db::connect(), ['User']);
                $user=Db::name('User')->master()->where('user_id',$row['owner_id'])->lock(true)->find();
                if (!$user || $user['user_portrait']!==$row['local_path']) { throw new \RuntimeException('Avatar pointer does not match its transfer intent'); }
            }
            $updates[$id]=array_replace($row,['reference_state'=>'committed','annex_id'=>$annexId,'updated_at'=>time()]);
        }
        foreach ($updates as $id=>$expected) {
            if (Db::name('StorageIntent')->where('intent_id',$id)->where('reference_state','pending')->update([
                'reference_state'=>'committed','annex_id'=>$expected['annex_id'],'updated_at'=>$expected['updated_at']])!==1) {
                throw new \RuntimeException('Storage reference was not recorded');
            }
            self::exact($id,$expected);
        }
    }

    public static function source(string $path): array
    {
        if (!StoragePublicUrl::localPath($path)) { throw new \InvalidArgumentException('Invalid local storage source'); }
        $absolute=rtrim(ROOT_PATH,'/\\');
        foreach (explode('/',$path) as $component) {
            $absolute.='/'.$component;
            if (is_link($absolute)) { throw new \RuntimeException('Storage source cannot be a symbolic link'); }
        }
        clearstatcache(true,$absolute);
        $bytes=is_file($absolute)?@filesize($absolute):false;
        $hash=is_int($bytes)&&$bytes>=0&&$bytes<=4294967295?@hash_file('sha256',$absolute):false;
        if (!is_string($hash)) { throw new \RuntimeException('Storage source is not a readable bounded file'); }
        return ['bytes'=>$bytes,'sha256'=>$hash];
    }

    public static function sameSource(array $row): void
    {
        $source=self::source($row['local_path']);
        if ($source['bytes']!==PointsBalance::amount($row['source_bytes'],true)
            || !hash_equals($row['source_sha256'],$source['sha256'])) { throw new \RuntimeException('Storage source changed after preparation'); }
    }

    private static function id(mixed $id): void
    {
        if (!is_string($id) || !preg_match('/^[0-9a-f]{32}$/D',$id)) { throw new \InvalidArgumentException('Invalid storage intent ID'); }
    }

    private static function exact(string $id,array $expected): array
    {
        $stored=self::inspect($id);
        foreach ($expected as $field=>$value) {
            if (!array_key_exists($field,$stored) || (is_int($value) ? (string)$stored[$field]!== (string)$value : $stored[$field]!==$value)) {
                throw new \RuntimeException('Storage intent did not persist exactly');
            }
        }
        return $stored;
    }

    private static function masterPdo($connection): \PDO
    {
        // SELECT initializes a cold connection and selects its master without committing anything.
        $connection->query('SELECT 1',[],true);
        $pdo=$connection->getPdo();
        if (!$pdo instanceof \PDO) { throw new \RuntimeException('Storage database connection is unavailable'); }
        return $pdo;
    }

    private static function transactionalTables($connection,array $tables): void
    {
        if (self::masterPdo($connection)->getAttribute(\PDO::ATTR_DRIVER_NAME)!=='mysql') { return; }
        foreach ($tables as $table) {
            $engines=$connection->query('SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?',[Db::name($table)->getTable()],true);
            if (count($engines)!==1 || strtolower((string)$engines[0]['ENGINE'])!=='innodb') {
                throw new \RuntimeException('Storage references require transactional tables');
            }
        }
    }

    private static function independent(string $phase, string $id, callable $operation): array
    {
        if (($blocked = StorageTransaction::blockedResult()) !== null) {
            throw new StorageOutcomeUnknown($blocked['info'] + ['phase'=>$phase, 'intent_id'=>$id]);
        }
        $connection=Db::connect();$current=$connection->getPdo();
        // Check the current handle and the actual master, including raw PDO transactions outside ORM counters.
        if (($current instanceof \PDO && $current->inTransaction()) || self::masterPdo($connection)->inTransaction()) {
            throw new \RuntimeException('Storage intents must commit independently before external writes');
        }
        Db::name('StorageIntent')->getTableFields();
        self::transactionalTables($connection,['StorageIntent']);
        $transaction = new StorageTransaction($phase, $id);
        try {
            $transaction->begin();
            $data = $operation();
            $transaction->assertActive();
            $result = $transaction->commit(['code'=>1, 'data'=>$data]);
        } catch (\Throwable $error) {
            $result = $transaction->rollback(['code'=>0]);
            if (isset($result['info'])) {
                throw new StorageOutcomeUnknown($result['info'] + ['phase'=>$phase, 'intent_id'=>$id], $error);
            }
            throw $error;
        }
        if ($result['code'] !== 1) {
            throw new StorageOutcomeUnknown($result['info'] + ['phase'=>$phase, 'intent_id'=>$id]);
        }
        return $result['data'];
    }
}
