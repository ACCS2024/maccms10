<?php
declare(strict_types=1);
namespace app\common\util;

use app\common\model\Plog;
use app\common\model\Ulog;
use app\common\model\User;
use think\facade\Db;

/** Transaction owner for a server-priced content purchase; controllers must verify the request identity. */
final class ContentPurchase
{
    /** Normalize legacy endpoint coordinates without allowing coercion or model/operation mismatches. */
    public static function parameters(array $parameters): ?array
    {
        $normalized=[];
        foreach (['mid','type','id','sid','nid'] as $field) {
            $optional=in_array($field,['sid','nid'],true);
            $value=array_key_exists($field,$parameters)?$parameters[$field]:($optional?0:null);
            $normalized[$field]=PointsBalance::amount($value,$optional);
            if ($normalized[$field]===null) { return null; }
        }
        if (!in_array($normalized['mid'],[1,2,12],true)
            || !in_array($normalized['type'],$normalized['mid']===1?[4,5]:[1],true)
            || $normalized['sid']>255 || $normalized['nid']>65535) { return null; }
        return $normalized;
    }

    /** $pricedRecord is built from current server content/configuration, never from submitted prices. */
    public static function buy($userId, array $pricedRecord): array
    {
        return self::execute($userId, $pricedRecord);
    }

    /** Internal server quote only: it runs after the owner lock and must return a priced record or a final response. */
    public static function buyVideo($userId, callable $quote): array
    {
        return self::execute($userId, [], $quote, 1);
    }

    /** Article quotes resolve an actual chapter with the same transaction and receipt contract. */
    public static function buyArt($userId, callable $quote): array
    {
        return self::execute($userId, [], $quote, 2);
    }

    /** Manga quotes validate the actual source/chapter before the same transactional debit. */
    public static function buyManga($userId, callable $quote): array
    {
        return self::execute($userId, [], $quote, 12);
    }

    private static function record(int $userId, array $pricedRecord): ?array
    {
        $selection=self::parameters([
            'mid'=>$pricedRecord['ulog_mid']??null,'type'=>$pricedRecord['ulog_type']??null,
            'id'=>$pricedRecord['ulog_rid']??null,'sid'=>$pricedRecord['ulog_sid']??null,'nid'=>$pricedRecord['ulog_nid']??null,
        ]);
        $points=PointsBalance::amount($pricedRecord['ulog_points']??null,true);
        if ($selection===null || $points===null || $points>65535) { return null; }
        return ['user_id'=>$userId,'ulog_mid'=>$selection['mid'],'ulog_type'=>$selection['type'],
            'ulog_rid'=>$selection['id'],'ulog_sid'=>$selection['sid'],'ulog_nid'=>$selection['nid'],'ulog_points'=>$points];
    }

    private static function execute($userId, array $pricedRecord, ?callable $quote = null, ?int $resourceMid = null): array
    {
        $userId=PointsBalance::amount($userId);
        $record=$userId!==null && $quote===null ? self::record($userId,$pricedRecord) : null;
        if ($userId===null || ($quote===null && $record===null)) { return ['code'=>2001,'msg'=>lang('param_err')]; }
        $started=false;
        try {
            if ($quote!==null && ($pdo=Db::connect()->getPdo()) && $pdo->inTransaction()) {
                throw new \RuntimeException('A resolved content purchase must own its transaction');
            }
            self::requireTransactionalStorage($resourceMid);
            Db::startTrans(); $started=true;
            // The same owner lock serializes all purchases before the authoritative receipt/balance reads.
            $user=Db::name('User')->master()->where('user_id',$userId)->lock(true)->find();
            $balance=$user?PointsBalance::amount($user['user_points']??null,true):null;
            if (!$user || (int)$user['user_status']!==1 || $balance===null) {
                throw new \RuntimeException('Purchase owner is unavailable');
            }
            if ($quote!==null) {
                $resolved=$quote($user);
                if (!is_array($resolved) || !isset($resolved['code'])) { throw new \RuntimeException('Invalid content quote'); }
                if (!isset($resolved['record'])) {
                    Db::rollback(); $started=false;
                    return $resolved;
                }
                $record=self::record($userId,$resolved['record']);
                if ($resolved['code']!==1 || $record===null || $record['ulog_mid']!==$resourceMid || $record['ulog_points']===0) {
                    throw new \RuntimeException('Invalid content quote');
                }
            }
            $points=$record['ulog_points'];
            // Use a current read: a transaction's earlier consistent snapshot may predate the lock winner.
            if (Db::name('Ulog')->master()->where($record)->lock(true)->find()) {
                Db::commit(); $started=false;
                return ['code'=>1,'msg'=>lang('index/buy_popedom1')];
            }
            if ($points>$balance) {
                Db::rollback(); $started=false;
                return ['code'=>2002,'msg'=>lang('index/buy_popedom3',[$points,$balance]),
                    'info'=>['need_points'=>$points,'current_points'=>$balance]];
            }
            if ($points>0) {
                if (Db::name('User')->where('user_id',$userId)->where('user_points',$balance)
                    ->setDec('user_points',$points)!==1
                    || (string)Db::name('User')->master()->where('user_id',$userId)->value('user_points')!==(string)($balance-$points)) {
                    throw new \RuntimeException('Purchase debit was not stored exactly');
                }
                $ledger=new Plog();
                $expected=['user_id'=>$userId,'plog_type'=>8,'plog_points'=>$points];
                $saved=$ledger->saveData($expected);
                if (($saved['code']??null)!==1) { throw new \RuntimeException('Purchase ledger failed'); }
                $stored=Db::name('Plog')->master()->where('plog_id',$ledger->getLastInsID())->find();
                foreach ($expected as $field=>$value) {
                    if (!$stored || (string)$stored[$field]!==(string)$value) { throw new \RuntimeException('Purchase ledger was not stored exactly'); }
                }
                $reward=(new User())->reward($points,$userId);
                if (($reward['code']??null)!==1) { throw new \RuntimeException('Purchase referral reward failed'); }
            }
            $saved=(new Ulog())->saveData($record);
            if (($saved['code']??null)!==1) { throw new \RuntimeException('Purchase entitlement failed'); }
            Db::commit(); $started=false;
            return ['code'=>1,'msg'=>lang('save_ok')];
        } catch (\Throwable $error) {
            if ($started) { Db::rollback(); }
            return ['code'=>2003,'msg'=>lang('index/buy_popedom2')];
        }
    }

    private static function requireTransactionalStorage(?int $resourceMid = null): void
    {
        $type=Db::connect()->getConfig('type');
        if ($type==='sqlite') { return; }
        if ($type!=='mysql') { throw new \RuntimeException('Unsupported purchase storage'); }
        $tables=[Db::name('User')->getTable(),Db::name('Plog')->getTable(),Db::name('Ulog')->getTable()];
        if ($resourceMid!==null) {
            $resource=[1=>'Vod',2=>'Art',12=>'Manga'][$resourceMid]??null;
            if ($resource===null) { throw new \RuntimeException('Unsupported purchase resource'); }
            $tables[]=Db::name($resource)->getTable(); $tables[]=Db::name('Group')->getTable();
        }
        $rows=Db::query('SELECT TABLE_NAME AS name, ENGINE AS engine FROM information_schema.TABLES '
            .'WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('.implode(',',array_fill(0,count($tables),'?')).')',$tables,true);
        foreach ($rows as $row) {
            $index=array_search($row['name'],$tables,true);
            if ($index!==false && strtoupper((string)$row['engine'])==='INNODB') { unset($tables[$index]); }
        }
        if ($tables!==[]) { throw new \RuntimeException('Purchases require transactional tables'); }
    }
}
