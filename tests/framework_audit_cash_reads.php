<?php
/** Actual ORM reads, bounded query values, immutable archive projections and primary routing. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
trait CashReadPrimaryGuard
{
    public static bool $guard = false;
    public static int $reads = 0;
    public function getPDOStatement(string $sql, array $bind = [], bool $master = false, bool $procedure = false): PDOStatement
    {
        if (self::$guard && preg_match('/\bFROM\s+[`"]?audit_(?:cash|cash_history|user)\b/i', $sql)) {
            self::$reads++;
            if (!$master) { throw new RuntimeException('Financial read routed to a replica'); }
        }
        return parent::getPDOStatement($sql, $bind, $master, $procedure);
    }
}
class CashReadSqlite extends \think\db\connector\Sqlite { use CashReadPrimaryGuard; }
class CashReadMysql extends \think\db\connector\Mysql { use CashReadPrimaryGuard; }
define('FRAMEWORK_AUDIT_CONNECTION_CLASS', getenv('FRAMEWORK_AUDIT_MYSQL') === '1' ? CashReadMysql::class : CashReadSqlite::class);
$frameworkAuditTables=['user','cash','plog'];
require __DIR__.'/fixtures/framework_audit_db.php';
use think\facade\Db;
use app\common\model\Cash;
use app\common\util\CashRead;
use app\common\util\CashArchive;
seed();$cash=new Cash();
expect($cash->saveForUser(1,['cash_money'=>'1.00','cash_bank_name'=>'Ordinary bank','cash_bank_no'=>'100%_!"+\\number','cash_payee_name'=>'Name'])['code']===1,'Read fixture must reserve real funds');
$row=Db::name('Cash')->where('user_id',1)->find();$id=(int)$row['cash_id'];
$connector=FRAMEWORK_AUDIT_CONNECTION_CLASS;$connector::$guard=true;
try {
    expect($cash->listData([],'cash_id',1,20)['total']===1,'Financial counts, rows and names must use primary reads');
    expect($cash->infoData(['cash_id'=>$id])['code']===1,'Cash detail must use a primary read');
} finally { $connector::$guard=false; }
expect($connector::$reads===4,'Primary guard must observe the actual count, list, user-name and detail statements');
expect($cash->delData(['cash_id'=>$id],['type'=>'user','id'=>1])['code']===1,'Archive projection fixture must refund once');
$archive=Db::name('CashHistory')->where('cash_id',$id)->find();
$connector::$guard=true;
try { $result=CashArchive::listData([],1,20); } finally { $connector::$guard=false; }
expect($result['code']===1&&$connector::$reads===7,'Archive count, records and user names must all route to primary');
expect($result['list'][0]['cash_status']===2&&$result['list'][0]['cash_points']===1&&$result['list'][0]['cash_money']==='1.00','Projection must retain exact amounts and final cancellation status');
expect(!isset($result['list'][0]['cash_payload'])&&!isset($result['list'][0]['cash_payload_hash']),'Projection must not expose unfiltered archive internals');
foreach(['100%_!', '&quot;', '+\\number'] as $keyword) {
    expect(CashArchive::listData([],1,20,$keyword)['total']===1,'Archive search must preserve literal wildcard, JSON escape and stored entity characters');
}
expect(CashArchive::listData([],1,20,'missing%_')['total']===0,'Archive keyword wildcards must not widen the selection');
Db::name('User')->where('user_id',1)->delete();
expect(CashArchive::listData([],1,20)['list'][0]['user_name']==='','Removed accounts must keep their historical numeric identity with an empty display name');
foreach(['cash_actor_type'=>'invalid','cash_actor_id'=>0,'cash_time_archive'=>0,'cash_status'=>0] as $field=>$value) {
    Db::name('CashHistory')->where('cash_id',$id)->update([$field=>$value]);
    expect(CashArchive::listData([],1,20)['code']!==1,'Invalid archive metadata must return a controlled error: '.$field);
    Db::name('CashHistory')->where('cash_id',$id)->update($archive);
}
foreach(['cash_points'=>65536,'cash_money'=>[],'cash_bank_no'=>[],'cash_payee_name'=>null,'cash_remarks'=>[],'cash_time_audit'=>'invalid'] as $field=>$value) {
    $payload=json_encode(array_replace($row,[$field=>$value]),JSON_THROW_ON_ERROR);
    Db::name('CashHistory')->where('cash_id',$id)->update(['cash_payload'=>$payload,'cash_payload_hash'=>hash('sha256',$payload)]);
    expect(CashArchive::listData([],1,20)['code']!==1,'Even correctly hashed malformed payload fields must not reach a template: '.$field);
    Db::name('CashHistory')->where('cash_id',$id)->update($archive);
}
foreach([[1,100,0],[10001,100,0],[1,1,1000000]] as [$page,$limit,$start]) {
    expect(CashRead::pagination($page,$limit,$start)!==null,'Permitted financial pagination boundaries must remain usable');
}
foreach([[0,20,0],[[],20,0],[true,20,0],['1.1',20,0],[1,101,0],[1,[],0],[10002,100,0],[1,1,1000001],[1,1,-1],['4294967295',100,0]] as [$page,$limit,$start]) {
    expect(CashRead::pagination($page,$limit,$start)===null,'Malformed or excessive pagination must fail before ORM arithmetic');
}
expect(CashRead::admin([],[])['limit']===20,'Invalid administrative page-size configuration must fall back to a bounded default');
finishFrameworkAudit('framework_audit_cash_reads');
