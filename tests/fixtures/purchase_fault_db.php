<?php
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
require __DIR__.'/purchase_owner_faults.php';
$ownerMysql = getenv('MEMBERSHIP_AUDIT_MYSQL') === '1';
$ownerTemporary = sys_get_temp_dir().'/maccms-purchase-owner-'.bin2hex(random_bytes(12));
if (!mkdir($ownerTemporary,0700)) { throw new RuntimeException('Cannot create owner fixture directory'); }
define('MEMBERSHIP_AUDIT_CONNECTION_CLASS', $ownerMysql ? PurchaseOwnerMysql::class : PurchaseOwnerSqlite::class);
define('MEMBERSHIP_AUDIT_DATABASE', $ownerMysql ? 'maccms_audit_owner_purchase' : $ownerTemporary.'/owner.sqlite');
if ($ownerMysql) {
    $server = new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST') ?: '127.0.0.1').';charset=utf8mb4',
        'root', getenv('MEMBERSHIP_AUDIT_PASSWORD') ?: '', [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
    $server->exec('CREATE DATABASE IF NOT EXISTS maccms_audit_owner_purchase CHARACTER SET utf8mb4');
    $server = null;
}
require __DIR__.'/security_audit_membership_db.php';
register_shutdown_function(static fn()=>audit_remove_temp($ownerTemporary));
use think\facade\Db;
use app\common\util\ContentPurchase;
use app\common\util\PurchaseTransaction;
if ($mysql) {
    Db::execute("SET SESSION sql_mode=''");
    $ddl=file_get_contents(dirname(__DIR__,2).'/application/install/sql/install.sql');
    foreach (['ulog','vod'] as $table) {
        if (!preg_match('/CREATE TABLE `mac_'.$table.'` \([\s\S]*?\) ENGINE[^;]*;/', $ddl, $match)) {
            throw new RuntimeException('Owner fixture installation schema missing');
        }
        Db::execute('DROP TABLE IF EXISTS audit_'.$table);
        Db::execute(str_replace('`mac_'.$table.'`','`audit_'.$table.'`',$match[0]));
    }
} else {
    Db::execute('ALTER TABLE audit_user ADD COLUMN user_status INTEGER NOT NULL DEFAULT 1');
    Db::execute('CREATE TABLE audit_ulog (ulog_id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,ulog_mid INTEGER,ulog_type INTEGER,ulog_rid INTEGER,ulog_sid INTEGER,ulog_nid INTEGER,ulog_points INTEGER,ulog_time INTEGER)');
}
function ownerRequest():void{think\Container::getInstance()->instance('request',new think\Request());}
function ownerSeed(int $balance=100):void{
    ownerRequest();PurchaseOwnerFault::reset();membershipSeed($balance);Db::execute('DELETE FROM audit_ulog');
    Db::name('User')->where('user_id','>',0)->update(['user_status'=>1]);
}
function ownerState():array{return [membershipState(),Db::name('Ulog')->order('ulog_id')->select()->toArray()];}
function ownerQuote(array $user):array{return ['code'=>1,'record'=>['ulog_mid'=>1,'ulog_type'=>4,'ulog_rid'=>7,'ulog_sid'=>1,'ulog_nid'=>2,'ulog_points'=>20]];}
function ownerBuy():array{return ContentPurchase::buyVideo(1,'ownerQuote');}
