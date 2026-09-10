<?php
/** Dedicated card tables and retained original PDO; uses the shared real transaction fault connector. */
declare(strict_types=1);
require dirname(__DIR__,2).'/vendor/autoload.php';
require __DIR__.'/purchase_owner_faults.php';
$cardMysql=getenv('MEMBERSHIP_AUDIT_MYSQL')==='1';
$cardTemporary=sys_get_temp_dir().'/maccms-card-owner-'.bin2hex(random_bytes(12));
if(!mkdir($cardTemporary,0700)){throw new RuntimeException('Cannot create card fixture directory');}
define('MEMBERSHIP_AUDIT_CONNECTION_CLASS',$cardMysql?PurchaseOwnerMysql::class:PurchaseOwnerSqlite::class);
define('MEMBERSHIP_AUDIT_DATABASE',$cardMysql?'maccms_audit_card_owner':$cardTemporary.'/card.sqlite');
if($cardMysql){
    $server=new PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST')?:'127.0.0.1').';charset=utf8mb4','root',getenv('MEMBERSHIP_AUDIT_PASSWORD')?:'');
    $server->exec('CREATE DATABASE IF NOT EXISTS maccms_audit_card_owner CHARACTER SET utf8mb4');
}
require __DIR__.'/security_audit_card_db.php';
register_shutdown_function(static fn()=>audit_remove_temp($cardTemporary));
function cardOwnerSeed(int $balance=100,int $points=20):void {
    think\Container::getInstance()->instance('request',new think\Request());
    PurchaseOwnerFault::reset();cardSeed($balance,$points);
}
function cardOwnerRun():array {return (new app\common\model\Card())->useData('fixture-card','fixture',['user_id'=>1]);}
