<?php
/** Real ORM writer/reader routing and a caller-owned raw PDO transaction in dedicated fixture databases. */
use think\facade\Db;

purchaseCsrfSeed();$originalManager=think\Container::getInstance()->make('think\\DbManager');$writer=Db::connect();
$writer->execute('CREATE DATABASE IF NOT EXISTS maccms_audit_purchase_csrf_read CHARACTER SET utf8mb4');
foreach(['user','group','art','plog','ulog']as $table){
    $writer->execute('DROP TABLE IF EXISTS maccms_audit_purchase_csrf_read.audit_'.$table);
    $writer->execute('CREATE TABLE maccms_audit_purchase_csrf_read.audit_'.$table.' LIKE maccms_audit_purchase_csrf.audit_'.$table);
    $writer->execute('INSERT INTO maccms_audit_purchase_csrf_read.audit_'.$table.' SELECT * FROM maccms_audit_purchase_csrf.audit_'.$table);
}
$identity=$writer->name('User')->where('user_id',1)->find();
$split=$configuration;$host=$connection['hostname'];
$split['connections']['audit']=array_replace($connection,[
    'deploy'=>1,'rw_separate'=>true,'master_num'=>1,'slave_no'=>1,'hostname'=>$host.','.$host,
    'database'=>'maccms_audit_purchase_csrf,maccms_audit_purchase_csrf_read',
]);
$splitManager=new think\DbManager();$splitManager->setConfig($split);
$writes=0;$splitManager->listen(static function($sql)use(&$writes):void{if(preg_match('/^\s*(UPDATE|INSERT|DELETE)\b/i',$sql))$writes++;});
think\Container::getInstance()->instance('think\\DbManager',$splitManager);
$masterPdo=null;
try{
    $routed=Db::connect();
    check($routed->query('SELECT DATABASE() AS db',[],true)[0]['db']==='maccms_audit_purchase_csrf'
        &&$routed->query('SELECT DATABASE() AS db',[],false)[0]['db']==='maccms_audit_purchase_csrf_read',
        'The article fixture must actually switch between distinct writer and reader databases');
    $routed->query('SELECT 1',[],true);$masterPdo=$routed->getPdo();$masterPdo->beginTransaction();
    $masterPdo->exec('UPDATE audit_user SET user_points=99 WHERE user_id=1');
    $routed->query('SELECT 1',[],false);
    check($routed->getPdo()!==$masterPdo&&!$routed->getPdo()->inTransaction()&&$masterPdo->inTransaction(),
        'The current ORM PDO is a reader while its separate writer retains a real raw transaction');
    $called=0;$writes=0;
    $result=\app\common\util\ContentPurchase::buyArt(1,static function($user)use(&$called):array{$called++;return ['code'=>1,'msg'=>'unused'];});
    check($result['code']===2003&&$called===0&&$writes===0&&$masterPdo->inTransaction()
        &&(int)$masterPdo->query('SELECT user_points FROM audit_user WHERE user_id=1')->fetchColumn()===99
        &&(int)$writer->name('User')->where('user_id',1)->value('user_points')===100
        &&$writer->name('Plog')->count()===0&&$writer->name('Ulog')->count()===0,
        'A hidden writer transaction must be rejected before the quote without ending or committing caller changes');
    $masterPdo->rollBack();$masterPdo=null;
    check((int)$writer->name('User')->where('user_id',1)->value('user_points')===100,
        'The caller can roll back its preserved transaction after the purchase rejection');
    $access=static function(array $row,array $coordinates):array{
        $controller=(new ReflectionClass(PurchaseCsrfIndex::class))->newInstanceWithoutConstructor();
        return(new ReflectionMethod($controller,'check_art_resource_access'))->invoke($controller,$row,$coordinates);
    };
    $result=\app\common\util\ArtPurchase::buy($identity,artPurchaseBody(),$access);
    check($result['code']===1&&(int)$writer->name('User')->where('user_id',1)->value('user_points')===80
        &&$writer->name('Ulog')->count()===1&&$routed->query('SELECT COUNT(*) AS count FROM audit_ulog',[],false)[0]['count']===0,
        'A normal article purchase uses the writer even while the reader has no current purchase receipt');
    $result=\app\common\util\ArtPurchase::buy($identity,artPurchaseBody(),$access);
    check($result['code']===1&&(int)$writer->name('User')->where('user_id',1)->value('user_points')===80&&$writer->name('Ulog')->count()===1,
        'A repeated article purchase finds its current writer receipt despite reader lag');
}finally{
    if($masterPdo&&$masterPdo->inTransaction())$masterPdo->rollBack();
    think\Container::getInstance()->instance('think\\DbManager',$originalManager);
    $writer->execute('DROP DATABASE maccms_audit_purchase_csrf_read');
}
