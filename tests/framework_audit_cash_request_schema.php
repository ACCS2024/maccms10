<?php
/** Explicit additive MySQL receipt migration; never bootstraps the application or uses its credentials. */
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_test_helpers.php';
require dirname(__DIR__).'/migration/lib/CashRequestMigration.php';
if(getenv('PURCHASE_CSRF_MYSQL')!=='1')throw new RuntimeException('Dedicated cash schema MySQL fixture required');
$pdo=new PDO('mysql:host='.(getenv('FRAMEWORK_AUDIT_HOST')?:'127.0.0.1').';charset=utf8mb4','root',getenv('FRAMEWORK_AUDIT_PASSWORD')?:'',
    [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
$pdo->exec('CREATE DATABASE IF NOT EXISTS maccms_audit_cash_write CHARACTER SET utf8mb4');$pdo->exec('USE maccms_audit_cash_write');
$prefix='receipt_schema_audit_';$table=$prefix.'cash_request';$migration=new CashRequestMigration($pdo,$prefix);
$reject=static function(callable $call):void {try{$call();}catch(RuntimeException|InvalidArgumentException $error){check(true,'Rejected incompatible receipt schema');return;}check(false,'Schema operation should have been rejected');};
try {
    $pdo->exec('DROP TABLE IF EXISTS `'.$table.'`');
    $report=$migration->preflight();check($report['blockers']===[]&&count($report['changes'])===1&&$report['deletes_existing_data']===false,'Read-only preflight must propose only a new receipt table');
    $pdo->beginTransaction();$reject(fn()=>$migration->apply());check($pdo->inTransaction(),'Migration must not implicitly commit a caller transaction');$pdo->rollBack();
    check($migration->apply()['changes']===[]&&$migration->preflight()['blockers']===[],'Applied receipt table must match the migration contract');
    $insert=$pdo->prepare('INSERT INTO `'.$table.'` VALUES(1,?,?,17,123)');$insert->execute([str_repeat('a',64),str_repeat('b',64)]);
    $before=$pdo->query('SELECT * FROM `'.$table.'`')->fetchAll(PDO::FETCH_ASSOC);
    check($migration->apply()['changes']===[]&&$pdo->query('SELECT * FROM `'.$table.'`')->fetchAll(PDO::FETCH_ASSOC)===$before,'Idempotent migration must preserve financial receipts');
    foreach(['','STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'] as $mode) {
        $pdo->exec('SET SESSION sql_mode='.$pdo->quote($mode));
        try{$insert->execute([str_repeat('a',64),str_repeat('c',64)]);check(false,'Duplicate owner request must fail');}
        catch(PDOException $error){check($error->getCode()==='23000','Unique receipt constraint must hold in strict and non-strict SQL');}
    }
    foreach(['ALTER TABLE `'.$table.'` ENGINE=MyISAM',
        'ALTER TABLE `'.$table.'` DROP PRIMARY KEY',
        'ALTER TABLE `'.$table.'` MODIFY request_id CHAR(32) NOT NULL'] as $change) {
        $pdo->exec('DROP TABLE `'.$table.'`');$pdo->exec(CashRequestMigration::ddl($prefix));$pdo->exec($change);
        check($migration->preflight()['blockers']!==[],'Incompatible engine, primary key or key capacity requires review');$reject(fn()=>$migration->apply());
    }
    $ddl=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
    check(preg_match('/CREATE TABLE `mac_cash_request` \([\s\S]*?\) ENGINE[^;]*;/',$ddl,$match)===1,'Fresh installation must declare the durable receipt table');
    $pdo->exec('DROP TABLE `'.$table.'`');$pdo->exec(str_replace('`mac_cash_request`','`'.$table.'`',$match[0]));
    check($migration->preflight()['blockers']===[]&&$migration->preflight()['changes']===[],'Install and upgrade schemas must agree');
    $reject(fn()=>new CashRequestMigration($pdo,'bad`prefix'));
    echo 'Cash request schema: '.$checks.' checks passed on PHP '.PHP_VERSION." / MySQL\n";
} finally {if($pdo->inTransaction())$pdo->rollBack();$pdo->exec('DROP TABLE IF EXISTS `'.$table.'`');}
