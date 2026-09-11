<?php
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_test_helpers.php';
require dirname(__DIR__).'/migration/lib/CashHistoryMigration.php';
if(getenv('PURCHASE_CSRF_MYSQL')!=='1')throw new RuntimeException('Dedicated MySQL cash archive fixture required');
$pdo=new PDO('mysql:host='.(getenv('FRAMEWORK_AUDIT_HOST')?:'127.0.0.1').';charset=utf8mb4','root',getenv('FRAMEWORK_AUDIT_PASSWORD')?:'',
    [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
$pdo->exec('CREATE DATABASE IF NOT EXISTS maccms_audit_cash_write CHARACTER SET utf8mb4');$pdo->exec('USE maccms_audit_cash_write');
$prefix='history_schema_audit_';$table=$prefix.'cash_history';$migration=new CashHistoryMigration($pdo,$prefix);
$reject=static function(callable $operation):void {try{$operation();}catch(RuntimeException|InvalidArgumentException $error){check(true,'Rejected unsafe archive schema operation');return;}check(false,'Archive schema operation must fail');};
try {
    $pdo->exec('DROP TABLE IF EXISTS `'.$table.'`');$report=$migration->preflight();
    check($report['blockers']===[]&&count($report['changes'])===1&&$report['deletes_existing_data']===false,'Preflight must propose only an additive archive table');
    $pdo->beginTransaction();$reject(fn()=>$migration->apply());check($pdo->inTransaction(),'Migration must retain caller transaction ownership');$pdo->rollBack();
    check($migration->apply()['changes']===[]&&$migration->preflight()['blockers']===[],'Applied archive schema must satisfy its contract');
    $payload=json_encode(['cash_id'=>1,'user_id'=>1,'cash_time'=>123,'cash_status'=>0,'cash_money'=>'20.00','cash_points'=>20,'cash_bank_name'=>'普通银行'],JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
    $insert=$pdo->prepare('INSERT INTO `'.$table.'` VALUES(1,1,2,123,124,\'user\',1,?,?)');$insert->execute([$payload,hash('sha256',$payload)]);
    $before=$pdo->query('SELECT * FROM `'.$table.'`')->fetchAll(PDO::FETCH_ASSOC);
    check($migration->apply()['changes']===[]&&$pdo->query('SELECT * FROM `'.$table.'`')->fetchAll(PDO::FETCH_ASSOC)===$before,'Migration replay must retain every archived byte');
    foreach(['','STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'] as $mode) {
        $pdo->exec('SET SESSION sql_mode='.$pdo->quote($mode));
        try{$insert->execute([$payload,hash('sha256',$payload)]);check(false,'Duplicate cash archive must not replace original history');}
        catch(PDOException $error){check($error->getCode()==='23000','Archive primary key must hold in both SQL modes');}
    }
    foreach(['ALTER TABLE `'.$table.'` ENGINE=MyISAM','ALTER TABLE `'.$table.'` DROP PRIMARY KEY',
        'ALTER TABLE `'.$table.'` MODIFY cash_payload VARCHAR(255) NOT NULL','ALTER TABLE `'.$table.'` ADD unknown_required INT NOT NULL'] as $sql) {
        $pdo->exec('DROP TABLE `'.$table.'`');$pdo->exec(CashHistoryMigration::ddl($prefix));$pdo->exec($sql);
        check($migration->preflight()['blockers']!==[],'Incompatible archive storage must be reviewed');$reject(fn()=>$migration->apply());
    }
    $ddl=file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
    check(preg_match('/CREATE TABLE `mac_cash_history` \([\s\S]*?\) ENGINE[^;]*;/',$ddl,$match)===1,'Installer must include cash history');
    $pdo->exec('DROP TABLE `'.$table.'`');$pdo->exec(str_replace('`mac_cash_history`','`'.$table.'`',$match[0]));
    check($migration->preflight()['changes']===[]&&$migration->preflight()['blockers']===[],'New-install and upgrade archive schemas must agree');
    $reject(fn()=>new CashHistoryMigration($pdo,'bad`prefix'));
    echo 'Cash archive schema: '.$checks.' checks passed on PHP '.PHP_VERSION." / MySQL\n";
} finally {if($pdo->inTransaction())$pdo->rollBack();$pdo->exec('DROP TABLE IF EXISTS `'.$table.'`');}
