<?php
/** Actual MySQL DDL/CLI in the dedicated financial fixture; no business database selected. */
if (getenv('MEMBERSHIP_AUDIT_MYSQL') !== '1') { echo "SKIP ledger schema: requires isolated MySQL\n"; exit(0); }
require __DIR__.'/fixtures/security_audit_membership_db.php';
require dirname(__DIR__).'/migration/lib/LedgerVisibilityMigration.php';
use think\facade\Db;
$dsn='mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST')?:'127.0.0.1').';dbname=maccms_audit_membership;charset=utf8mb4';
$pdo=new PDO($dsn,'root',getenv('MEMBERSHIP_AUDIT_PASSWORD')?:'',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
$migration=new LedgerVisibilityMigration($pdo,'audit_');
$environment=['LEDGER_SCHEMA_DSN'=>$dsn,'LEDGER_SCHEMA_USER'=>'root','LEDGER_SCHEMA_PASSWORD'=>getenv('MEMBERSHIP_AUDIT_PASSWORD')?:'','LEDGER_SCHEMA_PREFIX'=>'audit_'];
function ledgerCli(array $args,array $env): array {
    $process=proc_open([PHP_BINARY,dirname(__DIR__).'/migration/preserve-ledger-records.php',...$args],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,null,$env);
    if(!is_resource($process)){throw new RuntimeException('Cannot start migration CLI');}
    fclose($pipes[0]);$out=stream_get_contents($pipes[1]);fclose($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[2]);
    return [proc_close($process),$out,$err];
}
function ledgerRows(PDO $pdo): array {return $pdo->query('SELECT plog_id,user_id,plog_type,plog_points,plog_time,plog_remarks FROM audit_plog ORDER BY plog_id')->fetchAll(PDO::FETCH_ASSOC);}
membershipSeed();
Db::name('Plog')->insert(['plog_id'=>1,'user_id'=>1,'plog_type'=>1,'plog_points'=>123,'plog_time'=>1700000000,'plog_remarks'=>'fixture original']);
$originals=ledgerRows($pdo);
check($migration->preflight()['changes']===[] && $migration->preflight()['blockers']===[],'New installation requires visibility migration');
$pdo->exec('ALTER TABLE audit_plog DROP INDEX user_visibility, DROP COLUMN plog_user_hidden');
$schema=$pdo->query('SHOW CREATE TABLE audit_plog')->fetch(PDO::FETCH_NUM)[1];
$pdo->exec('START TRANSACTION READ ONLY');$report=$migration->preflight();
check($pdo->inTransaction(),'Preflight implicitly committed read-only transaction');$pdo->rollBack();
check(array_column($report['changes'],'id')===['ledger_user_visibility'] && $report['blockers']===[],'Legacy schema did not produce exactly one visibility plan');
check($pdo->query('SHOW CREATE TABLE audit_plog')->fetch(PDO::FETCH_NUM)[1]===$schema && ledgerRows($pdo)===$originals,'Preflight mutated schema/history');
[$status,$output,$error]=ledgerCli([],$environment);
check($status===0 && $error==='' && count(json_decode($output,true,512,JSON_THROW_ON_ERROR)['changes'])===1,'Default CLI did not return a read-only plan');
check($pdo->query('SHOW CREATE TABLE audit_plog')->fetch(PDO::FETCH_NUM)[1]===$schema,'Default CLI executed DDL');
[$status,$output]=ledgerCli(['--help'],[]);check($status===0 && str_contains($output,'read-only preflight'),'Help selected a database');
[$status]=ledgerCli([],[]);check($status===1,'CLI silently selected credentials/database');
[$status]=ledgerCli(['--unknown'],$environment);check($status===1,'Unknown option silently continued');
foreach(['../','bad-prefix','`x`',str_repeat('a',59)] as $prefix){$thrown=false;try{new LedgerVisibilityMigration($pdo,$prefix);}catch(InvalidArgumentException $e){$thrown=true;}check($thrown,'Unsafe prefix accepted');}
// An existing conflicting index is a manual-review blocker, never overwritten.
$pdo->exec('ALTER TABLE audit_plog ADD INDEX user_visibility (plog_id)');
check(in_array('visibility_index_name_requires_manual_review',$migration->preflight()['blockers'],true),'Conflicting index silently replaced');
$blocked=false;try{$migration->apply();}catch(RuntimeException $e){$blocked=true;}
check($blocked && ledgerRows($pdo)===$originals,'Apply ignored a fresh preflight blocker');
$pdo->exec('ALTER TABLE audit_plog DROP INDEX user_visibility');
[$status,$output,$error]=ledgerCli(['--apply'],$environment);
check($status===0 && $error==='' && $migration->preflight()['changes']===[],'Explicit migration failed');
check(ledgerRows($pdo)===$originals && $pdo->query('SELECT plog_user_hidden FROM audit_plog')->fetchColumn()===0,'Migration changed history or hid existing rows');
check($migration->apply()['changes']===[] && ledgerRows($pdo)===$originals,'Repeated apply was not idempotent');
$pdo->exec('UPDATE audit_plog SET plog_user_hidden=2');
check(in_array('invalid_visibility_values_require_manual_review',$migration->preflight()['blockers'],true),'Invalid hidden values were silently normalized');
$blocked=false;try{$migration->apply();}catch(RuntimeException $e){$blocked=true;}
check($blocked && $pdo->query('SELECT plog_user_hidden FROM audit_plog')->fetchColumn()===2,'Apply altered unexpected visibility values');
$pdo->exec('UPDATE audit_plog SET plog_user_hidden=0');
$pdo->exec('ALTER TABLE audit_plog MODIFY plog_user_hidden TINYINT NOT NULL DEFAULT 0');
check(in_array('visibility_column_requires_manual_review',$migration->preflight()['blockers'],true),'Conflicting column type silently changed');
$pdo->exec('ALTER TABLE audit_plog MODIFY plog_user_hidden TINYINT UNSIGNED NOT NULL DEFAULT 0');
$pdo->exec('ALTER TABLE audit_plog ENGINE=MyISAM');
check(in_array('ledger_table_missing_or_not_innodb',$migration->preflight()['blockers'],true),'Nontransactional ledger accepted');
$pdo->exec('ALTER TABLE audit_plog ENGINE=InnoDB');
check($migration->preflight()['changes']===[] && $migration->preflight()['blockers']===[] && ledgerRows($pdo)===$originals,'Final fixture/history differs');
echo "Ledger schema: $checks checks passed on PHP ".PHP_VERSION." / MySQL\n";
