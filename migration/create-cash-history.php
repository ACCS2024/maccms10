<?php
declare(strict_types=1);
if (PHP_SAPI!=='cli') {http_response_code(404);exit;}
require __DIR__.'/lib/CashHistoryMigration.php';
try {
    $apply=false;
    foreach (array_slice($argv,1) as $argument) {
        if ($argument==='--help') {
            echo "Usage: php migration/create-cash-history.php [--apply]\nDefault is read-only preflight. Set CASH_HISTORY_SCHEMA_DSN (explicit mysql dbname),\nCASH_HISTORY_SCHEMA_USER, CASH_HISTORY_SCHEMA_PASSWORD and optional CASH_HISTORY_SCHEMA_PREFIX (mac_).\nAdds only the cash history archive table; no existing data is changed or deleted. Existing incompatible tables require manual review.\n";exit(0);
        }
        if ($argument!=='--apply')throw new InvalidArgumentException('Unknown option');
        $apply=true;
    }
    $dsn=getenv('CASH_HISTORY_SCHEMA_DSN');
    if (!is_string($dsn) || !str_starts_with($dsn,'mysql:') || !preg_match('/(?:^mysql:|;)dbname=[^;]+/',$dsn))throw new InvalidArgumentException('Set an explicit mysql CASH_HISTORY_SCHEMA_DSN with dbname');
    $pdo=new PDO($dsn,getenv('CASH_HISTORY_SCHEMA_USER')?:'',getenv('CASH_HISTORY_SCHEMA_PASSWORD')?:'',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_EMULATE_PREPARES=>false]);
    $prefix=getenv('CASH_HISTORY_SCHEMA_PREFIX');$migration=new CashHistoryMigration($pdo,$prefix===false?'mac_':$prefix);
    $report=$migration->preflight();echo json_encode($report,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";
    if ($report['blockers'])exit(1);
    if ($apply) {$report=$migration->apply();echo json_encode(['after'=>$report],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n";}
    exit($report['blockers']||($apply&&$report['changes'])?1:0);
} catch (PDOException $error) {fwrite(STDERR,"Cash history migration failed (database error); inspect the database and rerun preflight.\n");exit(1);}
catch (Throwable $error) {fwrite(STDERR,'Cash history migration failed: '.$error->getMessage()."\n");exit(1);}
