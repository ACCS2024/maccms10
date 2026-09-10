<?php
/** Installed usage-record schema, trusted identity, immutable append and exact transactional writes. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
function lang($key, $vars = []) { return $key; }
function cookie(...$args) { throw new RuntimeException('Usage storage must never read browser identity'); }
$mysql = getenv('FRAMEWORK_AUDIT_MYSQL') === '1';
$app = new think\App(audit_temp_dir('ulog-writes'));
$temporary = $app->getRootPath();
register_shutdown_function(static function() use($temporary): void { audit_remove_temp($temporary); });
$configuration = ['default'=>'audit', 'auto_timestamp'=>false, 'connections'=>['audit'=>[
    'type'=>$mysql ? 'mysql' : 'sqlite', 'database'=>$mysql ? 'maccms_audit_models' : ':memory:',
    'hostname'=>getenv('FRAMEWORK_AUDIT_HOST') ?: '127.0.0.1', 'username'=>'root',
    'password'=>getenv('FRAMEWORK_AUDIT_PASSWORD') ?: '', 'charset'=>'utf8mb4',
    'prefix'=>'audit_ulog_write_', 'fields_cache'=>false,
]]];
$app->config->set($configuration, 'database');
$manager = new think\DbManager(); $manager->setConfig($configuration); $app->instance('think\DbManager', $manager);
if ($mysql) { think\facade\Db::execute("SET SESSION sql_mode=''"); }
$ddl = file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
foreach (['user','ulog'] as $table) {
    if (!preg_match('/CREATE TABLE `mac_'.$table.'` \(([\s\S]*?)\) ENGINE[^;]*;/', $ddl, $match)) { throw new RuntimeException('Missing installation schema'); }
    think\facade\Db::execute('DROP TABLE IF EXISTS audit_ulog_write_'.$table);
    if ($mysql) {
        think\facade\Db::execute(str_replace('`mac_'.$table.'`', '`audit_ulog_write_'.$table.'`', $match[0]));
    } else {
        $columns=[];
        foreach (explode("\n",$match[1]) as $line) {
            if (!preg_match('/^\s*`([^`]+)`\s+([^ ]+)(.*)$/', $line, $field)) { continue; }
            [$unused,$name,$type,$options]=$field;
            if (str_contains($options,'AUTO_INCREMENT')) { $columns[]=$name.' INTEGER PRIMARY KEY AUTOINCREMENT'; continue; }
            $integer=str_contains($type,'int'); $column=$name.($integer?' INTEGER':' TEXT');
            if (str_contains($options,'NOT NULL')) { $column.=' NOT NULL'; }
            if (preg_match("/DEFAULT ('[^']*'|[0-9]+)/", $options, $default)) { $column.=' DEFAULT '.$default[1]; }
            if (str_contains($options,'unsigned')) {
                $max=str_starts_with($type,'tinyint')?255:(str_starts_with($type,'smallint')?65535:(str_starts_with($type,'mediumint')?16777215:4294967295));
                $column.=' CHECK('.$name.' BETWEEN 0 AND '.$max.')';
            }
            $columns[]=$column;
        }
        think\facade\Db::execute('CREATE TABLE audit_ulog_write_'.$table.' ('.implode(',',$columns).')');
    }
}
think\facade\Db::name('User')->insertAll([
    ['user_id'=>1,'user_status'=>1,'user_name'=>'Fixture owner','user_points'=>100],
    ['user_id'=>2,'user_status'=>1,'user_name'=>'Other fixture','user_points'=>100],
    ['user_id'=>3,'user_status'=>0,'user_name'=>'Disabled fixture','user_points'=>100],
]);
$model=new app\common\model\Ulog();
function usageState(): array { return think\facade\Db::name('Ulog')->order('ulog_id')->select()->toArray(); }
$valid=['user_id'=>2,'ulog_mid'=>1,'ulog_type'=>4,'ulog_rid'=>8,'ulog_sid'=>1,'ulog_nid'=>2,'ulog_points'=>25];
$before=time();
check($model->saveData($valid+['ulog_time'=>1,'unrelated'=>'ignored'])['code']===1,'Explicit verified identity must insert without browser Cookie reads');
$row=usageState()[0];
foreach ($valid as $field=>$value) { check((int)$row[$field]===$value,'Every persisted usage field must match its validated input: '.$field); }
check((int)$row['ulog_time'] >= $before && (int)$row['ulog_time']<=time(),'Usage timestamp comes only from the server');
$stored=usageState();
foreach ([null,false,1,'data',new stdClass(),[]] as $bad) {
    check($model->saveData($bad)['code']>1 && usageState()===$stored,'Malformed containers and incomplete data cannot write');
}
foreach (array_keys($valid) as $field) {
    foreach ([null,[],new stdClass(),true,1.0,'1e1','-1','1.5','4294967296'] as $bad) {
        check($model->saveData(array_replace($valid,[$field=>$bad]))['code']>1 && usageState()===$stored,'Malformed '.$field.' cannot be coerced or saved');
    }
}
foreach ([['user_id'=>0],['user_id'=>3],['user_id'=>400],['ulog_mid'=>4],['ulog_type'=>0],['ulog_mid'=>1,'ulog_type'=>1],
    ['ulog_mid'=>2,'ulog_type'=>4],['ulog_mid'=>12,'ulog_type'=>5],['ulog_mid'=>3,'ulog_type'=>1],['ulog_mid'=>8,'ulog_type'=>5],
    ['ulog_rid'=>0],['ulog_sid'=>256],['ulog_nid'=>65536],['ulog_points'=>65536],['ulog_id'=>0],['ulog_id'=>$row['ulog_id']]] as $bad) {
    check($model->saveData(array_replace($valid,$bad))['code']>1 && usageState()===$stored,'Invalid identities, model operations, narrow fields and updates must leave receipts unchanged');
}
foreach ([1=>[2,3,4,5],2=>[1,2,3],3=>[2,3],8=>[2,3],12=>[1,2,3]] as $mid=>$types) {
    foreach ($types as $type) {
        check($model->saveData(['user_id'=>'1','ulog_mid'=>(string)$mid,'ulog_type'=>(string)$type,'ulog_rid'=>'1'])['code']===1,
            'Supported free activity types retain zero coordinate and price defaults');
    }
}
$max=['ulog_sid'=>255,'ulog_nid'=>65535,'ulog_points'=>65535,'ulog_rid'=>4294967295];
check($model->saveData(array_replace($valid,$max))['code']===1,'Largest installed coordinate, price and resource identifiers remain exact');
$stored=usageState();
think\facade\Db::startTrans();
think\facade\Db::name('User')->where('user_id',2)->setDec('user_points',25);
check($model->saveData($valid)['code']===1,'Append can participate in the caller purchase transaction');
think\facade\Db::rollback();
check(usageState()===$stored && (int)think\facade\Db::name('User')->where('user_id',2)->value('user_points')===100,
    'Outer rollback reverses both the balance change and nested usage record');
if ($mysql) {
    think\facade\Db::execute('ALTER TABLE audit_ulog_write_ulog MODIFY ulog_points TINYINT UNSIGNED NOT NULL DEFAULT 0');
    $stored=usageState(); // ALTER may clip the prior maximum fixture; assertions concern the next insert only.
    check($model->saveData(array_replace($valid,['ulog_points'=>300]))['code']>1 && usageState()===$stored,
        'Legacy narrower non-strict storage must roll back a silently clipped successful insert');
    think\facade\Db::execute('ALTER TABLE audit_ulog_write_ulog ENGINE=MyISAM');
    check($model->saveData($valid)['code']>1 && usageState()===$stored,'Nontransactional usage storage must fail before inserting');
    think\facade\Db::execute('ALTER TABLE audit_ulog_write_ulog ENGINE=InnoDB');
} else {
    think\facade\Db::execute('CREATE TRIGGER audit_usage_clipping AFTER INSERT ON audit_ulog_write_ulog BEGIN UPDATE audit_ulog_write_ulog SET ulog_points=1 WHERE ulog_id=NEW.ulog_id; END');
    check($model->saveData($valid)['code']>1 && usageState()===$stored,'Changed stored values must roll back the complete insert');
    think\facade\Db::execute('DROP TRIGGER audit_usage_clipping');
}
$body=$mysql?"FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='Isolated usage failure'":"BEGIN SELECT RAISE(ABORT, 'Isolated usage failure'); END";
think\facade\Db::execute('CREATE TRIGGER audit_usage_failure BEFORE INSERT ON audit_ulog_write_ulog '.$body);
check($model->saveData($valid)['code']>1 && usageState()===$stored,'A storage exception returns a controlled failure without partial writes');
think\facade\Db::execute('DROP TRIGGER audit_usage_failure');
check($model->saveData($valid)['code']===1,'The same valid write works after a transient storage fault is removed');
printf("Usage write audit: %d checks passed on PHP %s (%s).\n",$checks,PHP_VERSION,$mysql?'MySQL non-strict':'SQLite');
