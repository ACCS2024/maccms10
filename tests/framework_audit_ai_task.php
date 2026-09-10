<?php
/** Real plugin lifecycle/model, configured-prefix and decoy tables; no provider requests. */
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use think\facade\Db;
use addons\aicontent\model\AiTask;

function lang($key, $vars = []) { return $key; }
$temporary = audit_temp_dir('ai-task');
register_shutdown_function(static function () use ($temporary): void { audit_remove_temp($temporary); });
if (!defined('DS')) { define('DS', DIRECTORY_SEPARATOR); }
define('ROOT_PATH', $temporary.'/');
define('APP_PATH', $temporary.'/application/');
define('ADDON_PATH', $temporary.'/addons/');
define('RUNTIME_PATH', $temporary.'/runtime/');
mkdir(ADDON_PATH.'aicontent', 0700, true);
require dirname(__DIR__).'/vendor/autoload.php';
$mysql = getenv('FRAMEWORK_AUDIT_MYSQL') === '1';
$prefix = ($argv[1] ?? '') === 'default-prefix' ? 'mac_' : 'audit_ai_';
$table = $prefix.'ai_task';
$decoy = $prefix === 'mac_' ? 'audit_ai_ai_task' : 'mac_ai_task';
$app = new think\App($temporary.'/');
$configuration = ['default'=>'audit', 'auto_timestamp'=>false, 'connections'=>['audit'=>[
    'type'=>$mysql ? 'mysql' : 'sqlite', 'database'=>$mysql ? 'maccms_audit_models' : ':memory:',
    'hostname'=>getenv('FRAMEWORK_AUDIT_HOST') ?: '127.0.0.1', 'username'=>'root',
    'password'=>getenv('FRAMEWORK_AUDIT_PASSWORD') ?: '', 'prefix'=>$prefix,
    'charset'=>'utf8mb4', 'trigger_sql'=>false, 'fields_cache'=>false,
]]];
$app->config->set($configuration, 'database');
$manager = new think\DbManager(); $manager->setConfig($configuration); $app->instance('think\DbManager', $manager);
$source = file_get_contents(dirname(__DIR__).'/addons/aicontent/install.sql');
if (!$mysql) {
    // SQLite uses the same columns and defaults; MySQL executes the unmodified installation DDL.
    $source = preg_replace('/`id`\s+int\(11\) NOT NULL AUTO_INCREMENT,/', '`id` INTEGER PRIMARY KEY AUTOINCREMENT,', $source);
    $source = preg_replace('/\s+COMMENT\s+\x27[^\x27]*\x27/', '', $source);
    $source = preg_replace('/,\s*PRIMARY KEY \(`id`\),[\s\S]*?\) ENGINE[\s\S]*$/', "\n);", $source);
}
file_put_contents(ADDON_PATH.'aicontent/install.sql', $source);
$plugin = new addons\aicontent\Aicontent();
foreach ([$table, $decoy] as $name) { Db::execute('DROP TABLE IF EXISTS `'.$name.'`'); }
try {
    Db::execute('CREATE TABLE `'.$decoy.'` (id INTEGER PRIMARY KEY, marker VARCHAR(30))');
    Db::table($decoy)->insert(['id'=>987, 'marker'=>'other-site-history']);
    check($plugin->install(), 'Plugin installation must create the configured table');
    check((new AiTask())->getTable() === $table, 'The model must resolve the active connection prefix');
    check(AiTask::getHistory() === ['total'=>0,'list'=>[]], 'An empty real task history must remain an array');
    $task = AiTask::createTask('video', 42, 'Fixture title', 'fixture-provider', 'fixture-model');
    $id = $task->id;
    $row = Db::table($table)->find($id);
    check($id > 0 && $row['content_name'] === 'Fixture title' && $row['model'] === 'fixture-model'
        && $row['provider'] === 'fixture-provider' && (int)$row['status'] === 0, 'Create must persist the real ORM fields in the configured table');
    check($task->status_label === 'Pending', 'The mapped pending status must reach its accessor');
    $task->markDone('{"description":"normal content"}');
    $stored = AiTask::find($id);
    check((int)$stored->status === 1 && $stored->result === '{"description":"normal content"}'
        && $stored->error_msg === null && $stored->updated_at !== null, 'Completion must persist mapped status/result/error/time fields');
    check($stored->status_label === 'Done', 'Completion must reach the status accessor');
    $task->markError(str_repeat('错', 510));
    $stored = AiTask::find($id);
    check((int)$stored->status === 2 && mb_strlen($stored->error_msg) === 499
        && $stored->status_label === 'Error', 'Error updates must preserve UTF-8 and bounded error storage');
    $second = AiTask::createTask('article', 43, 'Second title', 'fixture-provider', 'fixture-model');
    $history = AiTask::getHistory(1,1);
    check($history['total'] === 2 && count($history['list']) === 1 && (int)$history['list'][0]['id'] === (int)$second->id,
        'Task history must use the configured table and newest-first page');
    check((int)AiTask::where('status', AiTask::STATUS_ERROR)->count() === 1, 'Dashboard status totals must use the same table');
    check($plugin->install() && (int)AiTask::count() === 2, 'Repeated installation must preserve current task history');
    check(Db::table($decoy)->select()->toArray() === [['id'=>987,'marker'=>'other-site-history']], 'Installation and normal writes must leave the other prefix untouched');
    check($plugin->uninstall(), 'Explicit uninstall must drop only the active table');
    if ($mysql) {
        $exists = Db::query('SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=?', [$table]);
    } else {
        $exists = Db::query("SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table' AND name=?", [$table]);
    }
    check((int)$exists[0]['n'] === 0, 'The selected table must actually be removed');
    check(Db::table($decoy)->select()->toArray() === [['id'=>987,'marker'=>'other-site-history']], 'Uninstall must preserve another site task table');
    unlink(ADDON_PATH.'aicontent/install.sql');
    try { $plugin->install(); throw new LogicException('Missing installation DDL reported success'); }
    catch (RuntimeException $error) { check(str_contains($error->getMessage(), 'schema'), 'Missing DDL must fail explicitly'); }
    echo 'AI task prefix/lifecycle: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($mysql?'MySQL':'SQLite').' / '.$prefix.PHP_EOL;
} finally {
    foreach ([$table,$decoy] as $name) { Db::execute('DROP TABLE IF EXISTS `'.$name.'`'); }
}
