<?php
/** Seven Receive actions -> real Collect/ORM and installation DDL in disposable MySQL. */
declare(strict_types=1);
require dirname(__DIR__) . '/vendor/autoload.php';
require dirname(__DIR__) . '/vendor/topthink/framework/src/helper.php';
require dirname(__DIR__) . '/application/common.php';
error_reporting(E_ALL);
set_error_handler(static function ($level, $message, $file, $line) {
    if (!(error_reporting() & $level)) { return false; }
    throw new ErrorException($message, 0, $level, $file, $line);
});
$database = getenv('RECEIVE_COLLECT_AUDIT_DATABASE') ?: '';
if (!preg_match('/^maccms_audit_receive_[a-f0-9]+$/D', $database)
    || getenv('RECEIVE_COLLECT_AUDIT_MYSQL_SOCKET') !== '/audit/mysql.sock') {
    throw new RuntimeException('Only a dedicated disposable Receive audit database is allowed');
}
define('ENTRANCE', 'api');
define('ROOT_PATH', dirname(__DIR__) . '/');
define('MAC_PATH', '/');
define('RUNTIME_PATH', '/audit/receive-runtime-' . getmypid() . '/');
$app = new think\App('/audit/receive-app-' . getmypid() . '/');
$app->config->set(['default'=>'file','stores'=>['file'=>['type'=>'File','path'=>RUNTIME_PATH.'cache/']]], 'cache');
$app->config->set(['default'=>'file','channels'=>['file'=>['type'=>'File','path'=>RUNTIME_PATH.'log/']]], 'log');
$dbConfig = ['default'=>'audit','auto_timestamp'=>false,'connections'=>['audit'=>[
    'type'=>'mysql','socket'=>'/audit/mysql.sock','database'=>$database,'username'=>'root',
    'password'=>getenv('RECEIVE_COLLECT_AUDIT_PASSWORD'),'prefix'=>'mac_','charset'=>'utf8mb4',
    'trigger_sql'=>false,'fields_cache'=>false,'fields_strict'=>true,
]]];
$app->config->set($dbConfig, 'database');
$manager = new think\DbManager(); $manager->setConfig($dbConfig); $app->instance('think\DbManager', $manager);
$GLOBALS['config'] = include dirname(__DIR__) . '/application/data/config/maccms.example.php';
$GLOBALS['config']['app']['cache_flag'] = 'receive-collect-audit';
$GLOBALS['config']['app']['vod_search_optimise'] = '';
$GLOBALS['config']['meilisearch']['enabled'] = '0';
foreach (['vod','art','actor','role','website','manga','comment'] as $kind) {
    $GLOBALS['config']['collect'][$kind] = ['pic'=>0,'status'=>1,'hits_start'=>0,'hits_end'=>0,'updown_start'=>0,'updown_end'=>0,'score'=>0,'tag'=>0,'inrule'=>'','uprule'=>''];
}
$app->config->set($GLOBALS['config'], 'maccms');
$app->config->set([], 'vodplayer'); $app->config->set([], 'voddowner');
class ReceiveCollectAuditController extends app\api\controller\Receive {
    // Authentication is covered separately; only site-wide view/user initialization is omitted here.
    public function __construct() { $this->_param = think\facade\Request::param(); }
}
$checks = 0; $failures = [];
function receiveCollectExpect(bool $condition, string $message): void {
    global $checks, $failures; ++$checks;
    if (!$condition) { $failures[] = $message; }
}
function receiveCollectCall(string $kind, array $params, ?int $expectedCode = 1): ?array {
    $request = (new think\Request())->withGet($params)->setMethod('GET')->setController('Receive')->setAction($kind);
    think\Container::getInstance()->instance('request', $request);
    ob_start();
    try {
        (new ReceiveCollectAuditController())->$kind();
        $result = json_decode(ob_get_clean(), true, 512, JSON_THROW_ON_ERROR);
        receiveCollectExpect($expectedCode === null ? in_array($result['code'] ?? null, [1,1001], true) : ($result['code'] ?? null) === $expectedCode, $kind.' request failed: '.json_encode($result));
        return $result;
    } catch (Throwable $error) {
        if (ob_get_level() > 0) { ob_end_clean(); }
        receiveCollectExpect(false, $kind.': '.get_class($error).': '.$error->getMessage().' @ '.basename($error->getFile()).':'.$error->getLine());
        return null;
    }
}
use think\facade\Db;
$tables = ['actor','art','collect','comment','manga','role','topic','type','vod','vod_search','website'];
try {
    $sql = file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
    foreach ($tables as $table) {
        if (!preg_match('/CREATE TABLE `mac_'.preg_quote($table,'/').'` \(.*?\) ENGINE=[^;]+;/s', $sql, $match)) { throw new RuntimeException('Missing installation DDL for '.$table); }
        Db::execute($match[0]);
    }
    Db::execute("SET SESSION sql_mode='STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'");
    $types = [];
    foreach ([[10,1,'Videos'],[20,2,'Articles'],[80,8,'Actors'],[110,11,'Websites'],[120,12,'Manga']] as [$id,$mid,$name]) {
        $types[$id] = ['type_id'=>$id,'type_mid'=>$mid,'type_name'=>$name,'type_pid'=>0];
    }
    think\facade\Cache::set('receive-collect-audit_type_list', $types);
    $cases = [
        'vod'=>['vod_name'=>'Receive minimal video','type_id'=>10],
        'art'=>['art_name'=>'Receive minimal article','type_id'=>20],
        'actor'=>['actor_name'=>'Receive minimal actor','actor_sex'=>'女','type_id'=>80],
        'website'=>['website_name'=>'Receive minimal website','type_id'=>110],
        'manga'=>['manga_name'=>'Receive minimal manga','type_id'=>120],
        'role'=>['role_name'=>'Receive minimal role','role_actor'=>'Receive minimal actor','vod_name'=>'Receive minimal video'],
        'comment'=>['comment_name'=>'Receive minimal comment','comment_content'=>'Comment text','comment_mid'=>1,'rel_name'=>'Receive minimal video'],
    ];
    foreach ($cases as $kind=>$params) {
        receiveCollectCall($kind, $params);
        $row = Db::name($kind)->where($kind.'_name',$params[$kind.'_name'])->find();
        receiveCollectExpect(is_array($row), $kind.' must insert a real row from only documented required fields');
        if (!$row) { continue; }
        receiveCollectExpect((int)$row[$kind.'_status'] === 1, $kind.' must retain configured publication status');
        if (isset($params['type_id'])) { receiveCollectExpect((int)$row['type_id'] === $params['type_id'], $kind.' category must persist'); }
        if (isset($row[$kind.'_content'])) { receiveCollectExpect($row[$kind.'_content'] === ($kind === 'comment' ? 'Comment text' : ''), $kind.' optional content defaults must be valid in strict MySQL'); }
    }
    // A second record exercises real optional body fields and transport metadata filtering.
    foreach ($cases as $kind=>$params) {
        $params[$kind.'_name'] .= ' optional';
        $params['provider_meta'] = 'source-only';
        $params['transport.meta'] = 'never a qualified SQL field';
        if ($kind !== 'comment') { $params[$kind.'_content'] = '<p>Stored body</p>'; $params[$kind.'_pic'] = 'https://fixture.invalid/stored.jpg'; }
        if ($kind === 'vod') { $params['vod_isend'] = 1; }
        receiveCollectCall($kind, $params);
        $row = Db::name($kind)->where($kind.'_name',$params[$kind.'_name'])->find();
        receiveCollectExpect(is_array($row), $kind.' source metadata must not break strict SQL insertion');
        if (!$row) { continue; }
        receiveCollectExpect($row[$kind.'_content'] === ($kind === 'comment' ? 'Comment text' : '<p>Stored body</p>'), $kind.' explicitly supplied content must persist');
    }
    $app->config->set(['fixture'=>['show'=>'Fixture'],'secondary'=>['show'=>'Secondary']], 'vodplayer');
    $app->config->set(['fixture'=>['show'=>'Fixture'],'secondary'=>['show'=>'Secondary']], 'voddowner');
    $mediaFrom = 'fixture$$$secondary';
    $mediaUrl = 'Episode1$https://fixture.invalid/first.mp4$$$Episode1$https://fixture.invalid/second.mp4';
    receiveCollectCall('vod', ['vod_name'=>'Minimal playable video','type_id'=>10,'vod_play_from'=>$mediaFrom,'vod_play_url'=>$mediaUrl,'vod_down_from'=>$mediaFrom,'vod_down_url'=>$mediaUrl]);
    $playable = Db::name('vod')->where('vod_name','Minimal playable video')->find();
    receiveCollectExpect($playable && $playable['vod_play_from'] === $mediaFrom && $playable['vod_play_url'] === $mediaUrl, 'multiple configured video groups must retain URLs without optional server/note arrays');
    receiveCollectExpect($playable && $playable['vod_down_from'] === $mediaFrom && $playable['vod_down_url'] === $mediaUrl, 'multiple configured download groups must retain URLs without optional server/note arrays');
    receiveCollectCall('vod', ['vod_name'=>'Rejected media','type_id'=>10,'vod_play_from'=>'fixture','vod_play_url'=>'Episode 1$https://fixture.invalid/rejected.mp4'], 1001);
    receiveCollectExpect(Db::name('vod')->where('vod_name','Rejected media')->count() === 0, 'single-record security rejection must return a controlled error without requiring pagination metadata');
    foreach (['legacy'=>['manga_play_from','manga_play_url'],'canonical'=>['manga_chapter_from','manga_chapter_url']] as $variant=>[$fromField,$urlField]) {
        receiveCollectCall('manga', ['manga_name'=>'Readable manga '.$variant,'type_id'=>120,$fromField=>'fixture',$urlField=>'Chapter 1$https://fixture.invalid/chapter/1']);
        $readable = Db::name('manga')->where('manga_name','Readable manga '.$variant)->find();
        receiveCollectExpect($readable && $readable['manga_chapter_from'] === 'fixture' && $readable['manga_chapter_url'] === 'Chapter 1$https://fixture.invalid/chapter/1', 'manga '.$variant.' chapter fields must reach canonical database columns');
    }
    $vodId = (int)Db::name('vod')->where('vod_name','Receive minimal video')->value('vod_id');
    Db::name('vod')->where('vod_id',$vodId)->update(['vod_douban_id'=>123456]);
    receiveCollectCall('role', ['role_name'=>'Douban-only role','role_actor'=>'Actor','douban_id'=>'123456']);
    receiveCollectExpect((int)Db::name('role')->where('role_name','Douban-only role')->value('role_rid') === $vodId, 'role must resolve a douban-only relation');
    receiveCollectCall('comment', ['comment_name'=>'Douban-only comment','comment_content'=>'Douban body','comment_mid'=>1,'douban_id'=>'123456']);
    receiveCollectExpect((int)Db::name('comment')->where('comment_name','Douban-only comment')->value('comment_rid') === $vodId, 'comment must resolve a douban-only video relation');
    $topicId = Db::name('topic')->insertGetId(['topic_name'=>'Receive topic fixture','topic_content'=>'','topic_rel_vod'=>'','topic_rel_art'=>'','topic_extend'=>'']);
    foreach ([1=>['vod','Receive minimal video'],2=>['art','Receive minimal article'],3=>['topic','Receive topic fixture'],8=>['actor','Receive minimal actor'],9=>['role','Receive minimal role'],11=>['website','Receive minimal website'],12=>['manga','Receive minimal manga']] as $mid=>[$kind,$name]) {
        $id = (int)Db::name($kind)->where($kind.'_name',$name)->value($kind.'_id');
        receiveCollectCall('comment', ['comment_name'=>'Module '.$mid,'comment_content'=>'Related content','comment_mid'=>$mid,'rel_name'=>$name]);
        $row = Db::name('comment')->where('comment_name','Module '.$mid)->find();
        receiveCollectExpect($row && (int)$row['comment_mid'] === $mid && (int)$row['comment_rid'] === $id, 'comment must resolve supported module '.$mid.' to its real row');
    }
    receiveCollectCall('comment', ['comment_name'=>'Explicit relation','comment_content'=>'By ID','comment_mid'=>1,'rel_name'=>'ignored display name','rel_id'=>$vodId]);
    receiveCollectExpect((int)Db::name('comment')->where('comment_name','Explicit relation')->value('comment_rid') === $vodId, 'existing explicit relation ID must remain supported');
    $GLOBALS['config']['collect']['comment']['inrule'] = 'b,c';
    $app->config->set($GLOBALS['config'], 'maccms');
    foreach ([1=>'Receive minimal video',2=>'Receive minimal article'] as $mid=>$name) {
        receiveCollectCall('comment', ['comment_name'=>'Shared author','comment_content'=>'Shared content','comment_mid'=>$mid,'rel_name'=>$name]);
    }
    receiveCollectExpect(Db::name('comment')->where('comment_name','Shared author')->count() === 2, 'comment duplicate checks must include the content module when relation IDs collide');
    $commentCount = Db::name('comment')->count();
    foreach ([4,5,6,7,10,99] as $mid) {
        receiveCollectCall('comment', ['comment_name'=>'Unsupported module','comment_content'=>'Unsupported','comment_mid'=>$mid,'rel_name'=>'unused','rel_id'=>$vodId], 1001);
    }
    receiveCollectCall('comment', ['comment_name'=>'Missing related record','comment_content'=>'Missing','comment_mid'=>1,'rel_name'=>'unknown'], 1001);
    receiveCollectCall('comment', ['comment_name'=>'Missing explicit relation','comment_content'=>'Missing ID','comment_mid'=>1,'rel_name'=>'unused','rel_id'=>999999], 1001);
    foreach (['not-a-number','1e0','-1',str_repeat('9',40)] as $invalid) {
        receiveCollectCall('comment', ['comment_name'=>'Invalid douban relation','comment_content'=>'Invalid','comment_mid'=>1,'douban_id'=>$invalid], 1001);
        receiveCollectCall('comment', ['comment_name'=>'Invalid explicit relation','comment_content'=>'Invalid','comment_mid'=>1,'rel_name'=>'unused','rel_id'=>$invalid], 1001);
        receiveCollectCall('role', ['role_name'=>'Invalid douban role','role_actor'=>'Actor','douban_id'=>$invalid], 1001);
    }
    receiveCollectCall('comment', ['comment_name'=>'Non-video douban relation','comment_content'=>'Unsupported','comment_mid'=>2,'douban_id'=>'123456'], 1001);
    receiveCollectExpect(Db::name('comment')->count() === $commentCount, 'invalid modules and absent related records must not insert comments');
    // Once update rules are enabled, a minimal repeat must not erase existing optional content.
    foreach (['vod','art','actor','role','website','manga'] as $kind) {
        $moduleConfig = $GLOBALS['config']['collect'][$kind];
        $moduleConfig['uprule'] = 'a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w';
        $GLOBALS['config']['collect'][$kind] = $moduleConfig;
    }
    $app->config->set($GLOBALS['config'], 'maccms');
    foreach (['vod','art','actor','role','website','manga'] as $kind) {
        $params = $cases[$kind]; $params[$kind.'_name'] .= ' optional';
        $before = Db::name($kind)->where($kind.'_name',$params[$kind.'_name'])->find();
        $count = Db::name($kind)->count();
        receiveCollectCall($kind, $params, null);
        $after = Db::name($kind)->where($kind.'_name',$params[$kind.'_name'])->find();
        receiveCollectExpect($before && $after && $after[$kind.'_content'] === $before[$kind.'_content'], $kind.' minimal update must not erase content');
        receiveCollectExpect(Db::name($kind)->count() === $count, $kind.' minimal repeat must not create duplicate records');
        receiveCollectExpect($before && $after && $after[$kind.'_pic'] === $before[$kind.'_pic'], $kind.' omitted picture must not erase existing remote artwork');
        if ($kind === 'vod') { receiveCollectExpect((int)$after['vod_isend'] === 1, 'omitted completion state must not reopen a completed video'); }
    }
    receiveCollectCall('vod', ['vod_name'=>'Receive minimal video optional','type_id'=>10,'vod_isend'=>0]);
    receiveCollectExpect((int)Db::name('vod')->where('vod_name','Receive minimal video optional')->value('vod_isend') === 0, 'an explicit zero completion state remains a valid update');
    receiveCollectCall('art', ['art_name'=>'Receive minimal article optional','type_id'=>20,'art_pic'=>'']);
    receiveCollectExpect(Db::name('art')->where('art_name','Receive minimal article optional')->value('art_pic') === '', 'an explicitly empty artwork field remains distinct from an omitted field');
    if ($failures) { throw new RuntimeException(implode(PHP_EOL, $failures)); }
    echo 'framework_audit_receive_collect: '.$checks.' checks passed on PHP '.PHP_VERSION.PHP_EOL;
} finally {
    foreach (array_reverse($tables) as $table) { Db::execute('DROP TABLE IF EXISTS `mac_'.$table.'`'); }
}
