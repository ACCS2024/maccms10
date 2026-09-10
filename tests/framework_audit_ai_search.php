<?php
/** Normal content records, real install DDL/ORM/Meili service; no external transport or application bootstrap. */
declare(strict_types=1);
namespace app\common\util {
    class MeilisearchHttp {
        public static array $ids = [10,20,30,40,50];
        public static string $mode = 'ok';
        public static array $calls = [];
        public static function requestParallel($host, $jobs, ...$arguments): array {
            if ($host !== 'https://fixture.invalid') { throw new \RuntimeException('Fixture transport only'); }
            $results = [];
            foreach ($jobs as $job) {
                self::$calls[] = $job;
                preg_match('/kind = "(vod|art|manga|topic|actor|role|website)"/', $job['body']['filter'], $match);
                if (!isset($match[1])) { throw new \RuntimeException('Unexpected resource module'); }
                if (self::$mode === 'unavailable') { $results[] = ['ok'=>false,'status'=>503]; continue; }
                $ids = self::$mode === 'empty' ? [] : array_slice(self::$ids, $job['body']['offset'], $job['body']['limit']);
                $results[] = ['ok'=>true,'status'=>200,'data'=>['hits'=>array_map(static fn($id)=>['id'=>$match[1].'_'.$id],$ids),'estimatedTotalHits'=>count(self::$ids)]];
            }
            return $results;
        }
    }
    // URL builders are unchanged by this batch; fixture links identify which real row/module reached them.
    function mac_url_vod_detail($row) { return '/fixture/vod/'.$row['vod_id']; }
    function mac_url_art_detail($row) { return '/fixture/art/'.$row['art_id']; }
    function mac_url_manga_detail($row) { return '/fixture/manga/'.$row['manga_id']; }
    function mac_url_topic_detail($row) { return '/fixture/topic/'.$row['topic_id']; }
    function mac_url_actor_detail($row) { return '/fixture/actor/'.$row['actor_id']; }
    function mac_url_role_detail($row) { return '/fixture/role/'.$row['role_id']; }
    function mac_url_website_detail($row) { return '/fixture/website/'.$row['website_id']; }
}
namespace {
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\AiSearch;
use app\common\util\MeilisearchHttp as Transport;
use app\common\util\MeilisearchService;
use think\facade\Db;
function config($key, $default = null) { return think\facade\Config::get($key,$default); }
$socket = getenv('DATABASE_AUDIT_MYSQL_SOCKET'); $database = getenv('DATABASE_AUDIT_DATABASE');
if ($socket !== '/audit/mysql.sock' || !is_string($database) || !preg_match('/^maccms_audit_ai_search_[a-f0-9]+$/D',$database)) { throw new RuntimeException('Isolated AI-search database required'); }
$temp = audit_temp_dir('ai-search'); $app = new think\App($temp);
$cfg = ['default'=>'fixture','auto_timestamp'=>false,'connections'=>['fixture'=>[
    'type'=>'mysql','dsn'=>'mysql:unix_socket='.$socket.';dbname='.$database.';charset=utf8mb4','database'=>$database,
    'username'=>'root','password'=>getenv('DATABASE_AUDIT_PASSWORD'),'prefix'=>'audit_ai_','charset'=>'utf8mb4','trigger_sql'=>true,'fields_cache'=>false,
]]];
$app->config->set($cfg,'database'); $originalManager = new think\DbManager(); $originalManager->setConfig($cfg); $app->instance('think\DbManager',$originalManager);
$kinds = ['vod','art','manga','topic','actor','role','website']; $modules = [...$kinds,'plot'];
$ai = ['enabled'=>'1','provider'=>'disabled','api_key'=>'','min_query_len'=>'1','internal_result_limit'=>'8','module'=>array_fill_keys($modules,'1')];
$app->config->set(['ai_search'=>$ai],'maccms');
$GLOBALS['config'] = ['meilisearch'=>['enabled'=>'0','host'=>'https://fixture.invalid','index_uid'=>'ai-search-fixture']];
$sql = []; Db::listen(static function($statement) use (&$sql): void { $sql[] = $statement; });
$sourceKind = static fn(string $module): string => $module === 'plot' ? 'vod' : $module;
$payloadIds = static fn(array $payload): array => array_map(static fn($row)=>(int)basename($row['url']),$payload['internal_resources']);
$clear = static function(): void {
    (new ReflectionProperty(AiSearch::class,'buildForSearchMemo'))->setValue(null,[]);
    (new ReflectionProperty(MeilisearchService::class,'searchMemo'))->setValue(null,[]);
    Transport::$ids = [10,20,30,40,50]; Transport::$mode = 'ok'; Transport::$calls = [];
};
$build = static function(string $module, bool $meili, string $mode='ok', string $word='Ordinary'): array {
    $GLOBALS['config']['meilisearch']['enabled'] = $meili ? '1' : '0'; Transport::$mode = $mode;
    return AiSearch::buildForSearch($module,['wd'=>$word]);
};
$defaults = [];
try {
    $ddl = file_get_contents(dirname(__DIR__).'/application/install/sql/install.sql');
    foreach ($kinds as $kind) {
        if (!preg_match('/CREATE TABLE `mac_'.preg_quote($kind,'/').'` \(.*?\) ENGINE=[^;]+;/s',$ddl,$match)) { throw new RuntimeException('Missing install table'); }
        Db::execute(str_replace('`mac_'.$kind.'`','`audit_ai_'.$kind.'`',$match[0]));
        $defaults[$kind] = [];
        foreach (Db::query('SHOW COLUMNS FROM audit_ai_'.$kind) as $column) {
            if ($column['Null']==='NO' && $column['Default']===null && !str_contains($column['Extra'],'auto_increment')) { $defaults[$kind][$column['Field']] = ''; }
        }
        foreach ([10=>1,20=>1,30=>0,40=>1,50=>1] as $id=>$status) {
            $row = [$kind.'_id'=>$id,$kind.'_status'=>$status,$kind.'_name'=>'Ordinary '.$kind.' '.$id,$kind.'_pic'=>'ordinary-'.$id.'.png',$kind.'_hits'=>$id];
            if ($kind === 'vod') { $row += ['vod_plot'=>1,'vod_plot_name'=>'Ordinary episodes','vod_plot_detail'=>'Episode description']; }
            if (in_array($kind,['vod','art','manga'],true)) { $row[$kind.'_recycle_time']=$id===40 ? 12345 : 0; }
            elseif ($id===40) { $row[$kind.'_status']=0; }
            Db::name($kind)->insert($row+$defaults[$kind]);
        }
        Db::name($kind)->where($kind.'_id',50)->delete();
    }
    foreach ($modules as $module) foreach ([false,true] as $meili) {
        $clear(); $kind=$sourceKind($module); $sql=[]; $payload=$build($module,$meili);
        check($payloadIds($payload)===($meili?[10,20]:[20,10]),'Ordinary resource rows or rank differ: '.$module);
        check(array_keys($payload)===['enabled','query_original','query_merged','expanded_terms','internal_resources','external_resources'] && $payload['enabled']===true,'Payload contract changed');
        foreach ($payload['internal_resources'] as $row) {
            $id=(int)basename($row['url']);
            check(array_keys($row)===['title','url','pic','type'] && $row['title']==='Ordinary '.$kind.' '.$id && $row['pic']==='ordinary-'.$id.'.png' && $row['type']===$module && $row['url']==='/fixture/'.$kind.'/'.$id,'Resource display contract changed');
        }
        check(count(array_filter($sql,static fn($q)=>str_contains(strtolower($q),'information_schema.columns')))===1,'One module lookup probed unnecessary table schemas');
        if ($meili) { check(count(Transport::$calls)>=1 && Transport::$calls[0]['body']['limit']===8,'Meili service limit or transport contract changed'); }
    }
    // Optional AI metadata may be built more than once. Reuse expansion, never stale public rows.
    foreach ($modules as $module) foreach ([false,true] as $meili) foreach (['withdraw','delete'] as $change) {
        $clear();$kind=$sourceKind($module);$before=$build($module,$meili);$networkCount=count(Transport::$calls);
        $saved=Db::name($kind)->where($kind.'_id',20)->find();
        if ($change==='withdraw') { Db::name($kind)->where($kind.'_id',20)->update([$kind.'_status'=>0]); }
        else { Db::name($kind)->where($kind.'_id',20)->delete(); }
        $after=$build($module,$meili);
        check($payloadIds($before)===($meili?[10,20]:[20,10]) && $payloadIds($after)===[10],'Repeated payload retained changed content: '.$module.'/'.$change);
        check(count(Transport::$calls)===$networkCount,'Repeated payload unnecessarily repeated the Meili transport');
        if ($change==='withdraw') { Db::name($kind)->where($kind.'_id',20)->update([$kind.'_status'=>1]); }
        else { Db::name($kind)->insert($saved); }
    }
    foreach (['vod','art','manga','plot'] as $module) {
        $clear();$kind=$sourceKind($module);$build($module,true);Db::name($kind)->where($kind.'_id',20)->update([$kind.'_recycle_time'=>23456]);
        check($payloadIds($build($module,true))===[10],'Recycled content remained in repeated payload');
        Db::name($kind)->where($kind.'_id',20)->update([$kind.'_recycle_time'=>0]);
    }
    // Empty/failing service searches differ from successful IDs that no longer identify public rows.
    foreach ($modules as $module) {
        foreach (['empty','unavailable'] as $mode) { $clear();check($payloadIds($build($module,true,$mode))===[20,10],'Ordinary empty/service-unavailable fallback changed: '.$module); }
        $clear();Transport::$ids=[30,40,50];$sql=[];$result=$build($module,true);
        $fallback=in_array($module,['topic','actor','role','website'],true);
        check($payloadIds($result)===($fallback?[20,10]:[]),'Per-module empty database-row fallback changed: '.$module);
        check(count(array_filter($sql,static fn($q)=>str_contains(strtolower($q),'information_schema.columns')))===($fallback?2:1),'Empty-row fallback probed unrelated modules');
    }
    // SQL retains its existing limit 8; only the index path uses internal_result_limit.
    foreach ($kinds as $kind) foreach (range(100,111) as $id) {
        $row=[$kind.'_id'=>$id,$kind.'_status'=>1,$kind.'_name'=>'Collection '.$id,$kind.'_pic'=>'ordinary.png',$kind.'_hits'=>$id];
        if ($kind==='vod') { $row += ['vod_plot'=>1,'vod_plot_name'=>'Collection episodes','vod_plot_detail'=>'Collection details']; }
        Db::name($kind)->insert($row+$defaults[$kind]);
    }
    foreach ($modules as $module) {
        foreach ([2,12,0] as $limit) {
            $app->config->set(['ai_search'=>array_replace($ai,['internal_result_limit'=>$limit])],'maccms');
            $clear();Transport::$ids=range(100,111);$indexed=$build($module,true,'ok','Collection');
            check($payloadIds($indexed)===array_slice(range(100,111),0,max(1,$limit)),'Configured index resource limit changed');
            $clear();$sqlRows=$build($module,false,'ok','Collection');
            check($payloadIds($sqlRows)===range(111,104),'SQL fallback original eight-row/order contract changed');
        }
    }
    $app->config->set(['ai_search'=>$ai],'maccms');
    // Genuine pre-recycle schemas remain usable. No helper DDL is permitted.
    foreach (['vod','art','manga'] as $kind) {
        Db::execute('ALTER TABLE audit_ai_'.$kind.' DROP COLUMN '.$kind.'_recycle_time');
        foreach ([false,true] as $meili) {
            $clear();$sql=[];$payload=$build($kind,$meili);
            check($payloadIds($payload)===($meili?[10,20,40]:[40,20,10]),'Confirmed legacy schema was not supported');
            check(!array_filter($sql,static fn($q)=>preg_match('/^(ALTER|CREATE|DROP|INSERT|UPDATE|DELETE)\b/i',$q)),'Resource lookup modified database schema/data');
        }
        Db::execute('ALTER TABLE audit_ai_'.$kind.' ADD COLUMN '.$kind.'_recycle_time INT UNSIGNED NOT NULL DEFAULT 0');
        Db::name($kind)->where($kind.'_id',40)->update([$kind.'_recycle_time'=>12345]);
    }
    // An incomplete installation is an error, not evidence of a permissive legacy table.
    foreach ($kinds as $kind) {
        Db::execute('ALTER TABLE audit_ai_'.$kind.' RENAME COLUMN '.$kind.'_status TO stored_status');
        try {
            foreach ([false,true] as $meili) {
                $clear();$failed=false;
                try { $build($kind,$meili); } catch (RuntimeException $error) { $failed=str_contains($error->getMessage(),'publication schema'); }
                check($failed,'Incomplete publication schema was accepted: '.$kind);
            }
        } finally { Db::execute('ALTER TABLE audit_ai_'.$kind.' RENAME COLUMN stored_status TO '.$kind.'_status'); }
    }
    foreach ($kinds as $kind) {
        $id=$kind==='topic'?65535:4294967295;
        Db::name($kind)->insert([$kind.'_id'=>$id,$kind.'_status'=>1,$kind.'_name'=>'Maximum id record',$kind.'_pic'=>'ordinary.png']+$defaults[$kind]);
        $clear();Transport::$ids=[$id];check($payloadIds($build($kind,true,'ok','Maximum'))===[$id],'Actual DDL maximum ID was lost');
        Db::name($kind)->where($kind.'_id',$id)->delete();
    }
    // Ordinary matches in each secondary field retain their OR grouping under the publication guard.
    $likeFields = [
        'vod'=>['vod_name','vod_sub','vod_actor','vod_tag'],
        'art'=>['art_name','art_sub','art_tag'],
        'manga'=>['manga_name','manga_sub','manga_tag','manga_blurb','manga_author'],
        'topic'=>['topic_name','topic_sub','topic_tag','topic_blurb'],
        'actor'=>['actor_name','actor_alias','actor_tag','actor_works'],
        'role'=>['role_name','role_actor','role_remarks'],
        'website'=>['website_name','website_sub','website_tag','website_blurb'],
        'plot'=>['vod_plot_name','vod_plot_detail'],
    ];
    foreach ($likeFields as $module=>$fields) foreach ($fields as $field) {
        $kind=$sourceKind($module);
        foreach ([70=>1,75=>0] as $id=>$status) {
            $row=[$kind.'_id'=>$id,$kind.'_status'=>$status,$kind.'_name'=>'Distinct ordinary title',$kind.'_pic'=>'ordinary.png',$kind.'_hits'=>$id];
            $row[$field]='Field sample';Db::name($kind)->insert($row+$defaults[$kind]);
        }
        foreach ([false,true] as $meili) {
            $clear();check($payloadIds($build($module,$meili,'unavailable','Field'))===[70],'Secondary field match or publication grouping changed: '.$field);
        }
        Db::name($kind)->whereIn($kind.'_id',[70,75])->delete();
    }
    $defaultLimit=$ai;unset($defaultLimit['internal_result_limit']);$app->config->set(['ai_search'=>$defaultLimit],'maccms');
    $clear();Transport::$ids=range(100,111);check($payloadIds($build('vod',true,'ok','Collection'))===range(100,107),'Missing configuration no longer defaults to eight index resources');
    $app->config->set(['ai_search'=>$ai],'maccms');
    require __DIR__.'/fixtures/ai_search_writer.php';
    // Module enablement and short/empty queries retain the existing optional-feature contract.
    foreach (['','x'] as $word) { $app->config->set(['ai_search'=>array_replace($ai,['min_query_len'=>'2'])],'maccms');check($build('vod',false,'ok',$word)['enabled']===false,'Minimum query length changed'); }
    $app->config->set(['ai_search'=>array_replace($ai,['enabled'=>'0'])],'maccms');check($build('vod',false)['enabled']===false,'Disabled AI resources queried content');
    echo 'AI internal resources: '.$checks.' checks passed on PHP '.PHP_VERSION." / MySQL\n";
} finally {
    $app->instance('think\DbManager',$originalManager);
    foreach ($kinds as $kind) { Db::execute('DROP TABLE IF EXISTS audit_ai_'.$kind); }
    audit_remove_temp($temp);
}
}
