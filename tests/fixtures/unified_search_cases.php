<?php
/** Full routes with real Request and SQL; invalidation is checked at both cache exits. */
use think\facade\Db;
use app\common\util\MeilisearchHttp as Transport;
$reset=static function():void{global $cache,$queryFault,$sql;$cache->data=[];$cache->ttl=[];$cache->fault='';$queryFault='';$sql=[];Transport::$hits=[];Transport::$ignoreLimit=false;$GLOBALS['config']['app']['search']='1';};
$ids=static fn($response,$kind)=>array_column($response['info'][$kind]['list'],'id');
$slimIds=static fn($response,$kind)=>array_values(array_column(array_filter($response['info']['list'],static fn($row)=>$row['module']===$kind),'id'));
$assertPublic=static function(array $response):void {
    check($response['code']===1 && array_keys($response)===['code','msg','info'],'Public search response shape changed');
    check(!str_contains(json_encode($response),'PRIVATE-'),'Unselected source fields escaped the DTO');
};
foreach($kinds as $kind) {
    $reset();$r=unifiedRequest('index',['wd'=>'match','module'=>$kind]);$assertPublic($r);
    check($r['info'][$kind]['total']===2&&$ids($r,$kind)===[20,10],'SQL Collection/publication failed for '.$kind);
    foreach($r['info'][$kind]['list'] as $row){check(count($row)===22&&$row['module']===$kind&&$row['link']==='/'.$kind.'/'.$row['id']&&$row['pic']==='/fixture/cover.png','Rich DTO lost usable fields');}
    $reset();$r=unifiedRequest('index',['wd'=>'match','module'=>$kind,'limit'=>'1','page'=>'2']);
    check($r['info']['page']===2&&$r['info']['limit']===1&&$r['info'][$kind]['total']===2&&$ids($r,$kind)===[10],'Each module must have its own page/limit');
    $reset();$r=unifiedRequest('index',['wd'=>'match','module'=>$kind],true);$assertPublic($r);
    check($ids($r,$kind)===[10,20]&&$r['info'][$kind]['total']===66,'Meili rank order/estimate or current DB visibility changed');
    $body=Transport::$calls[0]['body'];check($body['limit']===10&&$body['offset']===0&&$body['filter']==='kind = "'.$kind.'" AND recycle = 0 AND status = 1','Meili search lost its published filter or pagination');
}
$reset();$r=unifiedRequest('index',['wd'=>'match','limit'=>1]);$assertPublic($r);
check(array_keys($r['info'])===['wd','module','page','limit','vod','art','manga'],'Combined module structure changed');
foreach($kinds as $kind)check($r['info'][$kind]['total']===2&&$ids($r,$kind)===[20],'all limit is per module');
foreach(['empty','fail'] as $mode) {
    $reset();$r=unifiedRequest('index',['wd'=>'match','module'=>'vod'],true,$mode);
    check($ids($r,'vod')===($mode==='empty'?[]:[20,10]),'Index Meili-empty and unavailable fallback contracts changed');
    $reset();$r=unifiedRequest('suggest',['wd'=>'match'],true,$mode);$assertPublic($r);
    foreach($kinds as $kind)check($slimIds($r,$kind)===[20,10],'Suggestion empty/unavailable search must keep its SQL fallback');
}
$reset();$r=unifiedRequest('suggest',['wd'=>'match','limit'=>10],true);$assertPublic($r);
check($r['info']['total']===6&&array_is_list($r['info']['list']),'Unified suggestion count changed');
foreach($kinds as $kind)check($slimIds($r,$kind)===[10,20],'Suggestion Meili ranking/visibility lost');
foreach($r['info']['list'] as $row)check(array_keys($row)===['id','name','en','pic','link','module','module_name']&&$row['name']==='match '.$row['id']&&$row['link']==='/'.$row['module'].'/'.$row['id'],'Slim DTO differs from actual source row');

// Bad hit shapes/IDs cannot coerce another primary key or exceed the requested module limit.
$reset();Transport::$ignoreLimit=true;
foreach($kinds as $kind)Transport::$hits[$kind]=[null,[],['id'=>[]],['id'=>$kind.'_0'],['id'=>$kind.'_4294967296'],['id'=>$kind.'_01'],['id'=>$kind.'_10'],['id'=>$kind.'_10'],['id'=>$kind.'_20'],['id'=>'other_20']];
$r=unifiedRequest('index',['wd'=>'match','module'=>'vod','limit'=>50],true);
check($ids($r,'vod')===[10,20],'Malformed Meili hit ID changed DB lookup identity');
$cache->data=[];$r=unifiedRequest('index',['wd'=>'match','module'=>'vod','limit'=>1],true);
check($ids($r,'vod')===[],'Oversized Meili hit list exceeded requested per-module limit');

// String and integer request contracts, including a searchable numeric zero.
foreach($kinds as $kind){$row=Db::name($kind)->find(10);$row[$kind.'_id']=100;$row[$kind.'_name']='0';$row[$kind.'_en']='zero';Db::name($kind)->insert($row);}
foreach(['index','suggest'] as $endpoint) {
    foreach([0,'0',' 0 '] as $keyword){$reset();$r=unifiedRequest($endpoint,['wd'=>$keyword]);check($r['code']===1&&$r['info']['wd']==='0','Numeric zero keyword rejected');}
    foreach([[],['wd'=>null],['wd'=>''],['wd'=>'   '],['wd'=>[]],['wd'=>new stdClass()],['wd'=>false],['wd'=>true],['wd'=>1.25],['wd'=>"\xff"],['wd'=>"abc\0def"],['wd'=>str_repeat('a',4097)]] as $bad) {
        $reset();$r=unifiedRequest($endpoint,$bad);check($r['code']===1001&&!isset($r['info'])&&$sql===[]&&$cache->data===[],'Bad keyword must fail before cache/rate/SQL work');
    }
    $reset();$long=str_repeat('中',60);$r=unifiedRequest($endpoint,['wd'=>$long]);check($r['code']===1&&$r['info']['wd']===str_repeat('中',50),'Existing 50-character CJK truncation changed');
    foreach(['limit',...($endpoint==='index'?['page']:[])] as $field) {
        foreach([[],new stdClass(),false,true,1.5,'1e2','1.0','2garbage','--1',PHP_INT_MAX,'4294967296','-4294967296',str_repeat('1',80)] as $bad) {
            $reset();$r=unifiedRequest($endpoint,['wd'=>'match',$field=>$bad]);check($r['code']===1001&&$sql===[],'Bad pagination value reached query/cache work');
        }
    }
    foreach([null,1,'1',' +02 ','0000000001',0,'-2',99] as $value) {
        $reset();$r=unifiedRequest($endpoint,['wd'=>'match','limit'=>$value]);check($r['code']===1,'Legal integer pagination compatibility changed');
        if($endpoint==='index')check($r['info']['limit']===($value===null?10:max(1,min(50,(int)$value))),'Index limit clamp changed');
        else foreach($kinds as $kind)check(count($slimIds($r,$kind))<=($value===null?5:max(1,min(10,(int)$value))),'Suggestion limit no longer applies per module');
    }
}
foreach([null,'',' all ','VoD','art','MANGA','unknown',123] as $module){$reset();$r=unifiedRequest('index',['wd'=>'match','module'=>$module]);$normalized=strtolower(trim((string)$module));check($r['code']===1&&$r['info']['module']===(in_array($normalized,$kinds,true)?$normalized:'all'),'Legacy module normalization/default changed');}
foreach([[],new stdClass(),false,1.5,str_repeat('v',33)] as $module){$reset();$r=unifiedRequest('index',['wd'=>'match','module'=>$module]);check($r['code']===1001&&$sql===[],'Invalid module reached DB');}
$reset();$r=unifiedRequest('index',['wd'=>'match','module'=>'vod','page'=>'4294967295','limit'=>50]);
check($r['code']===1&&$r['info']['page']===4294967295&&$ids($r,'vod')===[]&&$r['info']['vod']['total']===2,'Max bounded page must return a coherent empty SQL page');
check(!(bool)array_filter($sql,static fn($q)=>preg_match('/\bLIMIT\b/i',$q)),'SQL offset beyond the real total still executed a deep SELECT');
$reset();$r=unifiedRequest('index',['wd'=>'match','module'=>'vod','page'=>'4294967295','limit'=>50],true);
check($r['code']===1&&Transport::$calls[0]['body']['offset']===214748364700,'Meili pagination offset overflowed or was silently clamped');
$reset();$r=unifiedRequest('index',['wd'=>'SELECT']);check($r['code']===1001,'Existing SQL-safe keyword filter changed');
foreach($kinds as $kind)Db::name($kind)->where($kind.'_id',100)->delete();

// Both result-cache exits must revalidate every source ID, including fresh Meili-backed pages.
foreach(['index','suggest'] as $endpoint)foreach([false,true] as $meili)foreach($kinds as $kind)foreach(['hidden','recycled','deleted'] as $state) {
    $original=Db::name($kind)->find(20);$reset();$before=unifiedRequest($endpoint,['wd'=>'match'], $meili);
    check($before['code']===1,'Could not populate a valid cached result');
    if($state==='deleted')Db::name($kind)->where($kind.'_id',20)->delete();else Db::name($kind)->where($kind.'_id',20)->update([$kind.($state==='hidden'?'_status':'_recycle_time')=>$state==='hidden'?0:time()]);
    $after=unifiedRequest($endpoint,['wd'=>'match'],$meili);
    check($after['code']===1&&!in_array(20,$endpoint==='index'?$ids($after,$kind):$slimIds($after,$kind),true),'Hidden/recycled/deleted result replayed from '.$endpoint.' cache');
    if($state==='deleted')Db::name($kind)->insert($original);else Db::name($kind)->where($kind.'_id',20)->update($original);
}
foreach(['index','suggest'] as $endpoint) {
    $reset();$before=unifiedRequest($endpoint,['wd'=>'match']);$rate=$cache->data['api_search_rl_'.md5('127.0.0.1')]??null;$sql=[];
    $after=unifiedRequest($endpoint,['wd'=>'match']);check($after===$before&&($cache->data['api_search_rl_'.md5('127.0.0.1')]??null)===$rate,'Valid cache hit consumed the miss-only rate quota');
    check(!(bool)array_filter($sql,static fn($q)=>stripos($q,' LIKE ')!==false),'Valid cache hit reran LIKE instead of ID visibility checks');
    $keys=array_values(array_filter(array_keys($cache->data),static fn($key)=>str_starts_with($key,'api_search_v2_')));
    check(count($keys)===1&&$cache->ttl[$keys[0]]===300,'Result cache TTL/key isolation changed');
    $key=$keys[0];$cache->data[$key]['info'][$endpoint==='index'?'vod':'list'][$endpoint==='index'?'list':0]= $endpoint==='index'
        ? array_replace($cache->data[$key]['info']['vod']['list'],[0=>$cache->data[$key]['info']['vod']['list'][0]+['PRIVATE'=>'value']])
        : $cache->data[$key]['info']['list'][0]+['PRIVATE'=>'value'];
    $after=unifiedRequest($endpoint,['wd'=>'match']);check($after['code']===1&&!str_contains(json_encode($after),'PRIVATE'),'Unexpected cached DTO fields escaped');
    $cache->data[$key]=$before;$GLOBALS['config']['app']['search']='0';$r=unifiedRequest($endpoint,['wd'=>'match']);check($r['code']===999,'Search site switch was bypassed by cached result');
}

// Malformed cached payloads are discarded, never projected directly into an otherwise successful response.
foreach(['index','suggest'] as $endpoint) {
    $reset();$valid=unifiedRequest($endpoint,['wd'=>'match']);
    $key=array_values(array_filter(array_keys($cache->data),static fn($key)=>str_starts_with($key,'api_search_v2_')))[0];
    foreach(['bad-id','overflow-id','duplicate-id','wrong-kind','missing-field','nested-name','too-many','wrong-code','wrong-page'] as $fault) {
        $cached=$valid;
        $rows=&$cached['info'][$endpoint==='index'?'vod':'list'];
        if($endpoint==='index')$rows=&$cached['info']['vod']['list'];
        switch($fault) {
            case 'bad-id':$rows[0]['id']=[];break;
            case 'overflow-id':$rows[0]['id']=4294967296;break;
            case 'duplicate-id':$rows[1]['id']=$rows[0]['id'];break;
            case 'wrong-kind':$rows[0]['module']='private';break;
            case 'missing-field':unset($rows[0]['name']);break;
            case 'nested-name':$rows[0]['name']=['PRIVATE'=>'cache'];break;
            case 'too-many':$rows=array_fill(0,51,$rows[0]);break;
            case 'wrong-code':$cached['code']=999;break;
            case 'wrong-page':if($endpoint==='index')$cached['info']['page']=2;else $cached['info']['total']=999;break;
        }
        unset($rows);$cache->data[$key]=$cached;
        $actual=unifiedRequest($endpoint,['wd'=>'match']);check($actual===$valid,'Malformed cached DTO was reused: '.$endpoint.'/'.$fault);
    }
}
$reset();foreach($kinds as $kind){$row=Db::name($kind)->find(10);$row[$kind.'_id']=4294967295;$row[$kind.'_name']='maximum';Db::name($kind)->insert($row);Transport::$hits[$kind]=[['id'=>$kind.'_4294967295']];}
foreach(['index','suggest'] as $endpoint){$cache->data=[];$r=unifiedRequest($endpoint,['wd'=>'maximum'],true);foreach($kinds as $kind)check(($endpoint==='index'?$ids($r,$kind):$slimIds($r,$kind))===[4294967295],'Valid UINT32 source ID was clipped or rejected');}
foreach($kinds as $kind)Db::name($kind)->where($kind.'_id',4294967295)->delete();
foreach(['index','suggest'] as $endpoint) {
    Db::execute('ALTER TABLE audit_unified_vod RENAME COLUMN vod_status TO fixture_missing_status');
    try{$reset();$r=unifiedRequest($endpoint,['wd'=>'match']);check($r['code']===1002&&!isset($r['info']),'Missing mandatory publication status must not return success');}
    finally{Db::execute('ALTER TABLE audit_unified_vod RENAME COLUMN fixture_missing_status TO vod_status');}
}

// Missing legacy recycle columns are discovered read-only; unrelated failures never relax guards.
foreach($kinds as $kind){
    Db::execute('ALTER TABLE audit_unified_'.$kind.' DROP COLUMN '.$kind.'_recycle_time');
    foreach(['index','suggest'] as $endpoint){$reset();$r=unifiedRequest($endpoint,['wd'=>'match','module'=>$kind]);check($r['code']===1,'Confirmed legacy missing recycle column must remain usable');
        check(in_array(40,$endpoint==='index'?$ids($r,$kind):$slimIds($r,$kind),true),'Legacy status-only schema was not recognized');
        check(!(bool)array_filter($sql,static fn($q)=>preg_match('/^(?:ALTER|CREATE|UPDATE|DELETE|INSERT|DROP)\b/i',$q)),'Public search performed schema/data mutation');}
    Db::execute('ALTER TABLE audit_unified_'.$kind.' ADD COLUMN '.$kind.'_recycle_time int unsigned NOT NULL DEFAULT 0');Db::name($kind)->where($kind.'_id',40)->update([$kind.'_recycle_time'=>time()]);
}
foreach(['index','suggest'] as $endpoint)foreach(['recycle','schema'] as $fault) {
    $reset();$queryFault=$fault;$logs=[];$r=unifiedRequest($endpoint,['wd'=>'match','module'=>'vod']);
    check($r['code']===1002&&!isset($r['info'])&&$logs!==[]&&!str_contains(json_encode($r),'private fixture'),'SQL/schema failure must be explicit, diagnosed and sanitized');
    check(!(bool)array_filter($sql,static fn($q)=>preg_match('/\bFROM\s+`?audit_unified_vod\b/i',$q)&&!str_contains($q,'vod_recycle_time')),'Query failure retried without recycle guard');
}
foreach(['index','suggest'] as $endpoint)foreach(['get','set'] as $fault) {
    $reset();$cache->fault=$fault;$logs=[];$r=unifiedRequest($endpoint,['wd'=>'match']);check($r['code']===1002&&$logs!==[]&&!isset($r['info']),'Cache exception became a PHP failure or false successful empty result');
}
$reset();$r=unifiedRequest('index',['wd'=>'match'],true,'throw');check($r['code']===1002,'Unexpected transport exception was not controlled');
$reset();for($i=0;$i<30;$i++){ $r=unifiedRequest($i%2?'index':'suggest',['wd'=>'miss-'.$i]);check($r['code']===1,'Shared quota rejected fewer than 30 misses'); }
$r=unifiedRequest('suggest',['wd'=>'over-quota']);check($r['code']===1004&&$cache->ttl['api_search_rl_'.md5('127.0.0.1')]===60,'index/suggest quota or window changed');
$r=unifiedRequest('suggest',['wd'=>'miss-0']);check($r['code']===1,'Previously cached result stopped working at rate limit');

require __DIR__.'/unified_search_writer.php';
