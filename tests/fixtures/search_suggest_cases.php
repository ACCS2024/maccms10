<?php
use think\facade\Db;
use app\common\util\ApiMeilisearchSuggest as Suggest;
use app\common\util\MeilisearchHttp as Transport;
foreach($kinds as $kind){
    check(array_column(Suggest::orderedDbRowsByIds($kind,[20,40,10,30,20,50,999]),$kind.'_id')===[20,10],'Actual ordered SQL returns a PHP array, deduplicates IDs and filters '.$kind.' state');
    resetSuggestSearch();$sql=[];assertSuggestions($kind,suggestApi($kind),[10,20]);
    check((bool)Transport::$calls,'Real API suggestion uses the search service transport');
    check(count(array_filter($sql,fn($query)=>preg_match('/^SELECT\b/i',$query)&&str_contains($query,'audit_suggest_'.$kind)))===1,'Successful search needs only one guarded database lookup');
    foreach([['empty',true],['fail',true],['empty',false]] as [$mode,$enabled]){
        resetSuggestSearch($mode,$enabled);$sql=[];assertSuggestions($kind,suggestApi($kind),[20,10]);
        check(!array_filter($sql,fn($query)=>preg_match('/^SELECT\s+\*/i',$query)),'Fallback suggestions fetch only their selected fields');
        if(!$enabled)check(Transport::$calls===[],'Disabled search makes no transport call');
    }
    resetSuggestSearch('empty',false);assertSuggestions($kind,suggestApi($kind,'no-such-title'),[]);
    resetSuggestSearch('empty',false);$r=suggestApi($kind,'match',1);assertSuggestions($kind,$r,[20]);
    check($r['total']===2 && $r['limit']===1 && $r['pagecount']===2,'API fallback retains real total and requested page size');
    $copy=Db::name($kind)->where($kind.'_id',10)->find();$copy[$kind.'_id']=70;$copy[$kind.'_name']='literal%_match';Db::name($kind)->insert($copy);
    check(array_column(Suggest::fallbackListDataRes($kind,'%_match',10)['list'],$kind.'_id')===[70],'Literal percent and underscore remain escaped in fallback LIKE');
    Db::name($kind)->where($kind.'_id',70)->delete();
}
foreach([1=>'vod',2=>'art',3=>'topic',8=>'actor',9=>'role',11=>'website'] as $mid=>$kind){
    foreach([['ok',true,[10,20]],['empty',true,[20,10]],['fail',true,[20,10]],['empty',false,[20,10]]] as [$mode,$enabled,$ids]){
        resetSuggestSearch($mode,$enabled);$cache->data=[];assertSuggestions($kind,suggestAjax($mid),$ids,true);
    }
    resetSuggestSearch('empty',false);$cache->data=[];assertSuggestions($kind,suggestAjax($mid,'no-such-title'),[],true);
    $cache->data=[];$r=suggestAjax($mid,'match',1);assertSuggestions($kind,$r,[20],true);
    check($r['total']===0 && $r['limit']===1 && $r['pagecount']===0,'Ajax fallback preserves its existing totalshow-disabled envelope');
    Db::name($kind)->where($kind.'_id',10)->update([$kind.'_hits_month'=>1000]);$cache->data=[];
    assertSuggestions($kind,suggestAjax($mid),[10,20],true);
    $cache->data=array_filter($cache->data,fn($key)=>str_starts_with($key,'search:suggest:debounce:'),ARRAY_FILTER_USE_KEY);
    $GLOBALS['config']['app']['search_suggest_order']='id';assertSuggestions($kind,suggestAjax($mid),[20,10],true);
    $GLOBALS['config']['app']['search_suggest_order']='popular';Db::name($kind)->where($kind.'_id',10)->update([$kind.'_hits_month'=>10]);
    resetSuggestSearch();$cache->data=[];$first=suggestAjax($mid);
    $normalKey=array_values(array_filter(array_keys($cache->data),fn($key)=>str_starts_with($key,'search:suggest:v')))[0];
    $debounceKey=array_values(array_filter(array_keys($cache->data),fn($key)=>str_starts_with($key,'search:suggest:debounce:')))[0];
    foreach(['normal','debounce'] as $cachePath){
        $cache->data=$cachePath==='normal'?[$normalKey=>$first]:[$debounceKey=>$first];resetSuggestSearch();$sql=[];
        assertSuggestions($kind,suggestAjax($mid),[10,20],true);
        check(Transport::$calls===[] && (bool)array_filter($sql,fn($query)=>str_contains($query,'COUNT(')),'Both '.$cachePath.' cache paths revalidate public IDs without rerunning search');
        Db::name($kind)->where($kind.'_id',10)->update([$kind.'_status'=>0]);resetSuggestSearch();
        $cache->data=$cachePath==='normal'?[$normalKey=>$first]:[$debounceKey=>$first];assertSuggestions($kind,suggestAjax($mid),[20],true);
        Db::name($kind)->where($kind.'_id',10)->update([$kind.'_status'=>1]);
    }
    $bad=$first;$bad['list'][0]['private_body']='PRIVATE-CACHED-BODY';check(!Suggest::cachedResultIsVisible($kind,$bad),'Old or overbroad cached DTOs cannot bypass fixed projection');
    foreach([[],null,'4294967296',0] as $id){$bad=$first;$bad['list'][0]['id']=$id;check(!Suggest::cachedResultIsVisible($kind,$bad),'Malformed cached IDs force a fresh lookup');}
}
// A real SQL error must preserve the safety predicate in the failed statement, without a weaker retry.
$meta=['table'=>'Vod','pk'=>'vod_id','status'=>'vod_status','recycle'=>'vod_recycle_time','field'=>'missing_fixture_column'];
$failed=false;try{Suggest::orderedDbRowsByIds('vod',[40],$meta);}catch(\think\db\exception\PDOException $error){$failed=true;}
check($failed && str_contains(Db::connect()->getLastSql(),'vod_recycle_time'),'Unknown selected columns fail at the guarded SQL statement');
$queryFault=true;$sql=[];$failed=false;try{Suggest::orderedDbRowsByIds('vod',[40]);}catch(\RuntimeException $error){$failed=str_contains($error->getMessage(),'Injected trace failure');}
check($failed && !array_filter($sql,fn($query)=>preg_match('/^SELECT\b/i',$query)&&!str_contains($query,'vod_recycle_time')),'Non-SQL failures also never cause a retry without the recycle predicate');
check(Suggest::orderedDbRowsByIds('unsupported',[10])===[] && Suggest::suggestListDataRes('unsupported','match',10)['code']===1001,'Unknown media retain controlled empty/error contracts');
// Missing recycle fields are detected before querying, including the Meili path before ordered selection.
foreach(['vod','art','manga'] as $kind){
    Db::name($kind)->where($kind.'_id',40)->delete();Db::execute('ALTER TABLE audit_suggest_'.$kind.' DROP COLUMN '.$kind.'_recycle_time');Db::connect()->getSchemaInfo('audit_suggest_'.$kind,true);
    $sql=[];check(array_column(Suggest::orderedDbRowsByIds($kind,[20,10,30]),$kind.'_id')===[20,10],'Legacy ordered lookup still enforces published state');
    resetSuggestSearch();assertSuggestions($kind,suggestApi($kind),[10,20]);
    resetSuggestSearch('empty',false);assertSuggestions($kind,suggestApi($kind),[20,10]);
    if($kind!=='manga'){$cache->data=[];assertSuggestions($kind,suggestAjax($kind==='vod'?1:2),[20,10],true);}
    check(!array_filter($sql,fn($query)=>preg_match('/^(ALTER|CREATE|INSERT|UPDATE|DELETE)\b/i',$query)),'Legacy search success needs no runtime DDL');
}
