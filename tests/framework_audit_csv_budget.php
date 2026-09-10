<?php
/** Bounded ordinary CSV inputs under the actual default deployment memory limit. */
declare(strict_types=1);
require dirname(__DIR__).'/application/common/util/BulkTableIo.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\BulkTableIo;
$cases=['empty','bom','standard','rows_limit','rows_over','columns_limit','columns_over',
    'cells_limit','cells_over','padding_limit','padding_over','record_limit','record_over',
    'bytes_limit','bytes_over','dense_fields','multiline','unclosed','trailing_text'];
if (($argv[1]??'')!=='--case') {
    foreach ($cases as $case) {
        $process=proc_open([PHP_BINARY,'-d','memory_limit=128M','-d','error_reporting=-1','-d','display_errors=stderr',
            __FILE__,'--case',$case],[0=>['file','/dev/null','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        check(is_resource($process),'CSV budget worker must start');
        $output=stream_get_contents($pipes[1]);fclose($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[2]);
        $status=proc_close($process);$result=json_decode($output,true);
        check($status===0&&$errors===''&&is_array($result)&&($result['result']??null)==='passed',
            'CSV budget worker failed: '.$case.'; '.$output.'; '.$errors);
        check($result['peak_bytes']<=96*1024*1024,'CSV parser exceeded its isolated memory allowance: '.$case);
        $checks+=$result['checks'];
        echo $case.': '.$result['peak_bytes']." peak bytes\n";
    }
    echo 'CSV budgets: '.$checks.' checks across '.count($cases).' isolated 128M processes on PHP '.PHP_VERSION."\n";
    exit;
}
$case=$argv[2]??'';
if (!in_array($case,$cases,true)) { throw new RuntimeException('Unknown ordinary CSV case'); }
$path=tempnam(sys_get_temp_dir(),'csv-budget-');
if ($path===false) { throw new RuntimeException('Cannot create CSV fixture'); }
$handle=fopen($path,'wb');
function csvBudgetRepeat($handle,string $value,int $count):void {
    for($i=0;$i<$count;$i++) { if(fwrite($handle,$value)!==strlen($value))throw new RuntimeException('Fixture write failed'); }
}
try {
    switch($case) {
        case 'empty':break;
        case 'bom':fwrite($handle,"\xEF\xBB\xBF");break;
        case 'standard':fwrite($handle,"\xEF\xBB\xBF name ,note\r\n普通,\"C:\\\"\r\n\"x\"\"y\",\"one\ntwo\"\r\n\r\n");break;
        case 'rows_limit':case 'rows_over':
            fwrite($handle,"name,note\n");csvBudgetRepeat($handle,"ordinary,tail\n",$case==='rows_limit'?2000:2001);break;
        case 'columns_limit':case 'columns_over':
            $count=$case==='columns_limit'?256:257;
            fputcsv($handle,array_map(static fn($i)=>'h'.$i,range(1,$count)),',','"','');
            fputcsv($handle,array_fill(0,$count,'ordinary'),',','"','');break;
        case 'cells_limit':case 'cells_over':
            fputcsv($handle,array_map(static fn($i)=>'h'.$i,range(1,100)),',','"','');
            csvBudgetRepeat($handle,str_repeat('ordinary,',99)."ordinary\n",$case==='cells_limit'?999:1000);break;
        case 'padding_limit':case 'padding_over':
            fputcsv($handle,array_map(static fn($i)=>'h'.$i,range(1,256)),',','"','');
            csvBudgetRepeat($handle,"ordinary\n",$case==='padding_limit'?390:391);break;
        case 'record_limit':case 'record_over':
            fwrite($handle,"note\n");csvBudgetRepeat($handle,str_repeat('a',1024),8192);
            fwrite($handle,$case==='record_over'?"b\n":"\n");break;
        case 'bytes_limit':
            fwrite($handle,"note\n");csvBudgetRepeat($handle,str_repeat('a',1024),7168);fwrite($handle,"\n");
            csvBudgetRepeat($handle,str_repeat('b',1024),7168);fwrite($handle,"\n");
            csvBudgetRepeat($handle,str_repeat('c',1024),6143);fwrite($handle,str_repeat('c',1016)."\n");break;
        case 'bytes_over':ftruncate($handle,BulkTableIo::MAX_IMPORT_BYTES+1);break;
        case 'dense_fields':fwrite($handle,str_repeat(',',2*1024*1024)."\n");break;
        case 'multiline':fwrite($handle,"note\n\"");csvBudgetRepeat($handle,"ordinary\n",3000);fwrite($handle,"\"\n");break;
        case 'unclosed':fwrite($handle,"note\n\"ordinary\n");break;
        case 'trailing_text':fwrite($handle,"note\n\"ordinary\"extra\n");break;
    }
    fclose($handle);$handle=null;
    $reject=str_ends_with($case,'_over')||in_array($case,['dense_fields','unclosed','trailing_text'],true);
    $result=null;$error=null;
    try { $result=BulkTableIo::parseCsv($path); } catch (RuntimeException $caught) { $error=$caught; }
    check(($error!==null)===$reject,'Parser must accept/reject the complete file at its documented boundary: '.$case);
    if (!$reject) {
        check(is_array($result)&&isset($result['headers'],$result['rows']),'Accepted CSV has the actual import contract');
        if(in_array($case,['empty','bom'],true))check($result===['headers'=>[],'rows'=>[]],'Empty data must remain empty');
        if($case==='standard')check($result===['headers'=>['name','note'],'rows'=>[
            ['name'=>'普通','note'=>'C:\\'],['name'=>'x"y','note'=>"one\ntwo"]]],'Standard quoting, BOM and literal backslash survive');
        if($case==='rows_limit')check(count($result['rows'])===2000,'Import row limit must not truncate a valid last row');
        if($case==='columns_limit')check(count($result['headers'])===256&&count($result['rows'][0])===256,'Column limit preserves all values');
        if($case==='cells_limit')check(count($result['rows'])===999&&count($result['rows'][998])===100,'Input cell budget includes the header');
        if($case==='padding_limit')check(count($result['rows'])===390&&count($result['rows'][389])===256,'Missing cells are budgeted before padding');
        if($case==='record_limit')check(strlen($result['rows'][0]['note'])===8388608,'A full-size record with a newline is accepted exactly');
        if($case==='bytes_limit')check(filesize($path)===BulkTableIo::MAX_IMPORT_BYTES&&count($result['rows'])===3
            &&array_sum(array_map('strlen',array_column($result['rows'],'note')))===BulkTableIo::MAX_IMPORT_BYTES-8,'Whole-file limit retains every byte of its three records');
        if($case==='multiline')check($result['rows']===[['note'=>str_repeat("ordinary\n",3000)]],'Quoted newlines do not count as extra records');
    }
    echo json_encode(['result'=>'passed','case'=>$case,'checks'=>$checks,'peak_bytes'=>memory_get_peak_usage(true)],JSON_THROW_ON_ERROR)."\n";
} finally {
    if(is_resource($handle))fclose($handle);
    unlink($path);
}
