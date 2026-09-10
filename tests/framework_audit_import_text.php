<?php
/** Complete CSV text validation before any row can be sent to storage. */
declare(strict_types=1);
require dirname(__DIR__).'/application/common/util/BulkTableIo.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\BulkTableIo;
use app\common\util\ImportTextException;
$directory=audit_temp_dir('import-text');
try {
    $path=$directory.'/ordinary.csv';
    $invalid=["\xff","\xc0\xaf","\xe2\x82","\xed\xa0\x80","\xf4\x90\x80\x80",iconv('UTF-8','GBK','普通正文')];
    foreach(range(0,31)as $byte){if(!in_array($byte,[9,10,13],true)){$invalid[]=chr($byte);}}
    foreach($invalid as $value){
        file_put_contents($path,"name,note\nFirst,prefix row\nSecond,".$value."\n");$hash=hash_file('sha256',$path);
        foreach(['csv','txt']as $extension){
            $caught=false;try{BulkTableIo::parseFile($path,$extension,true);}catch(ImportTextException $e){$caught=true;}
            check($caught && hash_file('sha256',$path)===$hash,'Invalid UTF-8 or unsupported control byte rejects the entire unchanged source');
        }
    }
    foreach(['UTF-16LE','UTF-16BE','UTF-32LE','UTF-32BE']as $encoding){
        file_put_contents($path,iconv('UTF-8',$encoding,"name,note\nFirst,ordinary\n"));
        $caught=false;try{BulkTableIo::parseCsv($path);}catch(ImportTextException $e){$caught=true;}
        check($caught,'CSV input encoding is explicit rather than guessed from byte patterns');
    }
    foreach([false,true]as $bom){
        $out=fopen($path,'wb');if($bom){fwrite($out,"\xef\xbb\xbf");}
        fputcsv($out,['name','note'],',','"','');$rows=[['name'=>'普通 😀','note'=>"Tabs\tCR\rLF\nend"],['name'=>'First','note'=>"Literal BOM \xef\xbb\xbf in text"]];
        foreach($rows as $row){fputcsv($out,array_values($row),',','"','');}fclose($out);
        check(BulkTableIo::parseCsv($path)['rows']===$rows,'UTF-8, optional initial BOM, literal internal BOM and allowed whitespace round-trip');
    }
    $handle=fopen($path,'wb');fwrite($handle,"note\n");$chunk=str_repeat('a',1024);
    for($i=0;$i<20479;$i++){fwrite($handle,$chunk);}fwrite($handle,str_repeat('b',1018)."\xff");fclose($handle);
    check(filesize($path)===BulkTableIo::MAX_IMPORT_BYTES,'Late invalid byte fixture uses the full accepted raw size');
    $caught=false;try{BulkTableIo::parseCsv($path);}catch(ImportTextException $e){$caught=true;}
    check($caught,'UTF-8 validation checks the entire raw file before its first parsed row');
    printf("Import text encoding: %d checks on PHP %s; peak %.2f MiB.\n",$checks,PHP_VERSION,memory_get_peak_usage(true)/1048576);
} finally {audit_remove_temp($directory);}
