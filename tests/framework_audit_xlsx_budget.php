<?php
/** Ordinary XLSX structure/capacity boundaries, real ZIP/XML, isolated 128M processes. */
declare(strict_types=1);
require dirname(__DIR__).'/application/common/util/BulkTableIo.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\BulkTableIo;
$cases=['empty','coordinate','row_limit','row_over','column_limit','column_over','coordinate_over','row_mismatch',
    'padding_limit','padding_over','cells_limit','cells_over','shared_over','reference_over','text_limit','text_over',
    'part_over','parts_sum_over','archive_limit','archive_over','zip_comment','entries_limit','entries_over','invalid_directory','invalid_directory_count','invalid_local','invalid_crc','invalid_central','invalid_xml','empty_xml',
    'doctype','doctype_utf16','doctype_utf32','utf16_le','utf16_be','utf32_le','utf32_be','utf16_no_bom','utf16_text_limit','cdata_literal','comment_literal','decl_unsupported','depth_limit','depth_over','attribute_count_limit','attribute_count_over','attribute_limit','attribute_over',
    'nodes_over','invalid_reference','duplicate_row','duplicate_cell','fallback','fallback_external','fallback_missing_id','fallback_duplicate_rel'];
if(($argv[1]??'')!=='--case') {
    foreach($cases as $case) {
        $process=proc_open([PHP_BINARY,'-d','memory_limit=128M','-d','error_reporting=-1','-d','display_errors=stderr',__FILE__,'--case',$case],
            [0=>['file','/dev/null','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        check(is_resource($process),'XLSX boundary worker must start');
        $output=stream_get_contents($pipes[1]);fclose($pipes[1]);$errors=stream_get_contents($pipes[2]);fclose($pipes[2]);
        $status=proc_close($process);$result=json_decode($output,true);
        check($status===0&&$errors===''&&is_array($result)&&($result['result']??null)==='passed','XLSX worker failed: '.$case.'; '.$output.'; '.$errors);
        check($result['peak_bytes']<=96*1024*1024&&$result['max_rss_kib']<=192*1024,'XLSX isolated capacity allowance exceeded: '.$case);
        $checks+=$result['checks'];echo $case.': '.$result['peak_bytes'].' PHP peak bytes; '.$result['max_rss_kib']." KiB RSS\n";
    }
    echo 'XLSX budgets: '.$checks.' checks across '.count($cases).' isolated processes on PHP '.PHP_VERSION."\n";exit;
}
$case=$argv[2]??'';if(!in_array($case,$cases,true))throw new RuntimeException('Unknown XLSX capacity case');
$directory=audit_temp_dir('xlsx-budget');$path=$directory.'/ordinary.xlsx';$part=$directory.'/sheet.xml';
$ns='http://schemas.openxmlformats.org/spreadsheetml/2006/main';
function xlsxBudgetRepeat($handle,string $text,int $count):void {
    $batch=max(1,intdiv(65536,max(1,strlen($text))));
    while($count>0){$size=min($batch,$count);fwrite($handle,str_repeat($text,$size));$count-=$size;}
}
function xlsxBudgetCell(string $reference,string $text='ordinary',string $type='inlineStr'):string {
    return '<c r="'.$reference.'" t="'.$type.'">'.($type==='inlineStr'?'<is><t>'.BulkTableIo::xmlEsc($text).'</t></is>':'<v>'.$text.'</v>').'</c>';
}
$sheet=fopen($part,'wb');$zip=new ZipArchive();$zip->open($path,ZipArchive::CREATE|ZipArchive::OVERWRITE);
try {
    if($case==='coordinate') {
        check(BulkTableIo::parseCellRef('A1')===[0,0]&&BulkTableIo::parseCellRef('xfd1048576')===[16383,1048575],'Full spreadsheet coordinate bounds are exact integers');
        foreach([null,[],1,'','A0','A01','XFE1','A1048577',str_repeat('Z',20).'1','A'.str_repeat('9',20),'A1tail'] as $reference) {
            $error=null;try{BulkTableIo::parseCellRef($reference);}catch(InvalidArgumentException $caught){$error=$caught;}
            check($error!==null,'Invalid spreadsheet reference must never coerce to a real cell');
        }
    }
    if(in_array($case,['utf16_le','utf16_be','utf16_text_limit','utf16_no_bom','utf32_le','utf32_be'],true)) {
        fwrite($sheet,'<?xml version="1.0" encoding="'.(str_starts_with($case,'utf32')?'UTF-32':'UTF-16').'"?>');
    }
    if(in_array($case,['doctype','doctype_utf16','doctype_utf32'],true))fwrite($sheet,'<!DOCTYPE worksheet>');
    if($case==='decl_unsupported')fwrite($sheet,'<?xml version="1.0" encoding="UTF-7"?>');
    $attributes='';
    if(str_starts_with($case,'attribute_count'))for($i=0;$i<($case==='attribute_count_limit'?63:64);$i++)$attributes.=' a'.$i.'="0"';
    if(in_array($case,['attribute_limit','attribute_over'],true))$attributes=' ordinary="'.str_repeat('a',$case==='attribute_limit'?8192:8193).'"';
    fwrite($sheet,'<worksheet xmlns="'.$ns.'"'.$attributes.'>');
    if(in_array($case,['depth_limit','depth_over'],true)) {
        $depth=$case==='depth_limit'?32:33;xlsxBudgetRepeat($sheet,'<x>',$depth);xlsxBudgetRepeat($sheet,'</x>',$depth);
    } elseif($case==='nodes_over') { xlsxBudgetRepeat($sheet,'<x/>',1000001); }
    elseif($case==='part_over') { xlsxBudgetRepeat($sheet,' ',21*1024*1024); }
    else {
        fwrite($sheet,'<sheetData>');
        $empty=in_array($case,['empty','coordinate','attribute_count_limit','attribute_count_over','attribute_limit','attribute_over'],true);
        if(!$empty) {
            $width=str_starts_with($case,'padding')?256:(str_starts_with($case,'cells')?100:1);
            fwrite($sheet,'<row r="1">');
            for($i=0;$i<$width;$i++)fwrite($sheet,xlsxBudgetCell(BulkTableIo::colName($i).'1',$i===0?'name':'h'.$i));
            if($case==='column_limit'||$case==='column_over')fwrite($sheet,xlsxBudgetCell(($case==='column_limit'?'IV':'IW').'1','last'));
            if($case==='duplicate_cell')fwrite($sheet,xlsxBudgetCell('A1','replacement'));
            fwrite($sheet,'</row>');
            if($case==='duplicate_row')fwrite($sheet,'<row r="1">'.xlsxBudgetCell('B1','another').'</row>');
            $rows=str_starts_with($case,'padding')?($case==='padding_limit'?390:391):(str_starts_with($case,'cells')?($case==='cells_limit'?999:1000):1);
            if($case==='reference_over')$rows=3;
            for($i=0;$i<$rows;$i++) {
                $row=$i+2;
                if($case==='row_limit'||$case==='row_over')$row=$case==='row_limit'?2001:2002;
                fwrite($sheet,'<row r="'.$row.'">');
                if(in_array($case,['text_limit','text_over','utf16_text_limit'],true)) {
                    fwrite($sheet,'<c r="A2" t="inlineStr"><is><t>');xlsxBudgetRepeat($sheet,str_repeat('a',1024),8192);
                    if($case==='text_over')fwrite($sheet,'b');fwrite($sheet,'</t></is></c>');
                } elseif($case==='cdata_literal') {fwrite($sheet,'<c r="A2" t="inlineStr"><is><t><![CDATA[ordinary <!DOCTYPE note>]]></t></is></c>');}
                elseif($case==='reference_over') { fwrite($sheet,xlsxBudgetCell('A'.$row,'0','s')); }
                elseif($case==='invalid_reference') { fwrite($sheet,xlsxBudgetCell('A2','9','s')); }
                elseif($case==='coordinate_over') { fwrite($sheet,xlsxBudgetCell(str_repeat('Z',20).'2')); }
                elseif($case==='row_mismatch') { fwrite($sheet,xlsxBudgetCell('A3')); }
                else {
                    $count=str_starts_with($case,'cells')?100:1;
                    for($col=0;$col<$count;$col++)fwrite($sheet,xlsxBudgetCell(BulkTableIo::colName($col).$row,'0','n'));
                    if($case==='column_limit')fwrite($sheet,xlsxBudgetCell('IV2','tail'));
                }
                fwrite($sheet,'</row>');
            }
        }
        fwrite($sheet,'</sheetData>');
    }
    if($case==='comment_literal')fwrite($sheet,'<!-- ordinary <!DOCTYPE note> -->');
    if($case==='parts_sum_over')xlsxBudgetRepeat($sheet,'<!--'.str_repeat('a',4096).'-->',3072);
    if($case!=='invalid_xml')fwrite($sheet,'</worksheet>');
    fclose($sheet);$sheet=null;
    if($case==='empty_xml')file_put_contents($part,'');
    if(in_array($case,['utf16_le','utf16_be','utf16_text_limit','utf16_no_bom','doctype_utf16','utf32_le','utf32_be','doctype_utf32'],true)) {
        if($case==='utf32_be'){$encoding='UTF-32BE';$bom="\x00\x00\xFE\xFF";}
        elseif($case==='utf32_le'||$case==='doctype_utf32'){$encoding='UTF-32LE';$bom="\xFF\xFE\x00\x00";}
        else {$encoding=$case==='utf16_be'?'UTF-16BE':'UTF-16LE';$bom=$case==='utf16_be'?"\xFE\xFF":"\xFF\xFE";}
        if($case==='utf16_no_bom')$bom='';
        file_put_contents($part,$bom.iconv('UTF-8',$encoding,file_get_contents($part)));
    }
    $sheetName=str_starts_with($case,'fallback')?'xl/worksheets/ordinary.xml':'xl/worksheets/sheet1.xml';
    $zip->addFile($part,$sheetName);
    if(str_starts_with($case,'fallback')) {
        $zip->addFromString('xl/workbook.xml','<x:workbook xmlns:x="'.$ns.'" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><x:sheets>'.($case==='fallback_missing_id'?'<x:sheet name="missing" sheetId="2"/>':'').'<x:sheet name="ordinary" sheetId="1" r:id="rId1"/></x:sheets></x:workbook>');
        $zip->addFromString('xl/_rels/workbook.xml.rels','<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Target="/xl/worksheets/ordinary.xml" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Id="rId1"'.($case==='fallback_external'?' TargetMode="External"':'').'/>'.($case==='fallback_duplicate_rel'?'<Relationship Id="rId1" Target="worksheets/ordinary.xml" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"/>':'').'</Relationships>');
    }
    if(in_array($case,['shared_over','reference_over','parts_sum_over'],true)) {
        $strings=$directory.'/shared.xml';$handle=fopen($strings,'wb');fwrite($handle,'<sst xmlns="'.$ns.'">');
        if($case==='parts_sum_over')xlsxBudgetRepeat($handle,'<!--'.str_repeat('a',4096).'-->',3072);
        elseif($case==='shared_over')xlsxBudgetRepeat($handle,'<si/>',100001);
        else {fwrite($handle,'<si><t>');xlsxBudgetRepeat($handle,str_repeat('a',1024),8192);fwrite($handle,'</t></si>');}
        fwrite($handle,'</sst>');fclose($handle);$zip->addFile($strings,'xl/sharedStrings.xml');
    }
    if(str_starts_with($case,'entries'))for($i=1;$i<($case==='entries_limit'?512:513);$i++)$zip->addFromString('ordinary-'.$i,'');
    if($case==='zip_comment')$zip->setArchiveComment("ordinary PK\x05\x06 comment");
    if($case==='archive_limit') {$padding=$directory.'/padding';file_put_contents($padding,'');$zip->addFile($padding,'padding');$zip->setCompressionName('padding',ZipArchive::CM_STORE);}
    $zip->close();$zip=null;
    if($case==='archive_limit') {
        $padding=$directory.'/padding';$handle=fopen($padding,'wb');ftruncate($handle,BulkTableIo::MAX_IMPORT_BYTES-filesize($path));fclose($handle);
        $zip=new ZipArchive();$zip->open($path,ZipArchive::CREATE|ZipArchive::OVERWRITE);$zip->addFile($part,$sheetName);$zip->addFile($padding,'padding');$zip->setCompressionName('padding',ZipArchive::CM_STORE);$zip->close();$zip=null;clearstatcache(true,$path);
        check(filesize($path)===BulkTableIo::MAX_IMPORT_BYTES,'The accepted archive fixture must sit exactly at the byte limit: '.filesize($path));
    }
    if($case==='archive_over') {$handle=fopen($path,'r+b');ftruncate($handle,BulkTableIo::MAX_IMPORT_BYTES+1);fclose($handle);}
    if($case==='invalid_directory')file_put_contents($path,str_repeat('ordinary',4));
    if($case==='invalid_directory_count') {
        $handle=fopen($path,'r+b');fseek($handle,-14,SEEK_END);fwrite($handle,pack('vv',0,0));fclose($handle);
    }
    if($case==='invalid_local') {$handle=fopen($path,'r+b');fwrite($handle,'NONE');fclose($handle);}
    if($case==='invalid_crc') {
        $handle=fopen($path,'r+b');fseek($handle,-22,SEEK_END);$end=fread($handle,22);$offset=unpack('V',substr($end,16,4))[1];
        fseek($handle,14);fwrite($handle,pack('V',0));fseek($handle,$offset+16);fwrite($handle,pack('V',0));fclose($handle);
    }
    if($case==='invalid_central') {
        $handle=fopen($path,'r+b');fseek($handle,-22,SEEK_END);$end=fread($handle,22);$offset=unpack('V',substr($end,16,4))[1];
        fseek($handle,$offset);fwrite($handle,'NONE');fclose($handle);
    }
    $sourceHash=hash_file('sha256',$path);
    $before=glob(sys_get_temp_dir().'/maccms-xlsx-*');$mode=libxml_use_internal_errors(false);
    $result=null;$error=null;
    try {$result=BulkTableIo::parseFile($path,'xlsx');}
    catch(RuntimeException|InvalidArgumentException $caught){$error=$caught;}
    $reject=str_ends_with($case,'_over')||str_starts_with($case,'invalid_')||str_starts_with($case,'duplicate_')||in_array($case,['doctype','doctype_utf16','doctype_utf32','decl_unsupported','empty_xml','row_mismatch','fallback_external','fallback_missing_id','fallback_duplicate_rel'],true);
    check(($error!==null)===$reject,'XLSX boundary result mismatch: '.$case.'; '.($error?get_class($error).': '.$error->getMessage():json_encode($result)));
    check(hash_file('sha256',$path)===$sourceHash,'XLSX parsing must leave the original source bytes intact');
    check(glob(sys_get_temp_dir().'/maccms-xlsx-*')===$before,'XLSX must clean its own private snapshot after success and failure');
    check(libxml_use_internal_errors()==false,'XLSX must restore the caller XML error mode');libxml_use_internal_errors($mode);
    if(!$reject) {
        check(is_array($result)&&isset($result['headers'],$result['rows']),'Accepted XLSX must return the import structure');
        if($case==='row_limit')check($result['rows']===[['name'=>'0']],'Sparse last allowed row must not be lost');
        if($case==='column_limit')check(count($result['headers'])===256&&$result['rows']===[['name'=>'0','last'=>'tail']],'Sparse last allowed column must preserve both values');
        if($case==='padding_limit')check(count($result['rows'])===390&&count($result['rows'][389])===256,'Padded matrix fits its actual budget');
        if($case==='cells_limit')check(count($result['rows'])===999&&count($result['rows'][998])===100,'Full input cell budget remains usable');
        if(in_array($case,['text_limit','utf16_text_limit'],true))check(strlen($result['rows'][0]['name'])===8388608,'Full cell text limit is accepted');
        if($case==='cdata_literal')check($result['rows']===[['name'=>'ordinary <!DOCTYPE note>']],'Literal declaration-like cell text must remain ordinary data');
        if($case==='fallback')check($result['rows']===[['name'=>'0']],'Namespaced workbook and reordered relationship attributes resolve the actual internal sheet');
    }
    echo json_encode(['result'=>'passed','case'=>$case,'checks'=>$checks,'peak_bytes'=>memory_get_peak_usage(true),'max_rss_kib'=>getrusage()['ru_maxrss']],JSON_THROW_ON_ERROR)."\n";
} finally {if(is_resource($sheet))fclose($sheet);if($zip!==null)$zip->close();audit_remove_temp($directory);}
