<?php
/** Report source records accurately after skipped blank rows, sparse XLSX coordinates and multiline CSV cells. */
declare(strict_types=1);
require dirname(__DIR__).'/application/common/util/BulkTableIo.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\BulkTableIo;
$directory=audit_temp_dir('import-row-numbers');
try{
    $path=$directory.'/ordinary.csv';
    foreach(["\n","\r\n","\r"]as $eol){
        $source=implode($eol,['name,note','','First,"inside'.$eol.'one cell"',',','Second,ordinary','']);
        file_put_contents($path,$source);
        $expected=['headers'=>['name','note'],'rows'=>[['name'=>'First','note'=>'inside'.$eol.'one cell'],['name'=>'Second','note'=>'ordinary']]];
        check(BulkTableIo::parseCsv($path)===$expected,'Default CSV result contract is unchanged');
        check(BulkTableIo::parseCsv($path,true)===$expected+['row_numbers'=>[3,5]],'CSV source records survive skipped blanks and cell newlines');
        foreach(['csv','txt']as $extension){check(BulkTableIo::parseFile($path,$extension,true)===$expected+['row_numbers'=>[3,5]],'Dispatch preserves requested CSV row metadata');}
    }
    foreach(['',"name,note\n", "name,note\n\n,\n"]as $source){
        file_put_contents($path,$source);$result=BulkTableIo::parseCsv($path,true);
        check($result['rows']===[] && $result['row_numbers']===[],'Empty or header-only CSV has no fabricated data row numbers');
    }
    $path=$directory.'/ordinary.xlsx';
    $namespace='http://schemas.openxmlformats.org/spreadsheetml/2006/main';
    $rows=[1=>['name','note'],3=>['First','ordinary'],4=>['',''],8=>['Second','0']];
    foreach([false,true]as $empty){
        $xml='<worksheet xmlns="'.$namespace.'"><sheetData>';
        if(!$empty){
            foreach($rows as $row=>$values){
                $xml.='<row r="'.$row.'">';
                foreach($values as $column=>$value){$xml.='<c r="'.BulkTableIo::colName($column).$row.'" t="inlineStr"><is><t>'.BulkTableIo::xmlEsc($value).'</t></is></c>';}
                $xml.='</row>';
            }
        }
        $xml.='</sheetData></worksheet>';
        $zip=new ZipArchive();check($zip->open($path,ZipArchive::CREATE|ZipArchive::OVERWRITE)===true,'XLSX row fixture opens');
        check($zip->addFromString('xl/worksheets/sheet1.xml',$xml) && $zip->close(),'XLSX row fixture is stored');
        $expected=$empty?['headers'=>[],'rows'=>[]]:['headers'=>['name','note'],'rows'=>[['name'=>'First','note'=>'ordinary'],['name'=>'Second','note'=>'0']]];
        check(BulkTableIo::parseXlsx($path)===$expected,'Default XLSX contract retains compact data rows');
        check(BulkTableIo::parseXlsx($path,true)===$expected+['row_numbers'=>$empty?[]:[3,8]],'XLSX original coordinates survive sparse and blank rows');
        check(BulkTableIo::parseFile($path,'xlsx',true)===$expected+['row_numbers'=>$empty?[]:[3,8]],'Dispatch preserves requested XLSX row metadata');
    }
    printf("Import source row numbers: %d checks on PHP %s.\n",$checks,PHP_VERSION);
}finally{audit_remove_temp($directory);}
