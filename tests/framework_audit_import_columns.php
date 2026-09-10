<?php
/** Reject ambiguous mapping before any caller can save a partially parsed file. */
declare(strict_types=1);
require dirname(__DIR__).'/application/common/util/BulkTableIo.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\BulkTableIo;
use app\common\util\ImportColumnException;
$directory=audit_temp_dir('import-columns');
try {
    $path=$directory.'/ordinary.csv';
    foreach([
        ["id,name,name\n7,First,Second\n",1,3],
        ["id,name, name \n7,First,Second\n",1,3],
        ["0,0\nFirst,Second\n",1,2],
        ["id,,name\n7,Ordinary note,First\n",2,2],
        ["id,name\n7,First,Ordinary note\n",2,3],
        ["id,name,content\n7,First\n",2,3],
        ["id,name\n7\n",2,2],
        ["id,name\n7,First\n8,Second,Note\n",3,3],
        ["id,name\n7,First\n\n8,Second,Note\n",4,3],
        ["id,name\n7,\"First\nmultiline\"\n8,Second,Note\n",3,3],
        ["id,,name\n7, ,First\n",2,2],
        [",\nFirst,Second\n",1,1],
    ]as [$source,$row,$column]){
        file_put_contents($path,$source);$hash=hash_file('sha256',$path);
        foreach([false,true]as $metadata){
            $caught=null;try{BulkTableIo::parseCsv($path,$metadata);}catch(ImportColumnException $e){$caught=$e;}
            check($caught!==null && $caught->row===$row && $caught->column===$column,'CSV ambiguity has exact safe logical row/column coordinates');
            check(hash_file('sha256',$path)===$hash,'Rejected CSV source is left unchanged');
        }
    }
    foreach([
        ["id,name,content\n7,First,\n",['id'=>'7','name'=>'First','content'=>'']],
        ["id,,name\n7,,First\n",['id'=>'7','name'=>'First']],
        ["id,name\n7,First,,\n",['id'=>'7','name'=>'First']],
        ["id,name\n\n7,First\n,,\n",['id'=>'7','name'=>'First']],
        ["0,00\nFirst,Second\n",[0=>'First','00'=>'Second']],
        ["name,Name\nFirst,Second\n",['name'=>'First','Name'=>'Second']],
    ]as [$source,$expected]){file_put_contents($path,$source);check(BulkTableIo::parseCsv($path)['rows']===[$expected],'Explicit empty cells and empty spacer columns retain their data semantics');}

    $path=$directory.'/ordinary.xlsx';
    $make=static function(array $grid)use($path):void {
        $xml='<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>';
        foreach($grid as $row=>$values){$xml.='<row r="'.$row.'">';foreach($values as $column=>$value){$xml.='<c r="'.BulkTableIo::colName($column).$row.'" t="inlineStr"><is><t>'.BulkTableIo::xmlEsc($value).'</t></is></c>';}$xml.='</row>';}
        $xml.='</sheetData></worksheet>';$zip=new ZipArchive();$zip->open($path,ZipArchive::CREATE|ZipArchive::OVERWRITE);$zip->addFromString('xl/worksheets/sheet1.xml',$xml);$zip->close();
    };
    foreach([
        [[1=>['id','name','name'],2=>['7','First','Second']],1,3],
        [[1=>['id','name',' name '],2=>['7','First','Second']],1,3],
        [[1=>['id','','name'],8=>['7','Ordinary note','First']],8,2],
        [[1=>['id','name'],8=>['7','First','Ordinary note']],8,3],
        [[1=>['id','name'],2=>['7','First'],8=>['8','Second','Note']],8,3],
        [[1=>['',''],2=>['First','Second']],1,1],
    ]as [$grid,$row,$column]){
        $make($grid);$hash=hash_file('sha256',$path);
        foreach([false,true]as $metadata){
            $caught=null;try{BulkTableIo::parseXlsx($path,$metadata);}catch(ImportColumnException $e){$caught=$e;}
            check($caught!==null && $caught->row===$row && $caught->column===$column,'XLSX ambiguity has actual worksheet coordinates');
            check(hash_file('sha256',$path)===$hash,'Rejected XLSX source is unchanged');
        }
    }
    foreach([
        [[1=>['id','name','content'],8=>['7','First']],['id'=>'7','name'=>'First','content'=>'']],
        [[1=>[0=>'id',2=>'name'],8=>[0=>'7',2=>'First']],['id'=>'7','name'=>'First']],
        [[1=>['id','name'],8=>['7','First','']],['id'=>'7','name'=>'First']],
    ]as [$grid,$expected]){$make($grid);check(BulkTableIo::parseXlsx($path,true)['rows']===[$expected],'Omitted XLSX cells represent normal blank cells and empty spacers are permitted');}
    printf("Import column mapping: %d checks on PHP %s.\n",$checks,PHP_VERSION);
}finally{audit_remove_temp($directory);}
