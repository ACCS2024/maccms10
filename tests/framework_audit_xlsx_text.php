<?php
/** Ordinary XLSX strings from real ZipArchive and XML parsing, including rich text and phonetic annotations. */
declare(strict_types=1);
require dirname(__DIR__).'/application/common/util/BulkTableIo.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\BulkTableIo;
$directory=audit_temp_dir('xlsx-text');
$ns='http://schemas.openxmlformats.org/spreadsheetml/2006/main';
$values=['name','note','number','flag','中文 😀 & "标题"'," leading \ntrailing ",'0','ordinary title','漢字','repeated'];
function xlsxTextFragment(string $value,bool $rich,bool $phonetic=false):string {
    if ($rich) {
        // Split at an ASCII space so every text run remains independently valid UTF-8.
        $space=strpos($value,' ');$parts=$space===false?[$value]:[substr($value,0,$space+1),substr($value,$space+1)];
        $xml='';
        foreach($parts as $part)$xml.='<r><rPr><b/></rPr><t xml:space="preserve">'.BulkTableIo::xmlEsc($part).'</t></r>';
    } else { $xml='<t xml:space="preserve">'.BulkTableIo::xmlEsc($value).'</t>'; }
    if($phonetic)$xml.='<rPh sb="0" eb="2"><t>かんじ</t></rPh><phoneticPr fontId="0"/>';
    return $xml;
}
try {
    foreach(['shared','inline','mixed'] as $mode) {
        foreach([false,true] as $rich) {
            foreach([false,true] as $prefixed) {
                $shared='<sst xmlns="'.$ns.'" count="12" uniqueCount="10">';
                foreach($values as $i=>$value)$shared.='<si>'.xlsxTextFragment($value,$rich,$i===8).'</si>';
                $shared.='</sst>';
                $grid=[[0,1,2,3],[4,5,'number:12.50','boolean:1'],[7,6,'number:0','boolean:0'],[8,9,'missing','missing'],[9,9,'missing','missing']];
                $sheet='<worksheet xmlns="'.$ns.'"><sheetData>';
                foreach($grid as $row=>$cells) {
                    $sheet.='<row r="'.($row+1).'">';
                    foreach($cells as $col=>$value) {
                        $reference=BulkTableIo::colName($col).($row+1);
                        if($value==='missing')continue;
                        if(is_string($value)) {
                            [$type,$number]=explode(':',$value);
                            $sheet.='<c r="'.$reference.'"'.($type==='boolean'?' t="b"':'').'><v>'.$number.'</v></c>';
                        } elseif($mode==='shared'||($mode==='mixed'&&$col%2===0)) {
                            $sheet.='<c r="'.$reference.'" t="s"><v>'.$value.'</v></c>';
                        } else {
                            $sheet.='<c r="'.$reference.'" t="inlineStr"><is>'.xlsxTextFragment($values[$value],$rich,$value===8).'</is></c>';
                        }
                    }
                    $sheet.='</row>';
                }
                $sheet.='</sheetData></worksheet>';
                if($prefixed) {
                    foreach(['shared','sheet'] as $variable) {
                        $$variable=str_replace('xmlns="'.$ns.'"','xmlns:x="'.$ns.'"',$$variable);
                        $$variable=preg_replace('/<(\/?)([A-Za-z][A-Za-z0-9]*)/','<$1x:$2',$$variable);
                    }
                }
                $path=$directory.'/ordinary.xlsx';$zip=new ZipArchive();
                check($zip->open($path,ZipArchive::CREATE|ZipArchive::OVERWRITE)===true,'Ordinary XLSX fixture opens');
                check($zip->addFromString('xl/worksheets/sheet1.xml',$sheet),'Ordinary worksheet stored');
                if($mode!=='inline')check($zip->addFromString('xl/sharedStrings.xml',$shared),'Ordinary shared table stored');
                check($zip->close(),'Ordinary XLSX fixture closes');
                $result=BulkTableIo::parseFile($path,'xlsx');
                check($result['headers']===['name','note','number','flag'],'Shared/inline string headers are readable: '.json_encode([$mode,$rich,$prefixed,$result]));
                check($result['rows']===[
                    ['name'=>$values[4],'note'=>$values[5],'number'=>'12.50','flag'=>'1'],
                    ['name'=>'ordinary title','note'=>'0','number'=>'0','flag'=>'0'],
                    ['name'=>'漢字','note'=>'repeated','number'=>'','flag'=>''],
                    ['name'=>'repeated','note'=>'repeated','number'=>'','flag'=>''],
                ],'Text runs, whitespace, zero values and repeated references survive without phonetic annotations');
            }
        }
    }
    echo 'XLSX ordinary text: '.$checks.' checks on PHP '.PHP_VERSION."\n";
} finally { audit_remove_temp($directory); }
