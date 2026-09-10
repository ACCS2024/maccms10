<?php
/** Real admin export method, ORM and CSV/XLSX writers; child processes preserve download + exit behavior. */
declare(strict_types=1);
require dirname(__DIR__) . '/vendor/autoload.php';
require __DIR__ . '/fixtures/security_audit_test_helpers.php';
use app\common\util\BulkTableIo;
use think\facade\Db;

set_exception_handler(static function (Throwable $error): void {
    fwrite(STDERR, get_class($error) . ': ' . $error->getMessage() . "\n");
    exit(1);
});

if (($argv[1] ?? '') === '--download') {
    $format = $argv[2]; $case = $argv[3];
    $configuration = ['default'=>'audit', 'connections'=>['audit'=>[
        'type'=>'sqlite', 'database'=>':memory:', 'prefix'=>'audit_export_', 'fields_cache'=>false,
    ]]];
    $manager = new think\DbManager(); $manager->setConfig($configuration);
    think\Container::getInstance()->instance('think\DbManager', $manager);
    Db::execute('CREATE TABLE audit_export_vod (vod_id INTEGER PRIMARY KEY, vod_name TEXT, vod_note TEXT)');
    $rows = [
        ['vod_id'=>1, 'vod_name'=>'普通标题', 'vod_note'=>''],
        ['vod_id'=>2, 'vod_name'=>'标题, "引号"', 'vod_note'=>"two\nlines"],
        ['vod_id'=>3, 'vod_name'=>'A&B <tag>', 'vod_note'=>'C:\folder\file'],
        ['vod_id'=>4, 'vod_name'=>'0', 'vod_note'=>null],
        ['vod_id'=>5, 'vod_name'=>'emoji 😀', 'vod_note'=>' trailing '],
    ];
    Db::name('Vod')->insertAll($rows);
    $parameters = ['format'=>$format]; $where = [];
    switch ($case) {
        case 'limit': $parameters['max']=2; break;
        case 'zero': $parameters['max']=0; break;
        case 'filtered': $where=[['vod_id', 'in', [1,3]]]; break;
        case 'empty': $where=[['vod_id', '=', 999999]]; break;
        case 'cap':
            $parameters['max']=BulkTableIo::MAX_EXPORT_ROWS+1000;
            $extra=[];
            for ($id=6; $id<=BulkTableIo::MAX_EXPORT_ROWS+2; $id++) {
                $extra[]=['vod_id'=>$id,'vod_name'=>'row '.$id,'vod_note'=>''];
                if (count($extra)===250) { Db::name('Vod')->insertAll($extra); $extra=[]; }
            }
            if ($extra) { Db::name('Vod')->insertAll($extra); }
            break;
    }
    $controller = (new ReflectionClass(app\admin\controller\Base::class))->newInstanceWithoutConstructor();
    $controller->base_export($parameters, 'vod', $where);
    throw new RuntimeException('Download did not terminate its response');
}

$temporary = audit_temp_dir('bulk-export');
try {
    foreach (['csv','xlsx'] as $format) {
        foreach (['default','limit','zero','filtered','empty','cap'] as $case) {
            $file=$temporary.'/result.'.$format;
            $process=proc_open([PHP_BINARY,'-d','error_reporting=-1','-d','display_errors=stderr',__FILE__,'--download',$format,$case],
                [0=>['file','/dev/null','r'],1=>['file',$file,'w'],2=>['pipe','w']],$pipes);
            check(is_resource($process),'Could not start the export process');
            $errors=stream_get_contents($pipes[2]); fclose($pipes[2]);
            check(proc_close($process)===0 && $errors==='', 'Real '.$format.' export failed: '.$errors);
            if ($format==='csv') {
                $handle=fopen($file,'rb'); check(fread($handle,3)==="\xEF\xBB\xBF",'CSV omitted its UTF-8 BOM');
                $rows=[];
                while (($row=fgetcsv($handle,null,',','"','\\'))!==false) { $rows[]=$row; }
                fclose($handle);
            } else {
                $archive=new ZipArchive(); check($archive->open($file)===true,'XLSX output is not a ZIP archive');
                $xml=$archive->getFromName('xl/worksheets/sheet1.xml'); $archive->close();
                check(is_string($xml),'XLSX worksheet missing');
                $document=new DOMDocument(); check($document->loadXML($xml,LIBXML_NONET),'XLSX worksheet XML invalid');
                $xpath=new DOMXPath($document); $xpath->registerNamespace('s','http://schemas.openxmlformats.org/spreadsheetml/2006/main');
                check((int)$xpath->evaluate('count(//s:sheetData/s:row/s:c[not(@t="inlineStr")])')===0,'XLSX unexpectedly changed cell types');
                $rows=[];
                foreach ($xpath->query('//s:sheetData/s:row') as $node) {
                    $row=[];
                    foreach ($xpath->query('s:c',$node) as $cell) {
                        $row[]=$xpath->evaluate('string(s:is/s:t)',$cell);
                    }
                    $rows[]=$row;
                }
            }
            check(array_shift($rows)===['vod_id','vod_name','vod_note'],'Export lost actual database field order');
            $expected=match($case) {
                'limit'=>[5,4], 'zero'=>[5], 'filtered'=>[3,1], 'empty'=>[],
                'cap'=>range(BulkTableIo::MAX_EXPORT_ROWS+2,3,-1), default=>[5,4,3,2,1],
            };
            check(array_map('intval',array_column($rows,0))===$expected,'Export changed filtering, descending order or row limits');
            if ($case==='default') {
                check($rows[0]===['5','emoji 😀',' trailing '], 'Unicode or whitespace changed');
                check($rows[1]===['4','0',''], 'Zero text or nullable cells changed');
                check($rows[2]===['3','A&B <tag>','C:\folder\file'], 'XML characters or backslashes changed');
                check($rows[3]===['2','标题, "引号"',"two\nlines"], 'Quoted or multiline values changed');
            }
        }
    }
    echo 'Admin bulk export: '.$checks.' checks passed on PHP '.PHP_VERSION."\n";
} finally { audit_remove_temp($temporary); }
