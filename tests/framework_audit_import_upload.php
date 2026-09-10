<?php
/** Actual TP8 upload objects and multipart transport; all files remain in private fixture directories. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\ImportUpload;
use app\common\util\BulkTableIo;
use think\file\UploadedFile;
$directory=audit_temp_dir('import-upload');$process=null;
try {
    $path=$directory.'/ordinary';file_put_contents($path,"name,type_id\nOrdinary,1\n");
    foreach(['csv','CSV','txt','xlsx']as $extension){
        $file=new UploadedFile($path,'ordinary.'.$extension,'application/octet-stream',UPLOAD_ERR_OK,true);
        check(ImportUpload::inspect($file,['csv','txt','xlsx'],BulkTableIo::MAX_IMPORT_BYTES)===['path'=>$path,'extension'=>strtolower($extension)],'Supported TP8 upload methods preserve the temporary path');
    }
    $invalid=[null,[],new stdClass(),new think\File($path),new UploadedFile($path,'ordinary.csv'),
        new UploadedFile($path,'ordinary.csv','text/csv',UPLOAD_ERR_PARTIAL,true)];
    foreach(['','ordinary','ordinary.xlsm','ordinary.php',str_repeat('x',1021).'.csv',"ordinary\0.csv"]as $name){$invalid[]=new UploadedFile($path,$name,null,0,true);}
    symlink($path,$directory.'/link');$invalid[]=new UploadedFile($directory.'/link','ordinary.csv',null,0,true);
    foreach($invalid as $file){
        $rejected=false;try{ImportUpload::inspect($file,['csv','txt','xlsx'],BulkTableIo::MAX_IMPORT_BYTES);}catch(InvalidArgumentException $e){$rejected=true;}
        check($rejected && is_file($path),'Malformed/failed/untrusted upload is rejected without removing the source');
    }
    $large=$directory.'/large';$handle=fopen($large,'wb');ftruncate($handle,BulkTableIo::MAX_IMPORT_BYTES);fclose($handle);
    check(ImportUpload::inspect(new UploadedFile($large,'ordinary.csv',null,0,true),['csv'],BulkTableIo::MAX_IMPORT_BYTES)['path']===$large,'Exact raw byte limit is accepted for subsequent bounded parsing');
    $handle=fopen($large,'ab');fwrite($handle,'x');fclose($handle);clearstatcache(true,$large);
    $rejected=false;try{ImportUpload::inspect(new UploadedFile($large,'ordinary.csv',null,0,true),['csv'],BulkTableIo::MAX_IMPORT_BYTES);}catch(InvalidArgumentException $e){$rejected=true;}
    check($rejected,'One byte beyond the raw limit is rejected');

    $socket=stream_socket_server('tcp://127.0.0.1:0',$errno,$error);check($socket!==false,'Private HTTP test socket is available');
    $address=stream_socket_get_name($socket,false);fclose($socket);
    $process=proc_open([PHP_BINARY,'-d','upload_max_filesize=24M','-d','post_max_size=25M','-d','memory_limit=128M','-S',$address,__DIR__.'/fixtures/import_upload_http.php'],
        [0=>['pipe','r'],1=>['file',$directory.'/http.log','a'],2=>['file',$directory.'/http.log','a']],$pipes);fclose($pipes[0]);
    check(is_resource($process),'Actual multipart server starts');
    $ready=false;for($attempt=0;$attempt<100;$attempt++){$probe=@stream_socket_client('tcp://'.$address,$errno,$error,0.05);if($probe){fclose($probe);$ready=true;break;}usleep(20000);}
    check($ready,'Actual multipart server is ready');
    $send=static function(array $fields)use($address):array {
        $curl=curl_init('http://'.$address.'/');curl_setopt_array($curl,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$fields,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>20]);
        $body=curl_exec($curl);$status=curl_getinfo($curl,CURLINFO_RESPONSE_CODE);curl_close($curl);
        check($body!==false && $status===200,'Multipart response is controlled');return json_decode($body,true,512,JSON_THROW_ON_ERROR);
    };
    foreach(['csv','CSV','txt']as $extension){
        $res=$send(['file'=>new CURLFile($path,'application/octet-stream','ordinary.'.$extension)]);
        check($res===['ok'=>true,'uploaded'=>true,'rows'=>[['name'=>'Ordinary','type_id'=>'1']],'row_numbers'=>[2]],'Actual PHP-owned multipart temporary file is accepted and parsed');
    }
    foreach([[],['file[]'=>new CURLFile($path,'text/csv','ordinary.csv')],['file'=>new CURLFile($path,'text/csv','ordinary.exe')],['file'=>new CURLFile($large,'text/csv','ordinary.csv')]]as $fields){
        check($send($fields)===['ok'=>false],'Missing, multiple, unsupported or oversized real multipart upload is controlled');
    }
    printf("Import upload boundary: %d checks on PHP %s.\n",$checks,PHP_VERSION);
} finally {
    if(is_resource($process)){proc_terminate($process);proc_close($process);}audit_remove_temp($directory);
}
