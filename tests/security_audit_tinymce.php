<?php
/** TinyMCE response status/body and real HTTP upload protocol; no application entry point. */
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_test_helpers.php';
$worker=__DIR__.'/fixtures/security_audit_tinymce_worker.php';
$success=['success','success-string','success-relative'];
$failure=['failure','failure-with-file','failure-string','failure-false','failure-no-info','failure-array-info',
    'failure-object-info','failure-long-info','failure-binary-info'];
$invalid=['missing-file','empty-file','whitespace-file','array-file','object-file','number-file','null-data',
    'string-data','object-data','binary-file','control-file','long-file','bad-status-array','bad-status-number','bad-status-true'];
foreach (array_merge($success,$failure,$invalid) as $case) {
    $process=proc_open([PHP_BINARY,$worker,$case],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
    fclose($pipes[0]);$output=stream_get_contents($pipes[1]);$errors=stream_get_contents($pipes[2]);
    fclose($pipes[1]);fclose($pipes[2]);
    check(proc_close($process)===0 && $errors==='', 'Adapter emitted a PHP warning/error: '.$case.' '.$errors);
    $response=json_decode($output,true,512,JSON_THROW_ON_ERROR);
    $data=json_decode($response['body'],true,512,JSON_THROW_ON_ERROR);
    $expected=in_array($case,$success,true) ? 200 : (in_array($case,$failure,true)?400:500);
    check($response['status']===$expected,'Incorrect TinyMCE status: '.$case);
    check($expected===200 ? is_string($data['location']??null) && !isset($data['error'])
        : !array_key_exists('location',$data) && is_string($data['error']['message']??null),
        'Failure exposed a successful location or lost JSON error: '.$case);
    if($case==='success-string')check($data['location']==='https://cdn.example.invalid/中文.png?signature=a%2Fb','Success URL was changed');
    if($case==='failure-binary-info')check($data['error']['message']==="invalid\u{fffd}",'Invalid UTF-8 error did not produce valid JSON');
}

$temporary=audit_temp_dir('tinymce-http');
$server=null;
try {
    $socket=stream_socket_server('tcp://127.0.0.1:0',$errno,$error);
    if(!$socket)throw new RuntimeException($error);
    $address=stream_socket_get_name($socket,false);fclose($socket);
    $server=proc_open([PHP_BINARY,'-S',$address,$worker],[0=>['pipe','r'],1=>['file',$temporary.'/http.log','a'],2=>['file',$temporary.'/http.log','a']],$pipes,$temporary);
    fclose($pipes[0]);
    for($i=0;$i<100;$i++) {
        $connection=@stream_socket_client('tcp://'.$address,$errno,$error,0.1);
        if($connection){fclose($connection);break;}
        usleep(50000);
    }
    $http=static function(string $case,?array $file=null) use($address): array {
        $options=['ignore_errors'=>true,'timeout'=>10];
        $query=['case'=>$case];
        if(str_starts_with($case,'upload-')) {
            $query+=['from'=>'tinymce','flag'=>'vod_editor'];
            $boundary='tiny-audit-'.bin2hex(random_bytes(8));
            $body=$file===null ? '' : '--'.$boundary."\r\nContent-Disposition: form-data; name=\"file\"; filename=\"".$file[0]."\"\r\nContent-Type: image/png\r\n\r\n".$file[1]."\r\n";
            $body.='--'.$boundary."--\r\n";
            $options+=['method'=>'POST','header'=>"X-CSRF-Token: tinymce-protocol-csrf\r\nContent-Type: multipart/form-data; boundary=".$boundary,'content'=>$body];
        }
        $body=file_get_contents('http://'.$address.'/?'.http_build_query($query),false,stream_context_create(['http'=>$options]));
        $headers=[];
        foreach($http_response_header as $line) {
            if(preg_match('~^HTTP/\S+ (\d+)~',$line,$match))$headers['status']=(int)$match[1];
            elseif(str_contains($line,':')){[$key,$value]=explode(':',$line,2);$headers[strtolower($key)]=trim($value);}
        }
        try { $data=json_decode($body,true,512,JSON_THROW_ON_ERROR); }
        catch (\JsonException $error) { throw new RuntimeException('Invalid TinyMCE JSON: '.$body, 0, $error); }
        return [$headers,$data];
    };
    foreach(['success'=>200,'failure'=>400,'failure-with-file'=>400,'failure-binary-info'=>400,'missing-file'=>500] as $case=>$expected) {
        [$headers,$data]=$http($case);
        check($headers['status']===$expected,'HTTP did not transmit adapter status: '.$case);
        check($headers['content-type']==='application/json; charset=utf-8' && $headers['x-content-type-options']==='nosniff','JSON headers missing');
        check($expected===200 ? isset($data['location']) : !array_key_exists('location',$data),'HTTP failure leaked location');
    }
    $image=imagecreatetruecolor(32,16);imagefill($image,0,0,imagecolorallocate($image,30,160,250));
    ob_start();imagepng($image);$png=ob_get_clean();
    [$headers,$data]=$http('upload-success',['test.png',$png]);
    check($headers['status']===200 && is_string($data['location']??null),'Real Upload pipeline lost TinyMCE success protocol');
    check($headers['x-audit-unchanged']==='no' && $headers['x-audit-annex-count']==='1','Real upload did not store its image/Annex');
    foreach(['upload-missing'=>null,'upload-forbidden'=>['test.exe',$png]] as $case=>$file) {
        [$headers,$data]=$http($case,$file);
        check($headers['status']===400 && !array_key_exists('location',$data) && isset($data['error']['message']), 'Real rejected upload escaped as a 200/invalid response');
        check($headers['x-audit-unchanged']==='yes' && $headers['x-audit-annex-count']==='0','Rejected upload changed files or DB');
    }
} finally {
    if(is_resource($server)){proc_terminate($server);proc_close($server);}
    audit_remove_temp($temporary);
}
printf("TinyMCE response: %d checks passed on PHP %s\n",$checks,PHP_VERSION);
