<?php
/** Real locally installed SDKs. Upyun talks only to an isolated loopback HTTP fixture. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require dirname(__DIR__).'/extend/upyun/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\StoragePublicUrl;
$bucket='storage-fixture';$key='upload/vod/object.txt';
foreach ([[],['endpoint'=>'https://s3.fixture.invalid'],
    ...array_map(fn($base)=>['basepath'=>$base,'domain'=>'https://cdn.fixture.invalid'],['objects','/objects/','/','0'])] as $extra) {
    $settings=array_replace(['bucket'=>$bucket,'region'=>'us-east-1'],$extra);$policy=StoragePublicUrl::configured('s3',$settings);
    $options=['region'=>'us-east-1','version'=>'2006-03-01','credentials'=>['key'=>'fixture','secret'=>'fixture']];
    if(isset($extra['endpoint'])){$options['endpoint']=$extra['endpoint'];$options['use_path_style_endpoint']=true;}
    $actualKey=!empty($extra['basepath'])?rtrim($extra['basepath'],'/').'/'.$key:$key;
    $expected=isset($extra['domain'])?'https://cdn.fixture.invalid/'.$bucket.'/'.$actualKey:(new Aws\S3\S3Client($options))->getObjectUrl($bucket,$actualKey);
    check($policy->expected($key)===$expected && $policy->accepts($expected,$key),'Public URL policy differs from the actual S3 URL constructor');
}
// Real AWS serialization/signing/response parsing with an in-process HTTP transport (no external requests).
foreach ([200,201,204,202] as $status) {
    $calls=0;
    $client=new Aws\S3\S3Client(['region'=>'us-east-1','version'=>'2006-03-01','retries'=>0,
        'credentials'=>['key'=>'fixture','secret'=>'fixture'],
        'http_handler'=>static function ($request,array $options) use($status,&$calls) {
            $calls++;$response=new GuzzleHttp\Psr7\Response($status,['ETag'=>'"fixture-etag"']);
            if(isset($options['on_stats']))$options['on_stats'](new GuzzleHttp\TransferStats($request,$response,0.001));
            return new GuzzleHttp\Promise\FulfilledPromise($response);
        }]);
    $result=$client->putObject(['Bucket'=>$bucket,'Key'=>$key,'Body'=>'fixture body','ACL'=>'public-read']);
    check($calls===1 && $result instanceof Aws\ResultInterface && $result['@metadata']['statusCode']===$status,
        'Actual AWS PutObject result lost its integer completion status');
    check(in_array($result['@metadata']['statusCode'],[200,201,204],true)===($status!==202),
        'Strict S3 completion check accepted a pending response');
}
$temp=audit_temp_dir('storage-sdk');
file_put_contents($temp.'/router.php', <<<'ROUTER'
<?php
$code=(int)basename(parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH));
http_response_code($code);
if ($code===307)header('Location: http://127.0.0.1:1/must-not-follow');
header('Content-Type: application/octet-stream');
ROUTER);
$socket=stream_socket_server('tcp://127.0.0.1:0',$errno,$error);$address=stream_socket_get_name($socket,false);fclose($socket);
$process=proc_open([PHP_BINARY,'-S',$address,$temp.'/router.php'],[0=>['pipe','r'],1=>['file',$temp.'/server.log','a'],2=>['file',$temp.'/server.log','a']],$pipes,$temp);fclose($pipes[0]);
try {
    $ready=false;for($try=0;$try<100;$try++){if($probe=@stream_socket_client('tcp://'.$address,$errno,$error,.05)){fclose($probe);$ready=true;break;}usleep(10000);}
    check($ready,'SDK loopback fixture did not start');
    $configuration=new Upyun\Config('fixture-bucket','fixture-user','fixture-password');
    $configuration->useSsl=false;Upyun\Config::$restApiEndPoint=$address;
    foreach([200,201,204,202,307,500] as $code) {
        $stream=fopen('php://temp','r+');fwrite($stream,'fixture upload bytes');rewind($stream);
        try {$response=(new Upyun\Uploader($configuration))->upload('/'.$code,$stream,[],false);$error=null;}
        catch(Throwable $caught){$response=null;$error=$caught;}
        finally {if(is_resource($stream))fclose($stream);}
        if(in_array($code,[307,500],true))check($error!==null,'Actual Upyun SDK accepted a redirect/server failure');
        else {
            check($response instanceof Psr\Http\Message\ResponseInterface && $response->getStatusCode()===$code,'Actual Upyun uploader lost its raw HTTP response');
            check(in_array($response->getStatusCode(),[200,201,204],true)===($code!==202),'Strict branch confused accepted/pending completion');
        }
    }
    echo "Storage actual SDK contracts: $checks checks passed on PHP ".PHP_VERSION."\n";
} finally {proc_terminate($process);proc_close($process);audit_remove_temp($temp);}
