<?php
/** Actual request binding, explicit proxy policy, and HTTP headers from a loopback server. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require dirname(__DIR__).'/vendor/topthink/framework/src/helper.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
require dirname(__DIR__).'/application/common.php';
use app\common\util\ClientIp;
use think\facade\Config;

$temporary=audit_temp_dir('client-ip');$server=null;
try {
    mkdir($temporary.'/application');
    copy(dirname(__DIR__).'/application/provider.php',$temporary.'/application/provider.php');
    $app=new \app\MacApp($temporary);
    check($app->make('request') instanceof \app\Request,'The production binding must use the common IP policy');
    $app->env->set(['CLIENT_IP_TRUSTED_PROXIES'=>'127.0.0.1','CLIENT_IP_FORWARDED_HEADER'=>'cf-connecting-ip']);
    Config::load(dirname(__DIR__).'/config/client_ip.php','client_ip');
    $configured=(new \app\Request())->withServer(['REMOTE_ADDR'=>'127.0.0.1','HTTP_CF_CONNECTING_IP'=>'8.8.8.8']);
    check($configured->ip()==='8.8.8.8','The shipped configuration must load the documented environment variables');
    foreach (['127.0.0.1','10.0.0.2','192.168.1.2','8.8.8.8','::1','2001:db8::123','::ffff:192.0.2.4'] as $peer) {
        foreach (['x-forwarded-for','cf-connecting-ip','x-real-ip','ali-cdn-real-ip'] as $header) {
            check(ClientIp::resolve($peer,'9.9.9.9',[],$header)===$peer,'Untrusted peer headers cannot replace a public, private, loopback or IPv6 peer');
        }
    }
    foreach ([null,[],['127.0.0.1'],true,1,'','1.0.1.junk','0127.0.0.1','127.0.0.1:80','[::1]','fe80::1%eth0',"127.0.0.1\n"] as $peer) {
        check(ClientIp::resolve($peer,'8.8.8.8',['127.0.0.1'])==='0.0.0.0','An invalid socket peer never delegates identity to a header');
    }
    $trust=['127.0.0.1','10.16.0.0/12','2001:db8:1234::/48'];
    foreach ([['8.8.8.8','8.8.8.8'],['9.9.9.9, 8.8.8.8','8.8.8.8'],
        ['invalid client prefix, 8.8.8.8','8.8.8.8'],['8.8.8.8, 10.20.0.2','8.8.8.8'],
        ['9.9.9.9, 192.0.2.9, 10.20.0.2','192.0.2.9'],['8.8.8.8, 2001:db8:1234::2','8.8.8.8'],
        ['2001:0db8:9999:0000:0000:0000:0000:0001, 10.20.0.2','2001:db8:9999::1'],
        ['10.20.0.3, 10.20.0.2','10.20.0.3'],["\t8.8.8.8 \t",'8.8.8.8'],
        ['8.8.8.8, ','127.0.0.1'],['8.8.8.8, invalid','127.0.0.1'],['8.8.8.8, [::1]','127.0.0.1']] as [$value,$expected]) {
        check(ClientIp::resolve('127.0.0.1',$value,$trust)===$expected,'Forwarded chains must resolve from the immediate peer toward the first untrusted client');
    }
    foreach ([null,[],true,17,'',str_repeat('1',8193),"8.8.8.8\r\nX: 1",'8.8.8.8:443'] as $header) {
        check(ClientIp::resolve('127.0.0.1',$header,$trust)==='127.0.0.1','Malformed headers must retain the known socket peer');
    }
    foreach (['cf-connecting-ip','x-real-ip','ali-cdn-real-ip'] as $header) {
        check(ClientIp::resolve('127.0.0.1','8.8.8.8',$trust,$header)==='8.8.8.8','An explicitly selected single-address header works behind a trusted peer');
        check(ClientIp::resolve('127.0.0.1','9.9.9.9, 8.8.8.8',$trust,$header)==='127.0.0.1','Single-address headers cannot silently become chains');
    }
    $long=implode(',',array_fill(0,32,'10.20.0.2'));
    check(ClientIp::resolve('127.0.0.1','8.8.8.8,'.$long,$trust)==='127.0.0.1','Trusted chain processing is bounded');
    check(ClientIp::resolve('127.0.0.1',str_repeat('ignored,',40).'8.8.8.8',$trust)==='8.8.8.8','An irrelevant client prefix cannot prevent resolving an appended real peer');
    foreach ([['10.16.0.0/12','10.16.0.0',true],['10.16.0.0/12','10.31.255.255',true],['10.16.0.0/12','10.32.0.0',false],
        ['192.0.2.128/25','192.0.2.127',false],['192.0.2.128/25','192.0.2.255',true],
        ['192.0.2.8/31','192.0.2.9',true],['192.0.2.8/31','192.0.2.10',false],
        ['192.0.2.8','192.0.2.8',true],['192.0.2.8','192.0.2.9',false],
        ['2001:db8::/65','2001:db8:0:0:7fff::1',true],['2001:db8::/65','2001:db8:0:0:8000::1',false],
        ['2001:db8::8/127','2001:db8::9',true],['2001:db8::8/127','2001:db8::a',false],
        ['::1','::1',true],['::1','::2',false],['192.0.2.0/24','::ffff:192.0.2.8',false],
        ['::ffff:192.0.2.0/120','::ffff:192.0.2.8',true]] as [$network,$peer,$trusted]) {
        check(ClientIp::resolve($peer,'8.8.8.8',[$network])===($trusted?'8.8.8.8':inet_ntop(inet_pton($peer))),'CIDR boundaries: '.$network.' / '.$peer);
    }
    foreach ([null,false,1,['name'=>'127.0.0.1'],[null],[''],['proxy.invalid'],['*'],['10.0.0.0/33'],['::1/129'],['::1/-1'],['::1/01'],['::1/1/2'],array_fill(0,129,'127.0.0.1')] as $bad) {
        $rejected=false;try {ClientIp::resolve('127.0.0.1','8.8.8.8',$bad);}catch(InvalidArgumentException $error){$rejected=true;}
        check($rejected,'Invalid server proxy configuration must fail explicitly');
    }
    Config::set(['trusted_proxies'=>'127.0.0.1, 10.16.0.0/12','forwarded_header'=>'x-forwarded-for'],'client_ip');
    foreach (['8.8.8.8','9.9.9.9'] as $ip) {
        $request=(new \app\Request())->withServer(['REMOTE_ADDR'=>'127.0.0.1','HTTP_X_FORWARDED_FOR'=>$ip.', 10.20.0.2']);
        $app->instance('request',$request);
        $_SERVER=['REMOTE_ADDR'=>'1.1.1.1','HTTP_CF_CONNECTING_IP'=>'2.2.2.2'];
        check($request->ip()===$ip && mac_get_client_ip()===$ip && $app->make(\think\Request::class)->ip()===$ip,
            'Framework injection and legacy consumers must use the active request, with no process-wide cached IP');
    }
    $request->withServer(['REMOTE_ADDR'=>'192.0.2.9','HTTP_X_FORWARDED_FOR'=>'1.1.1.1']);
    check($request->ip()==='192.0.2.9' && mac_get_client_ip()==='192.0.2.9','Reused request objects cannot keep an earlier client address');
    Config::set(['trusted_proxies'=>[],'forwarded_header'=>'cf-connecting-ip'],'client_ip');
    $request->withServer(['REMOTE_ADDR'=>'127.0.0.1'])->withHeader(['cf-connecting-ip'=>'8.8.8.8']);
    check($request->ip()==='127.0.0.1','Header bags alone cannot bypass the immediate-peer trust check');
    foreach ([['trusted_proxies'=>null],['forwarded_header'=>null],['forwarded_header'=>['x-real-ip']],['forwarded_header'=>'client-ip']] as $bad) {
        Config::set($bad,'client_ip');$error=null;try {$request->ip();}catch(InvalidArgumentException $caught){$error=$caught;}
        check($error!==null,'Explicit invalid/null configuration is not replaced with defaults');
        $response=(new \app\ExceptionHandle($app))->render($request->withHeader(['accept'=>'application/json']),$error);
        check($response->getCode()===500 && !str_contains($response->getContent(),'trusted proxy'),'Configuration errors remain controlled through real exception rendering');
    }
    $source=dirname(__DIR__);
    file_put_contents($temporary.'/router.php','<?php require '.var_export($source.'/vendor/autoload.php',true).'; require '.var_export($source.'/vendor/topthink/framework/src/helper.php',true).'; require '.var_export($source.'/application/common.php',true).'; $app=new \\app\\MacApp('.var_export($temporary,true).'); $mode=parse_url($_SERVER["REQUEST_URI"],PHP_URL_PATH); \\think\\facade\\Config::set(["trusted_proxies"=>$mode==="/none"?[]:["127.0.0.1"],"forwarded_header"=>$mode==="/cf"?"cf-connecting-ip":"x-forwarded-for"],"client_ip"); $r=$app->make("request"); header("Content-Type: application/json"); echo json_encode([$r->ip(),mac_get_client_ip()]);');
    $socket=stream_socket_server('tcp://127.0.0.1:0',$errno,$message);$address=stream_socket_get_name($socket,false);fclose($socket);
    $server=proc_open([PHP_BINARY,'-S',$address,$temporary.'/router.php'],[0=>['file','/dev/null','r'],1=>['file',$temporary.'/server.log','a'],2=>['file',$temporary.'/server.log','a']],$pipes,$temporary);
    $ready=false;for($i=0;$i<100;$i++){if($probe=@stream_socket_client('tcp://'.$address,$errno,$message,.05)){fclose($probe);$ready=true;break;}usleep(10000);}
    check($ready,'Real HTTP IP fixture must start');
    foreach ([['none',['CF-Connecting-IP: 8.8.8.8','X-Forwarded-For: 9.9.9.9'],'127.0.0.1'],
        ['xff',['X-Forwarded-For: 9.9.9.9, 8.8.8.8','CF-Connecting-IP: 1.1.1.1'],'8.8.8.8'],
        ['cf',['CF-Connecting-IP: 8.8.8.8','X-Forwarded-For: 1.1.1.1'],'8.8.8.8'],
        ['cf',['CF-Connecting-IP: 9.9.9.9, 8.8.8.8'],'127.0.0.1'],['xff',['X-Real-IP: 8.8.8.8'],'127.0.0.1']] as [$path,$headers,$expected]) {
        $curl=curl_init('http://'.$address.'/'.$path);curl_setopt_array($curl,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_HTTPHEADER=>$headers,CURLOPT_TIMEOUT=>5]);
        $body=curl_exec($curl);$status=curl_getinfo($curl,CURLINFO_RESPONSE_CODE);curl_close($curl);
        check($status===200 && json_decode((string)$body,true)===[$expected,$expected],'Real PHP HTTP request initialization must obey the same configured header policy');
    }
    echo "Client IP audit: $checks checks passed on PHP ".PHP_VERSION."\n";
} finally {if(is_resource($server)){proc_terminate($server);proc_close($server);}audit_remove_temp($temporary);}
