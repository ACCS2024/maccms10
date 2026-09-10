<?php
/** Legitimate local account fixtures: reject unusable session secrets and preserve real native Cookie roundtrips. */
declare(strict_types=1);
require __DIR__.'/fixtures/member_cookie.php';
use think\facade\Db;
use app\common\model\User;
use app\common\util\JwtService;
function memberCredential(array $row):array{return ['user_id'=>(string)$row['user_id'],'user_name'=>$row['user_name'],
    'user_check'=>md5($row['user_random'].'-'.$row['user_name'].'-'.$row['user_id'].'-')];}
function memberCheck(array $cookies,array $headers=[],bool $success=false,bool $persist=true):array{
    memberCookieRequest($cookies,$headers);$before=memberCookieState();$GLOBALS['member_cookie_writes']=0;
    $result=(new User())->checkLogin($persist);
    check(($result['code']===1)===$success,'Session result must match the controlled credential contract');
    check(memberCookieState()===$before&&$GLOBALS['member_cookie_writes']===0,'Credential checking must not change account state in this fixture');return $result;
}
memberCookieSeed();
foreach(['','short',str_repeat('a',31),str_repeat('a',31).' ',str_repeat('a',31).'_',str_repeat('a',31)."\n",str_repeat('a',31)."\0",str_repeat('é',16)]as $random){
    Db::name('User')->where('user_id',1)->update(['user_random'=>$random,'group_id'=>3,'user_end_time'=>time()-60]);
    $row=Db::name('User')->where('user_id',1)->find();
    // This isolated row represents the old default/invalid credential state; it must require a normal login.
    memberCheck(memberCredential($row));
    if($random!=='')memberCheck([],['Authorization'=>'Bearer '.JwtService::encode(1,$random)]);
}
// A declared legacy wide-field fixture verifies the stored-secret upper bound, not only token claims.
if($mysql)Db::execute('ALTER TABLE cookie_audit_user MODIFY user_random varchar(64) NOT NULL DEFAULT ""');
else Db::execute('PRAGMA ignore_check_constraints=ON');
try{
    foreach([33,64]as $length){
        Db::name('User')->where('user_id',1)->update(['user_random'=>str_repeat('a',$length)]);
        memberCheck(memberCredential(Db::name('User')->where('user_id',1)->find()));
    }
}finally{
    Db::name('User')->where('user_id',1)->update(['user_random'=>'']);
    if($mysql)Db::execute('ALTER TABLE cookie_audit_user MODIFY user_random varchar(32) NOT NULL DEFAULT ""');
    else Db::execute('PRAGMA ignore_check_constraints=OFF');
}
Db::name('User')->where('user_id',1)->update(['user_random'=>str_repeat('a',32),'group_id'=>2]);
$row=Db::name('User')->where('user_id',1)->find();$valid=memberCredential($row);
foreach(array_keys($valid)as $field){
    foreach([null,[],['ordinary'],true,false,1.5,new stdClass(),'']as $bad)memberCheck(array_replace($valid,[$field=>$bad]));
}
foreach(['0','01','-1','+1',' 1','1 ','1e0','1.0','%31','4294967296',str_repeat('1',100)]as $id)memberCheck(array_replace($valid,['user_id'=>$id]));
foreach([str_repeat('a',31),str_repeat('汉',31),str_repeat('🙂',31),"bad\0name","bad\nname","bad\tname","bad\x7fname","bad\xffname"]as $name)memberCheck(array_replace($valid,['user_name'=>$name]));
foreach(['Member','member ','用户🙂']as $name)memberCheck(array_replace($valid,['user_name'=>$name]));
foreach([strtoupper($valid['user_check']),$valid['user_check'].' ',$valid['user_check']."\n",str_repeat('a',33),str_repeat('a',31),'%61'.substr($valid['user_check'],1)]as $signature)memberCheck(array_replace($valid,['user_check'=>$signature]));
memberCheck($valid,[],true);memberCheck(array_replace($valid,['user_id'=>1]),[],true);
foreach([str_repeat('Ab9Z',8),str_repeat('a',32)]as $random){
    Db::name('User')->where('user_id',1)->update(['user_random'=>$random]);$row=Db::name('User')->where('user_id',1)->find();$valid=memberCredential($row);
    memberCheck($valid,[],true);memberCheck([],['Authorization'=>'Bearer '.JwtService::encode(1,$random)],true);
}
$token=JwtService::encode(1,$row['user_random']);
memberCheck($valid,['Authorization'=>'Bearer '.JwtService::encode(1,str_repeat('a',33))]);
foreach([[],true,3,'Bearer','Bearer ','Bearer ordinary','Bearer '.$token.'x','Bearer '.$token.' extra',"Bearer\n".$token,"\rBearer ".$token]as $header){
    memberCheck($valid,['Authorization'=>$header]);
}
memberCheck(['user_id'=>[]],['Authorization'=>'Bearer '.$token],true);
memberCheck($valid,['Authorization'=>'Basic fixture-gateway'],true);
$GLOBALS['config']['app']['api_jwt_enabled']=0;
memberCheck($valid,['Authorization'=>'Bearer ignored'],true);memberCheck($valid,['Authorization'=>[]],true);
$GLOBALS['config']['app']['api_jwt_enabled']=1;
foreach([['user_status'=>0],['user_random'=>str_repeat('b',32)],['user_name'=>'renamed']]as $changes){
    Db::name('User')->where('user_id',1)->update($changes);memberCheck($valid);
    Db::name('User')->where('user_id',1)->update($row);
}
Db::name('User')->where('user_id',1)->update(['user_id'=>4294967295]);$maximum=Db::name('User')->where('user_id',4294967295)->find();
check(memberCheck(memberCredential($maximum),[],true)['info']['user_id']==4294967295,'The maximum actual unsigned account id remains usable');
Db::name('User')->where('user_id',4294967295)->update(['user_id'=>1]);
Db::name('User')->where('user_id',1)->update(['group_id'=>3,'user_end_time'=>time()-60]);
check((int)memberCheck($valid,[],true,false)['info']['group_id']===2,'Read-only valid expired sessions use the effective ordinary group');
memberCookieRequest($valid);check((new User())->checkLogin()['code']===1&&(int)Db::name('User')->where('user_id',1)->value('group_id')===2,
    'Ordinary valid callers retain the established expiry persistence behavior');

// Native HTTP setcookie -> libcurl Cookie jar -> real PHP parser; the test never decodes a Cookie itself.
$socket=stream_socket_server('tcp://127.0.0.1:0',$error,$message);$port=(int)substr(strrchr(stream_socket_get_name($socket,false),':'),1);fclose($socket);
$log=$temp.'/http.log';$server=proc_open([PHP_BINARY,'-S','127.0.0.1:'.$port,__DIR__.'/fixtures/member_cookie_http.php'],
    [0=>['file','/dev/null','r'],1=>['file',$log,'a'],2=>['file',$log,'a']],$pipes,$temp);
if(!is_resource($server))throw new RuntimeException('Cookie fixture listener failed');
try{
    $base='http://127.0.0.1:'.$port;$deadline=microtime(true)+10;
    do{$client=curl_init($base.'/health');curl_setopt_array($client,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_CONNECTTIMEOUT=>1,CURLOPT_TIMEOUT=>1]);$ready=curl_exec($client);curl_close($client);if($ready!==false)break;if(microtime(true)>$deadline)throw new RuntimeException('Cookie fixture startup timed out');usleep(20000);}while(true);
    function memberHttp(string $path,?array $post=null,?string $jar=null,array $headers=[]):array{
        global $base;
        $client=curl_init($base.$path);$responseHeaders=[];
        curl_setopt_array($client,[CURLOPT_RETURNTRANSFER=>true,CURLOPT_CONNECTTIMEOUT=>2,CURLOPT_TIMEOUT=>10,
            CURLOPT_HTTPHEADER=>$headers,CURLOPT_HEADERFUNCTION=>static function($client,$line)use(&$responseHeaders){$parts=explode(':',$line,2);if(count($parts)===2)$responseHeaders[strtolower(trim($parts[0]))]=trim($parts[1]);return strlen($line);}]);
        if($post!==null)curl_setopt_array($client,[CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>http_build_query($post)]);
        if($jar!==null)curl_setopt_array($client,[CURLOPT_COOKIEFILE=>$jar,CURLOPT_COOKIEJAR=>$jar]);
        $body=curl_exec($client);$status=curl_getinfo($client,CURLINFO_RESPONSE_CODE);curl_close($client);
        check($body!==false&&$status===200,'The real Cookie fixture request must complete normally');
        return ['data'=>json_decode($body,true,32,JSON_THROW_ON_ERROR),'headers'=>$responseHeaders];
    }
    foreach(['member','a+b','a%2Bb','a&amp;b',str_repeat('汉',30),'用户🙂',str_repeat('🙂',30)]as $name){
        // Installation tables are utf8mb3. Exercise their real boundary first, then a declared utf8mb4 upgrade.
        if($mysql&&$name==='用户🙂')Db::execute('ALTER TABLE cookie_audit_user CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci');
        memberCookieSeed($name);$jar=$temp.'/cookies-'.bin2hex(random_bytes(4));
        $login=memberHttp('/signin',['user_name'=>'cookie-fixture@example.test','user_pwd'=>'fixture-password'],$jar);
        check($login['data']['code']===1,'A normal email/password login must issue usable Cookies for an existing stored username');
        $row=Db::name('User')->where('user_id',1)->find();check(preg_match('/^[a-f0-9]{32}$/D',$row['user_random'])===1,'Normal password login restores an old empty-secret account by rotating a new secret');
        $before=memberCookieState();$identity=memberHttp('/identity',null,$jar);
        check($identity['data']['code']===1&&$identity['data']['user_name']===$name&&$identity['headers']['x-audit-write-count']==='0'&&memberCookieState()===$before,
            'Native Cookie transport must preserve the exact original stored UTF-8/plus/percent/entity username without secondary decoding');
    }
    memberCookieSeed();$jar=$temp.'/normal.jar';memberHttp('/signin',['user_name'=>'member','user_pwd'=>'fixture-password'],$jar);
    $oldJar=$temp.'/old.jar';copy($jar,$oldJar);
    check(memberHttp('/identity',null,$oldJar)['data']['code']===1,'The previous real Cookie jar is usable before another normal login');
    memberHttp('/signin',['user_name'=>'member','user_pwd'=>'fixture-password'],$jar);
    $before=memberCookieState();$oldSession=memberHttp('/identity',null,$oldJar);
    check($oldSession['data']['code']!==1&&$oldSession['headers']['x-audit-write-count']==='0'&&memberCookieState()===$before,
        'A second normal password login invalidates the old native Cookie jar without writing on its failed identity request');
    $before=memberCookieState();$response=memberHttp('/identity',null,$jar,['Authorization: Bearer ordinary']);
    check($response['data']['code']!==1&&$response['headers']['x-audit-write-count']==='0'&&memberCookieState()===$before,'Invalid Bearer must not fall back to real browser Cookies');
    // Let PHP perform the single transport decoding, with all other Cookies still supplied by its native jar.
    $row=Db::name('User')->where('user_id',1)->find();$credential=memberCredential($row);
    $wire='Cookie: user_id=%31; user_name=member; user_check='.$credential['user_check'];
    $response=memberHttp('/identity',null,null,[$wire]);check($response['data']['code']===1,'A once URL-encoded HTTP account id is parsed by PHP itself');
    $wire='Cookie: user_id=%2531; user_name=member; user_check='.$credential['user_check'];
    $response=memberHttp('/identity',null,null,[$wire]);check($response['data']['code']!==1&&$response['headers']['x-audit-write-count']==='0','A double-encoded HTTP id must not be decoded again by the authentication model');
}finally{
    proc_terminate($server);$deadline=microtime(true)+3;
    while(proc_get_status($server)['running']&&microtime(true)<$deadline)usleep(20000);
    if(proc_get_status($server)['running'])proc_terminate($server,9);proc_close($server);
}
if($mysql)require __DIR__.'/fixtures/member_cookie_replica.php';
fwrite(STDOUT,'Member Cookie audit passed ('.$checks.' checks; '.($mysql?'MySQL non-strict + real ORM writer/reader routing':'SQLite').")\n");
