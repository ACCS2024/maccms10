<?php
/** Actual card controllers, Request decoding, validators and Card/ledger ORM; authentication is an isolated boundary. */
declare(strict_types=1);
namespace app\common\model {
    class User {
        public function checkLogin(){return empty($GLOBALS['card_ingress_logged_in'])?['code'=>1001]:['code'=>1,'info'=>['user_id'=>1]];}
    }
}
namespace {
    $mysql=getenv('MEMBERSHIP_AUDIT_MYSQL')==='1';
    define('MEMBERSHIP_AUDIT_DATABASE',$mysql?'maccms_audit_card_ingress':':memory:');
    if($mysql){
        $server=new \PDO('mysql:host='.(getenv('MEMBERSHIP_AUDIT_HOST')?:'127.0.0.1').';charset=utf8mb4','root',getenv('MEMBERSHIP_AUDIT_PASSWORD')?:'');
        $server->exec('CREATE DATABASE IF NOT EXISTS maccms_audit_card_ingress CHARACTER SET utf8mb4');
    }
    require __DIR__.'/fixtures/security_audit_card_db.php';
    use think\facade\Db;
    function json($value){return $value;}
    function request(){return \think\Container::getInstance()->make('request');}
    class CardIngressRequest extends \think\Request {public function isCli():bool{return false;}}
    function ingressCall(string $kind,array $params,string $method='POST',bool $formBody=false):array {
        if($formBody){parse_str(http_build_query($params,'','&',PHP_QUERY_RFC3986),$params);}
        $r=(new CardIngressRequest())->withServer(['REQUEST_METHOD'=>$method]);$r->setAction($kind==='api'?'use_card':'buy');
        $r=$method==='POST'?$r->withPost($params):$r->withGet($params);
        \think\Container::getInstance()->instance('request',$r);
        $class=$kind==='api'?\app\api\controller\Payment::class:\app\index\controller\User::class;
        $controller=(new \ReflectionClass($class))->newInstanceWithoutConstructor();
        $result=$kind==='api'?$controller->use_card($r):$controller->buy();
        check(is_array($result) && isset($result['code']),'Actual controller returns a controlled result');
        return $result;
    }
    function ingressSeed(string $number='fixture-card',string $password='fixture'):void {
        cardSeed();$GLOBALS['card_ingress_logged_in']=true;
        Db::name('Card')->where('card_id',1)->update(['card_no'=>$number,'card_pwd'=>$password]);
    }
    foreach(['api','front']as $kind){
        foreach([
            ['fixture-card','fixture'],['literal%41','pw%42'],['literal+card','a+b'],['literal&card','a&b'],
            ['literal-card',"a'b\"c"],['fixture-card',' pw '],[' 卡片 ',' 密码 '],
            [str_repeat('卡',16),str_repeat('密',8)],['123456','12345678'],
        ]as [$number,$password]){
            foreach([false,true]as $formBody){
                ingressSeed($number,$password);
                check(ingressCall($kind,['flag'=>'card','card_no'=>$number,'card_pwd'=>$password],'POST',$formBody)['code']===1,
                    'Valid credential is preserved through the actual controller and one transport decode: '.$kind);
                check(memberRow(1)['user_points']===120 && (int)Db::name('Card')->value('card_use_status')===1 && Db::name('Plog')->count()===1,'Controller credits one exact stored credential');
            }
        }
        foreach([['literalA','pwB','literal%41','pw%42'],['fixture-card','a b','fixture-card','a+b'],
            ['fixture-card','pw','fixture-card',' pw '],['fixture-card','a&amp;b','fixture-card','a&b']]as [$number,$password,$inputNo,$inputPwd]){
            ingressSeed($number,$password);$before=cardState();
            check(ingressCall($kind,['flag'=>'card','card_no'=>$inputNo,'card_pwd'=>$inputPwd],'POST',true)['code']!==1 && cardState()===$before,
                'Normalization cannot turn a different literal request into a valid credential: '.$kind);
        }
        foreach(['card_no','card_pwd']as $field){
            foreach([null,[],['ordinary'],new \stdClass(),true,1.5,str_repeat('x',65),"\xff"]as $value){
                ingressSeed();$before=cardState();$params=['flag'=>'card','card_no'=>'fixture-card','card_pwd'=>'fixture'];$params[$field]=$value;
                check(ingressCall($kind,$params)['code']===1001 && cardState()===$before,'Malformed credential shape fails without PHP coercion or mutation: '.$kind.'/'.$field);
            }
            ingressSeed();$before=cardState();$params=['flag'=>'card','card_no'=>'fixture-card','card_pwd'=>'fixture'];unset($params[$field]);
            check(ingressCall($kind,$params)['code']===1001 && cardState()===$before,'Missing credential is controlled: '.$kind.'/'.$field);
        }
        ingressSeed('123456','12345678');
        check(ingressCall($kind,['flag'=>'card','card_no'=>123456,'card_pwd'=>12345678])['code']===1,'Existing integer-valued API/internal credentials retain their canonical decimal form');
    }
    foreach(['GET','HEAD','PUT','DELETE','OPTIONS']as $method){
        ingressSeed();$before=cardState();
        check(ingressCall('api',['card_no'=>'fixture-card','card_pwd'=>'fixture'],$method)['code']===1001 && cardState()===$before,'Card API accepts POST only: '.$method);
    }
    ingressSeed();$before=cardState();$GLOBALS['card_ingress_logged_in']=false;
    check(ingressCall('api',['card_no'=>'fixture-card','card_pwd'=>'fixture'])['code']===1401 && cardState()===$before,'Existing API login rejection remains enforced');
    printf("Card controller credential ingress: %d checks on PHP %s / %s.\n",$checks,PHP_VERSION,$mysql?'MySQL non-strict':'SQLite');
}
