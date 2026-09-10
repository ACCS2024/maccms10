<?php
use think\facade\Db;
use app\common\util\ContentResource;
use app\common\util\ContentPassword;
use app\common\util\MangaResourceReader;
$row=['manga_id'=>1,'manga_name'=>'Public manga','manga_en'=>'rewritten-manga','manga_status'=>1,'type_id'=>1,
    'manga_points'=>9,'manga_points_detail'=>3,'manga_pwd'=>'PWD-MANGA','manga_blurb'=>'Public introduction','manga_content'=>'<p>Public description</p>',
    'manga_chapter_from'=>'first$$$second','manga_chapter_url'=>'First$https://fixture.invalid/SECRET-1.png,https://fixture.invalid/SECRET-2.png##Third$https://fixture.invalid/SECRET-3.png$$$Other$https://fixture.invalid/SECRET-OTHER.png'];
Db::name('manga')->insert($row);
$restore=function()use($row,$cache):void{Db::name('manga')->where('manga_id',1)->update($row+['manga_recycle_time'=>0]);Db::name('ulog')->where('ulog_mid',12)->delete();$GLOBALS['config']['app']['cache_core']=0;$GLOBALS['config']['user']['manga_points_type']='0';$GLOBALS['config']['rewrite']['manga_id']=0;foreach(array_keys($cache->data)as $key)if(str_contains($key,'_manga_detail_'))unset($cache->data[$key]);};
$secrets=function($result,array $allowed=[]):void{$text=is_string($result)?$result:json_encode($result,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES);foreach(['PWD-MANGA','SECRET-1','SECRET-2','SECRET-3','SECRET-OTHER']as $marker)if(!in_array($marker,$allowed,true))check(!str_contains($text,$marker),'Unexpected password/other chapter in output: '.$marker);};
$receipt=function(int $uid,int $sid,int $nid,int $points):void{Db::name('ulog')->insert(['user_id'=>$uid,'ulog_mid'=>12,'ulog_type'=>1,'ulog_rid'=>1,'ulog_sid'=>$sid,'ulog_nid'=>$nid,'ulog_points'=>$points,'ulog_time'=>time()]);};
$grant=function(int $uid=0,string $password='PWD-MANGA'):string{$r=mangaApi('verify_pwd',['id'=>1,'pwd'=>$password],$uid);check($r['code']===1,'Real Manga password endpoint grants this session');$id=think\Container::getInstance()->make('session')->getId();think\Container::getInstance()->make('session')->save();return $id;};
foreach([0,1,2,3,4]as $uid){$r=mangaApi('get_chapter',['id'=>1],$uid);check($r['code']===1 && $r['info']['can_read']===0 && $r['info']['deny_code']===6001 && $r['info']['images']===[],'Every account still needs the independent Manga password');$secrets($r);}
$session=$grant();
foreach([0=>false,1=>false,2=>true,3=>false]as $uid=>$expected){$r=mangaApi('get_chapter',['id'=>1],$uid,[],$session);check((bool)$r['info']['can_read']===$expected,'Password grant preserves guest/member/VIP/group policy');$secrets($r,$expected?['SECRET-1','SECRET-2']:[]);}
$receipt(1,1,1,3);
foreach([[1,1,true],[1,3,false],[2,1,false]]as [$sid,$nid,$allowed]){$r=mangaApi('get_chapter',['id'=>1,'sid'=>$sid,'nid'=>$nid],1,[],$session);check((bool)$r['info']['can_read']===$allowed,'Receipt scope never grants another source/chapter');$secrets($r,$allowed?['SECRET-1','SECRET-2']:[]);}
$r=mangaApi('get_chapter',['id'=>1],1,[],$session);check($r['info']['sid']===1 && $r['info']['nid']===1 && $r['info']['next_nid']===3 && str_contains($r['info']['next_link'],'nid=3'),'API default/next coordinates are actual chapter keys');
$receipt(3,1,1,3);check(mangaApi('get_chapter',['id'=>1],3,[],$session)['info']['can_read']===1,'Existing group-denied paid receipt fallback remains effective');
$validCookie=['user_id'=>'2','user_name'=>'member-2','user_check'=>md5(md5('fixture-2').'-member-2-2-')];
check(mangaApi('get_chapter',['id'=>1],0,[],$session,$validCookie)['info']['can_read']===1,'Actual signed member cookie resolves the server VIP identity');
$validCookie=['user_id'=>'1','user_name'=>'member-1','user_check'=>md5(md5('fixture-1').'-member-1-1-'),'group_id'=>'3'];
$r=mangaApi('get_chapter',['id'=>1,'nid'=>3],0,[],$session,$validCookie);check($r['info']['can_read']===0,'A forged group cookie cannot turn the real ordinary account into VIP');$secrets($r);
$GLOBALS['config']['user']['manga_points_type']='1';
check(mangaApi('get_chapter',['id'=>1],1,[],$session)['info']['can_read']===0,'Single-chapter3-point receipt does not cover whole-work9-point permission');
$receipt(1,0,0,9);foreach([[1,1],[1,3],[2,1]]as [$sid,$nid]){check(mangaApi('get_chapter',['id'=>1,'sid'=>$sid,'nid'=>$nid],1,[],$session)['info']['can_read']===1,'Whole receipt covers each actual chapter');}
$restore();
foreach(['get_detail','get_chapter','verify_pwd']as $action){foreach([null,0,-1,[],true,1.5,'1junk','4294967296','999999999999999999999999']as $id){$r=mangaApi($action,['id'=>$id,'pwd'=>'PWD-MANGA']);check($r['code']===1001,'Bad id is rejected by '.$action);$secrets($r);}}
foreach(['sid','nid']as $field){foreach([0,-1,[],true,1.5,'1junk','4294967296','']as $bad){$r=mangaApi('get_chapter',['id'=>1,$field=>$bad]);check($r['code']===1001,'Invalid '.$field.' is never coerced to chapter1');$secrets($r);}}
foreach([[1,2],[2,2],[3,1],[1,20001]]as [$sid,$nid]){check(mangaApi('get_chapter',['id'=>1,'sid'=>$sid,'nid'=>$nid],2)['code']===1002,'Missing actual resource stays controlled for VIP too');}
$session=$grant();Db::name('manga')->where('manga_id',1)->update(['manga_pwd'=>'CHANGED']);$r=mangaApi('get_chapter',['id'=>1],2,[],$session);check($r['info']['can_read']===0 && $r['info']['password_required'],'Changing the stored password revokes the previous guest grant');$secrets($r);
foreach([['12-1-1'=>true],['2-1-1'=>['version'=>1,'fingerprint'=>hash('sha256',"12-1-1\0CHANGED")]],['12-1-2'=>['version'=>1,'fingerprint'=>hash('sha256',"12-1-1\0CHANGED")]]]as $state){check(mangaApi('get_chapter',['id'=>1],2,$state)['info']['can_read']===0,'Legacy booleans/other media/other work scopes never grant Manga access');}
$restore();Db::name('manga')->where('manga_id',1)->update(['manga_pwd'=>'a +&=0']);mangaRequest(['mid'=>12,'type'=>1,'id'=>1,'pwd'=>'a +&=0']);$ajax=(new ReflectionClass(app\index\controller\Ajax::class))->newInstanceWithoutConstructor();$r=json_decode($ajax->pwd()->getContent(),true);check($r['code']===1,'Actual Ajax endpoint supports Manga password bytes');$session=think\Container::getInstance()->make('session')->getId();think\Container::getInstance()->make('session')->save();check(mangaApi('get_chapter',['id'=>1],2,[],$session)['info']['can_read']===1,'Guest Ajax password grant works with later API identity');
foreach([2,4,5,12]as $type){mangaRequest(['mid'=>12,'type'=>$type,'id'=>1,'pwd'=>'a +&=0']);check(json_decode($ajax->pwd()->getContent(),true)['code']===1001,'Manga has one independent password operation');}
$restore();Db::name('manga')->where('manga_id',1)->update(['manga_pwd'=>'','manga_points'=>0,'manga_points_detail'=>0]);
$emptyRow=Db::name('manga')->where('manga_id',1)->find();
foreach(['Two$','0$','$','   ']as $text){$copy=$emptyRow;$copy['manga_chapter_url']=$text;$copy['manga_chapter_from']='reader';$ctx=ContentResource::mangaContext($copy,[]);check($ctx['code']===1 && $ctx['images']===[] && !$ctx['purchase_supported'],'Explicit empty/whitespace image chapters cannot be sold as paths');}
foreach(['https://fixture.invalid/image.png','http://fixture.invalid/a.jpg?sig=a%2Bb&x=1','//fixture.invalid/a.png','mac://fixture.invalid/a.png','upload/a.png','/upload/a.png']as $url){check(count(ContentResource::mangaImages($url))===1,'Legitimate image address mapping remains available');}
foreach(['javascript:alert(1)','data:image/svg+xml,test','file:///etc/passwd','ftp://fixture.invalid/a','https://u:p@fixture.invalid/a',"https://fixture.invalid/a\nB",'https://fixture.invalid\\evil/a','https://','https://fixture.invalid:9999999/x']as $url){check(ContentResource::mangaImages($url)===[],'Unsupported or ambiguous image URL is not returned: '.json_encode($url));}
$restore();$sqlTrace=[];
$info=MangaResourceReader::find(['manga_id'=>1]);check($info['code']===1 && array_keys($info['info']['manga_page_list'][1]['urls'])===[1,3],'Writer reader keeps actual catalog positions');
check(!(bool)array_filter($sqlTrace,fn($sql)=>preg_match('/\b(?:ALTER|CREATE|DROP)\b/i',$sql)),'Fresh resource reading performs no DDL');

$restore();Db::name('manga')->where('manga_id',1)->update(['manga_pwd'=>'']);
$groupRow=Db::name('group')->where('group_id',3)->find();
foreach([['group_status'=>0],['group_type'=>'2,'],['group_popedom'=>json_encode([1=>[2=>1,3=>0]])],['group_popedom'=>'not-json']]as $change){Db::name('group')->where('group_id',3)->update($groupRow);Db::name('group')->where('group_id',3)->update($change);$r=mangaApi('get_chapter',['id'=>1],2);check($r['info']['can_read']===0,'Cached VIP cannot override writer group status/type/permission/corruption');$secrets($r);}
Db::name('group')->where('group_id',3)->delete();$r=mangaApi('get_chapter',['id'=>1],2);check($r['info']['can_read']===0,'Deleted writer group cannot survive in a cached VIP profile');$secrets($r);Db::name('group')->insert($groupRow);
$GLOBALS['config']['user']['status']=0;Db::name('manga')->where('manga_id',1)->update(['manga_pwd'=>'PWD-MANGA']);check(mangaApi('get_chapter',['id'=>1],0)['info']['can_read']===0,'Disabling the member subsystem does not disable the separate content password');Db::name('manga')->where('manga_id',1)->update(['manga_pwd'=>'']);check(mangaApi('get_chapter',['id'=>1],0)['info']['can_read']===1,'Existing member-subsystem-disabled free reading contract remains available');$GLOBALS['config']['user']['status']=1;$restore();

$restore();Db::name('manga')->where('manga_id',1)->update(['manga_pwd'=>'','manga_points'=>0,'manga_points_detail'=>0]);
foreach(['02','2,02']as $membership){Db::name('user')->where('user_id',1)->update(['group_id'=>$membership]);check(mangaApi('get_chapter',['id'=>1],1)['info']['can_read']===1,'Validated leading-zero or duplicate membership IDs have the same Manga policy as group2');}Db::name('user')->where('user_id',1)->update(['group_id'=>'2']);
foreach([[],new stdClass(),'2','1junk',-1]as $mode){$GLOBALS['config']['user']['manga_points_type']=$mode;$r=mangaApi('get_chapter',['id'=>1],1);check($r['code']===1002,'Malformed price-scope configuration cannot reinterpret a receipt or throw under PHP8');}$GLOBALS['config']['user']['manga_points_type']='0';$restore();

// Current-category projection preserves group union semantics and never borrows another category's permission.
$restore();Db::name('manga')->where('manga_id',1)->update(['manga_pwd'=>'','manga_points'=>0,'manga_points_detail'=>0]);
$memberGroup=Db::name('group')->where('group_id',2)->find();$extraGroup=Db::name('group')->where('group_id',5)->find();
Db::name('group')->where('group_id',2)->update(['group_popedom'=>json_encode([1=>[3=>0],2=>[3=>1]])]);
Db::name('group')->where('group_id',5)->update(['group_popedom'=>json_encode([1=>[3=>1],2=>[3=>0]])]);
check(mangaApi('get_chapter',['id'=>1],1)['info']['can_read']===0,'Permission on another category never grants the actual Manga category');
check(mangaApi('get_chapter',['id'=>1],4)['info']['can_read']===1,'A later active group still grants its actual-category permission');
Db::name('group')->where('group_id',5)->update(['group_popedom'=>json_encode([2=>[3=>1]])]);
check(mangaApi('get_chapter',['id'=>1],4)['info']['can_read']===0,'A missing current-category entry cannot be replaced by another-category permission');
Db::name('group')->where('group_id',2)->update($memberGroup);Db::name('group')->where('group_id',5)->update($extraGroup);$restore();
