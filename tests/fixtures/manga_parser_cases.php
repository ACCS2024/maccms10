<?php
use think\facade\Db;

$source='One$https://fixture.invalid/one.png##Three$https://fixture.invalid/three.png';
$expected=[1=>['sid'=>1,'from'=>'reader','url'=>$source,'server'=>'','note'=>'','url_count'=>2,'urls'=>[
    1=>['name'=>'One','url'=>'https://fixture.invalid/one.png','from'=>'reader','nid'=>1],
    3=>['name'=>'Three','url'=>'https://fixture.invalid/three.png','from'=>'reader','nid'=>3],
]]];
check(mac_manga_list('reader',$source)===$expected,'Omitted optional columns preserve the complete original catalog contract');
check(mac_manga_list('reader',$source,'','')===$expected,'Explicit empty optional fields match omitted fields');
check(mac_manga_list('reader',$source,null,null)===$expected,'Legacy null optional fields have empty defaults');
foreach([[],new stdClass(),false,3]as $invalid){check(mac_manga_list($invalid,$source)===[],'Invalid source-container types do not cause PHP warnings');check(mac_manga_list('reader',$source,$invalid,$invalid)===$expected,'Invalid optional containers do not alter chapter data');}
check(mac_manga_list('',$source)===[] && mac_manga_list(null,$source)===[],'Absent source does not invent a source for orphan chapter data');
foreach([null,'',[],new stdClass()]as $empty){$result=mac_manga_list('reader',$empty);check(array_keys($result)===[1] && $result[1]['urls']===[] && $result[1]['url_count']===0,'An empty/invalid chapter container preserves the declared empty source');}
$result=mac_manga_list('first$$$second$$$third',$source,'legacy-server','legacy-note');
check(array_keys($result)===[1,2,3] && $result[2]['urls']===[] && $result[3]['urls']===[],'Fewer URL groups preserve empty declared source slots');
check($result[1]['server']==='legacy-server' && $result[1]['note']==='legacy-note' && $result[2]['server']==='' && $result[2]['note']==='','Partial server/note groups fill only their own source');
$result=mac_manga_list('$$$real','$$$'.$source,'$$$server-2','$$$note-2');
check(array_keys($result)===[1,2] && $result[1]['urls']===[] && array_keys($result[2]['urls'])===[1,3],'Empty leading source never compresses real sid2 to sid1');
check($result[2]['urls'][3]['nid']===3 && $result[2]['server']==='server-2' && $result[2]['note']==='note-2','Later source metadata and chapter keys retain their original coordinates');
$result=mac_manga_list('first',$source.'$$$Orphan$https://fixture.invalid/orphan.png');
check(count($result)===1 && $result[1]['url_count']===2,'Extra URL groups cannot become fake declared sources');
$result=mac_manga_list('reader','#Second$https://fixture.invalid/two.png##Fourth$https://fixture.invalid/four.png#');
check(array_keys($result[1]['urls'])===[2,4] && $result[1]['url_count']===2,'Leading, middle and trailing empty episode segments preserve actual chapter keys');
$result=mac_manga_list('0','0$https://fixture.invalid/zero.png');
check($result[1]['from']==='0' && $result[1]['urls'][1]['name']==='0','String zero is a valid source label and chapter title');
$result=mac_manga_list('reader','https://fixture.invalid/nameless.png');
check($result[1]['urls'][1]['url']==='https://fixture.invalid/nameless.png' && $result[1]['urls'][1]['nid']===1,'Existing URL-only chapter format stays readable');

$columns=Db::query('SHOW COLUMNS FROM audit_mangaparser_manga');$names=array_column($columns,'Field');
check(!in_array('manga_play_server',$names,true) && !in_array('manga_play_note',$names,true),'Regression runs against actual installation DDL without optional legacy fields');
$row=['manga_id'=>1,'manga_name'=>'Manga parser fixture','manga_en'=>'parser-fixture','manga_status'=>1,'type_id'=>1,
    'manga_chapter_from'=>'reader','manga_chapter_url'=>$source,'manga_pwd'=>'','manga_points'=>0,'manga_points_detail'=>0];
Db::name('manga')->insert($row);$sqlTrace=[];
$info=(new app\common\model\Manga())->infoData(['manga_id'=>1]);
check($info['code']===1 && $info['info']['manga_page_list']===$expected && $info['info']['manga_page_total']===1,'Real fresh ORM lookup parses normal installed Manga without undefined fields');
$api=mangaApi('get_detail',['id'=>1]);
check($api['code']===1 && array_keys($api['info']['manga_page_list'][1]['urls'])===[1,3],'Real detail JSON keeps sparse source/episode keys');
check(!str_contains(json_encode($api),'https://fixture.invalid/one.png'),'Existing public detail DTO still withholds raw chapter images');
foreach([1,3]as $nid){$api=mangaApi('get_chapter',['id'=>1,'sid'=>1,'nid'=>$nid]);check($api['code']===1 && $api['info']['can_read']===1 && $api['info']['nid']===$nid && count($api['info']['images'])===1,'Actual free chapter API serves its existing chapter coordinate from normal installation DDL');}
check(mangaApi('get_chapter',['id'=>1,'sid'=>1,'nid'=>2])['code']===1002,'A genuine chapter hole remains nonexistent, not silently remapped');
foreach([
    ['manga_chapter_from'=>'first$$$second','manga_chapter_url'=>$source],
    ['manga_chapter_from'=>'$$$real','manga_chapter_url'=>'$$$'.$source],
    ['manga_chapter_from'=>'reader','manga_chapter_url'=>null],
    ['manga_chapter_from'=>'','manga_chapter_url'=>$source],
]as $update){Db::name('manga')->where('manga_id',1)->update($update);$info=(new app\common\model\Manga())->infoData(['manga_id'=>1]);check($info['code']===1,'Actual schema row supports incomplete/null collection data without a 500');$api=mangaApi('get_detail',['id'=>1]);check($api['code']===1,'Actual public detail handles an incomplete catalog');}
Db::name('manga')->where('manga_id',1)->update($row);$GLOBALS['config']['app']['cache_core']=1;
foreach([0,1]as $cached){$info=(new app\common\model\Manga())->infoData(['manga_id'=>1],'*',$cached);check($info['info']['manga_page_list']===$expected,'Fresh and existing core-cache parse shape stays identical');}
check(!(bool)array_filter($sqlTrace,fn($sql)=>preg_match('/\b(?:ALTER|CREATE|DROP)\b/i',$sql)),'All production model/API reads after fixture setup perform no schema mutation');
// Production has no runtime DDL repair; a fixture-only extended legacy row still retains optional metadata.
Db::execute("ALTER TABLE audit_mangaparser_manga ADD manga_play_server VARCHAR(255) NOT NULL DEFAULT 'legacy-server', ADD manga_play_note VARCHAR(255) NOT NULL DEFAULT 'legacy-note'");
$info=(new app\common\model\Manga())->infoData(['manga_id'=>1],'*',0);
check($info['info']['manga_page_list'][1]['server']==='legacy-server' && $info['info']['manga_page_list'][1]['note']==='legacy-note','Extended legacy schema metadata is preserved without becoming an image prefix');
check($info['info']['manga_page_list'][1]['urls'][1]['url']==='https://fixture.invalid/one.png','Existing server metadata remains metadata rather than changing original image URLs');
