<?php
use think\facade\Db;
use app\common\util\ContentResource;
use app\common\util\MangaResourceReader;
$restore();Db::name('manga')->where('manga_id',1)->update(['manga_pwd'=>'','manga_points'=>0,'manga_points_detail'=>0]);
$base=Db::name('manga')->where('manga_id',1)->find();
$chapterCount=ContentResource::MANGA_MAX_CHAPTERS;
$long=$base;$long['manga_chapter_from']='reader';$long['manga_chapter_url']=str_repeat('#',$chapterCount-1).'Final$https://fixture.invalid/final.png';
$ctx=ContentResource::mangaContext($long,['nid'=>$chapterCount]);check($ctx['code']===1 && $ctx['nid']===$chapterCount && $ctx['previous_nid']===null && $ctx['purchase_supported'],'Maximum sparse chapter slot retains its exact real coordinate');
$long['manga_chapter_url']='#'.$long['manga_chapter_url'];$ctx=ContentResource::mangaContext($long,['nid'=>$chapterCount]);check($ctx['code']===1002 && !$ctx['purchase_supported'],'One extra chapter slot rejects the entire catalog instead of shifting or truncating a paid coordinate');
$many=$base;$many['manga_chapter_from']=implode('$$$',array_fill(0,256,'x'));$many['manga_chapter_url']=implode('$$$',array_fill(0,256,'One$https://fixture.invalid/a.png'));
$ctx=ContentResource::mangaContext($many,['sid'=>256]);check($ctx['code']===1 && $ctx['sid']===256 && !$ctx['purchase_supported'],'An extended legacy source256 keeps its readable coordinate without offering an unrepresentable receipt');
$GLOBALS['config']['user']['manga_points_type']='1';$ctx=ContentResource::mangaContext($many,['sid'=>256]);check($ctx['code']===1 && $ctx['purchase_supported'] && $ctx['purchase_sid']===1 && $ctx['ulog_sid']===0 && $ctx['sid']===256,'Whole-work purchase chooses a representable real entry while retaining current source256');
$many['manga_chapter_from'].='$$$x';check(ContentResource::mangaContext($many,[])['code']===1002,'Source budget excess rejects the whole work');$GLOBALS['config']['user']['manga_points_type']='0';
$limits=$base;$limits['manga_chapter_from']='reader';$limits['manga_chapter_url']='One$'.implode(',',array_fill(0,1024,'https://fixture.invalid/a.png'));
check(count(ContentResource::mangaContext($limits,[])['images'])===1024,'Maximum single-chapter image count is accepted intact');$limits['manga_chapter_url'].=',https://fixture.invalid/extra.png';check(ContentResource::mangaContext($limits,[])['code']===1002,'Image count excess prevents both reading and purchasing, rather than silently truncating');
$url='https://fixture.invalid/a.png?pad=';$url.=str_repeat('a',8192-strlen($url));check(count(ContentResource::mangaImages($url))===1,'Maximum individual URL length remains supported');check(ContentResource::mangaImages($url.'a')===[],'Overlong image URL is rejected intact');
$limits=$base;$limits['manga_chapter_from']=str_repeat('x',4096);check(ContentResource::mangaWithinBudget($limits),'Source byte boundary is explicit for extended legacy schemas');$limits['manga_chapter_from'].='x';check(!ContentResource::mangaWithinBudget($limits),'Excess source bytes reject before delimiter expansion');
$description=$base;$description['manga_content']=str_repeat('d',ContentResource::MANGA_MAX_DESCRIPTION_BYTES);check(ContentResource::mangaWithinBudget($description),'Maximum public description has an explicit independent byte budget');$description['manga_content'].='d';check(!ContentResource::mangaWithinBudget($description),'Description excess is rejected before catalog allocation');unset($description);
// Verify actual writer resource reads against mismatched replica content, schema and receipts.
$replicaName=$database.'_manga_replica';Db::execute('CREATE DATABASE `'.$replicaName.'` CHARACTER SET utf8mb4');
$replicaPdo=new PDO('mysql:unix_socket='.$socket.';dbname='.$replicaName.';charset=utf8mb4','root',getenv('DATABASE_AUDIT_PASSWORD'),[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
$split=$cfg;$split['default']='split';$split['connections']['split']=$cfg['connections']['fixture']+['hostname'=>'localhost,localhost','hostport'=>'3306,3306','deploy'=>1,'rw_separate'=>true,'master_num'=>1,'slave_no'=>1];
$split['connections']['split']['database']=$database.','.$replicaName;$split['connections']['split']['dsn']=$cfg['connections']['fixture']['dsn'].',mysql:unix_socket='.$socket.';dbname='.$replicaName.';charset=utf8mb4';
try {
    foreach(['manga','user','ulog','type','group','plog']as $table){preg_match('/CREATE TABLE `mac_'.preg_quote($table,'/').'` \(.*?\) ENGINE=[^;]+;/s',$ddl,$match);$replicaPdo->exec(str_replace('`mac_'.$table.'`','`audit_mangaaccess_'.$table.'`',$match[0]));}
    $insert=$replicaPdo->prepare('INSERT INTO audit_mangaaccess_manga (manga_id,manga_name,manga_status,manga_recycle_time,manga_chapter_from,manga_chapter_url,type_id) VALUES (1,?,1,0,?,?,1)');$insert->execute(['Replica-only','reader','One$https://fixture.invalid/REPLICA-SECRET.png']);
    Db::name('manga')->where('manga_id',1)->update(['manga_status'=>0]);$manager->setConfig($split);
    check(Db::name('manga')->value('manga_name')==='Replica-only','Fixture confirms ordinary ORM reads really use the separate replica database');
    $sqlTrace=[];check(MangaResourceReader::find(['manga_id'=>1])['code']===1002,'Writer unpublishing wins over a published replica');
    Db::name('manga')->where('manga_id',1)->update(['manga_status'=>1,'manga_recycle_time'=>time()]);$replicaPdo->exec('ALTER TABLE audit_mangaaccess_manga DROP COLUMN manga_recycle_time');
    check(MangaResourceReader::find(['manga_id'=>1])['code']===1002,'Writer recycle-column discovery is independent of a replica missing the column');
    $manager->setConfig($cfg);Db::execute('ALTER TABLE audit_mangaaccess_manga DROP COLUMN manga_recycle_time');$manager->setConfig($split);$sqlTrace=[];
    check(MangaResourceReader::find(['manga_id'=>1])['code']===1,'Legacy writer table missing recycle remains a read-only supported schema');
    check(!(bool)array_filter($sqlTrace,fn($sql)=>preg_match('/\b(?:ALTER|CREATE|DROP)\b/i',$sql)),'No production read silently adds the legacy recycle column');
    $manager->setConfig($cfg);Db::execute('ALTER TABLE audit_mangaaccess_manga ADD manga_recycle_time INT UNSIGNED NOT NULL DEFAULT 0');
    Db::name('manga')->where('manga_id',1)->update(['manga_points_detail'=>3]);$manager->setConfig($split);
    $replicaPdo->exec('INSERT INTO audit_mangaaccess_ulog (user_id,ulog_mid,ulog_type,ulog_rid,ulog_sid,ulog_nid,ulog_points) VALUES (1,12,1,1,1,1,3)');
    // Identity was already checked from the writer; source/receipt policy below executes on the distributed connection.
    $GLOBALS['user']=['user_id'=>1,'group_id'=>'2'];$probe=new MangaAccessPage();$access=(new ReflectionMethod($probe,'check_manga_resource_access'))->invoke($probe,MangaResourceReader::find(['manga_id'=>1])['info'],['sid'=>1,'nid'=>1]);
    check(!$access['can_access'],'A replica-only stale paid receipt cannot grant current access');
    Db::name('ulog')->insert(['user_id'=>1,'ulog_mid'=>12,'ulog_type'=>1,'ulog_rid'=>1,'ulog_sid'=>1,'ulog_nid'=>1,'ulog_points'=>3,'ulog_time'=>time()]);$replicaPdo->exec('DELETE FROM audit_mangaaccess_ulog');
    $access=(new ReflectionMethod($probe,'check_manga_resource_access'))->invoke($probe,MangaResourceReader::find(['manga_id'=>1])['info'],['sid'=>1,'nid'=>1]);check($access['can_access'],'A newly committed writer receipt grants access even before replica catch-up');
} finally {$manager->setConfig($cfg);Db::execute('DROP DATABASE IF EXISTS `'.$replicaName.'`');}
$restore();Db::name('manga')->where('manga_id',1)->update(['manga_pwd'=>'','manga_points'=>0,'manga_points_detail'=>0,'manga_chapter_from'=>'reader']);
// Test the real 8 MiB MEDIUMTEXT boundary with the production-like 128M PHP limit, not unlimited CLI memory.
$full='First$'.str_repeat($url.',',1023);$lastLength=ContentResource::MANGA_MAX_CHAPTER_BYTES-strlen($full);$last='https://fixture.invalid/last.png?pad=';$full.=$last.str_repeat('b',$lastLength-strlen($last));
check(strlen($full)===ContentResource::MANGA_MAX_CHAPTER_BYTES,'The fixture reaches the exact chapter field byte limit');
Db::name('manga')->where('manga_id',1)->update(['manga_chapter_url'=>$full]);unset($full,$long,$many,$limits,$ctx);gc_collect_cycles();memory_reset_peak_usage();$began=hrtime(true);
$result=mangaApi('get_chapter',['id'=>1],0);$duration=(hrtime(true)-$began)/1e9;$peak=memory_get_peak_usage(true);
check($result['code']===1 && count($result['info']['images'])===1024,'Real installed table/API returns every image at the exact field and image-count limit');check($peak<=128*1024*1024,'Maximum supported field stays within PHP128M');echo 'Manga 8MiB API: '.round($duration,3).'s; peak '.round($peak/1024/1024,2).'MiB; PHP limit '.ini_get('memory_limit').PHP_EOL;
unset($result);gc_collect_cycles();Db::execute("UPDATE audit_mangaaccess_manga SET manga_chapter_url=CONCAT(manga_chapter_url,'x') WHERE manga_id=1");$result=mangaApi('get_chapter',['id'=>1],0);check($result['code']===1002 && empty($result['purchase_supported']),'One byte above the field budget returns controlled failure without partial images');
// A dense 20k-entry public directory is also exercised end to end under the same limit.
$denseChapter='Title$https://fixture.invalid/a.png?pad=';
$length=intdiv(ContentResource::MANGA_MAX_CHAPTER_BYTES+1,20000)-1;
$denseChapter.=str_repeat('d',$length-strlen($denseChapter));
$extra=ContentResource::MANGA_MAX_CHAPTER_BYTES-(strlen($denseChapter)*20000+19999);
$dense=implode('#',array_merge(array_fill(0,$extra,$denseChapter.'d'),array_fill(0,20000-$extra,$denseChapter)));check(strlen($dense)===ContentResource::MANGA_MAX_CHAPTER_BYTES,'Dense maximum catalog simultaneously reaches the field byte limit');Db::name('manga')->where('manga_id',1)->update(['manga_chapter_url'=>$dense,'manga_content'=>str_repeat('d',ContentResource::MANGA_MAX_DESCRIPTION_BYTES)]);unset($dense);gc_collect_cycles();memory_reset_peak_usage();$began=hrtime(true);$result=mangaApi('get_detail',['id'=>1]);$duration=(hrtime(true)-$began)/1e9;$peak=memory_get_peak_usage(true);
check($result['code']===1 && count($result['info']['manga_page_list'][1]['urls'])===20000,'A dense maximum directory retains every chapter in the public DTO');check(!str_contains(json_encode($result),'https://fixture.invalid/a.png'),'Maximum directory still contains no resource addresses');echo 'Manga 20k catalog: '.round($duration,3).'s; peak '.round($peak/1024/1024,2).'MiB; PHP limit '.ini_get('memory_limit').PHP_EOL;
unset($result);gc_collect_cycles();memory_reset_peak_usage();$began=hrtime(true);$result=mangaApi('get_chapter',['id'=>1,'nid'=>20000],0);$duration=(hrtime(true)-$began)/1e9;$peak=memory_get_peak_usage(true);check($result['code']===1 && $result['info']['nid']===20000 && count($result['info']['images'])===1,'Dense 20k/8MiB plus1MiB description returns only its actual final chapter');echo 'Manga 20k/8MiB reader: '.round($duration,3).'s; peak '.round($peak/1024/1024,2).'MiB; PHP limit '.ini_get('memory_limit').PHP_EOL;unset($result);gc_collect_cycles();
// Large ordinary permissions fit the actual TEXT columns. This starts after trusted identity resolution;
// the shared User finalizer's complete Group cache is deliberately a separate audit boundary.
$permissionMap=[];for($category=1;$category<=3920;$category++)$permissionMap[$category]=[3=>'3'];
$permissionJson=json_encode($permissionMap,JSON_THROW_ON_ERROR);$categoryList=','.implode(',',range(1,12773)).',';$capacityGroups=range(100,131);
check(strlen($permissionJson)===65534 && strlen($categoryList)===65533,'Normal near-TEXT-limit group JSON and type lists fit actual installation columns');
foreach($capacityGroups as $id)Db::name('group')->insert(['group_id'=>$id,'group_name'=>'Capacity '.$id,'group_status'=>1,'group_type'=>$categoryList,'group_popedom'=>$permissionJson]);
unset($permissionMap,$permissionJson,$categoryList);
mangaRequest(['id'=>1,'sid'=>1,'nid'=>20000]);$GLOBALS['user']=['user_id'=>1,'group_id'=>implode(',',$capacityGroups)];
$probe=(new ReflectionClass(app\api\controller\Manga::class))->newInstanceWithoutConstructor();
$projected=(new ReflectionMethod($probe,'mangaPermissionGroups'))->invoke($probe,$capacityGroups,1);
check(count($projected)===32 && count(array_filter($projected,fn($group)=>array_keys($group['group_popedom'])===[1]))===32,'Every selected group retains only the actual category permission tree');
unset($projected);gc_collect_cycles();memory_reset_peak_usage();$began=hrtime(true);$baseline=memory_get_usage(true);
$response=$probe->get_chapter(request());$result=json_decode($response->getContent(),true,512,JSON_THROW_ON_ERROR);
check($result['code']===1 && $result['info']['can_read']===1 && $result['info']['nid']===20000 && count($result['info']['images'])===1,'Maximum ordinary group configuration still authorizes exactly the actual current chapter');
echo 'Manga 32-group/3920-category reader: baseline '.round($baseline/1024/1024,2).'MiB; peak '.round(memory_get_peak_usage(true)/1024/1024,2).'MiB; PHP limit '.ini_get('memory_limit').PHP_EOL;
Db::name('group')->whereIn('group_id',$capacityGroups)->delete();unset($response,$result,$probe,$capacityGroups);gc_collect_cycles();
Db::execute("UPDATE audit_mangaaccess_manga SET manga_content=CONCAT(manga_content,'x') WHERE manga_id=1");check(mangaApi('get_chapter',['id'=>1],0)['code']===1002,'Actual over-budget description fails without allocating a public resource response');$restore();
