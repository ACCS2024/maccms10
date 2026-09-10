<?php
// This file is included only after the dedicated MySQL fixture and real framework have been initialized.
$original=$row;
$restore=function()use($original){\think\facade\Db::name('art')->where('art_id',1)->update($original);\think\facade\Db::name('ulog')->where('ulog_id','>',0)->delete();$GLOBALS['config']['user']['art_points_type']='0';$GLOBALS['config']['user']['status']=1;};
$grant=function(int $uid=0,string $password='PWD-ART')use($app):string{
    $r=artApi('verify_pwd',['art_id'=>1,'pwd'=>$password],$uid);check($r['code']===1,'Real scoped article password verification succeeds');$id=$app->session->getId();$app->session->save();return $id;
};
foreach([0,1,2,3,4] as $uid){$r=artApi('get_read_page',['art_id'=>1,'page'=>2],$uid);check($r['info']['can_read']===0 && $r['info']['password_required'],'Every identity, including VIP, needs the article password');noArtSecrets($r);}
$session=$grant();
$r=artApi('get_read_page',['art_id'=>1,'page'=>2],2,[],$session);check($r['info']['can_read']===1 && $r['info']['page']===2,'A verified password and trusted VIP can read the selected chapter');noArtSecrets($r,['BODY-PAGE-2']);
$r=artApi('get_read_page',['art_id'=>1,'page'=>2],0,[],$session);check($r['info']['can_read']===0 && !$r['info']['password_required'],'A guest password grant does not waive points');noArtSecrets($r);
$validCookie=['user_id'=>'2','user_name'=>'member-2','user_check'=>md5('fixture-2-member-2-2-')];
$r=artApi('get_read_page',['art_id'=>1,'page'=>1],0,[],$session,$validCookie);check($r['info']['can_read']===1,'Trusted Cookie and Bearer authorize through the same real user model');noArtSecrets($r,['BODY-PAGE-1']);
$invalidCookie=$validCookie;$invalidCookie['user_check']='wrong';$r=artApi('get_read_page',['art_id'=>1],0,[],$session,$invalidCookie);check($r['info']['can_read']===0,'A forged Cookie cannot authorize a protected chapter');noArtSecrets($r);
foreach([['user_status'=>0],['user_end_time'=>time()-100]] as $change){\think\facade\Db::name('user')->where('user_id',2)->update($change);$r=artApi('get_read_page',['art_id'=>1],2,[],$session);check($r['info']['can_read']===0,'Disabled or expired VIP cannot bypass article points');noArtSecrets($r);\think\facade\Db::name('user')->where('user_id',2)->update(['user_status'=>1,'user_end_time'=>time()+3600,'group_id'=>'3']);}

// Current price, module, row, chapter and owner all belong to the same purchase key.
foreach([[1,200,3,1,2,1],[2,2,3,1,2,1],[1,2,4,1,2,1],[1,2,3,2,2,1],[1,2,3,1,1,1],[1,2,3,1,2,2]] as $record){purchase(...$record);}
$r=artApi('get_read_page',['art_id'=>1,'page'=>200],1,[],$session);check($r['info']['page']===3 && $r['info']['can_read']===0,'A page-200 voucher cannot authorize clamped page 3');noArtSecrets($r);
$r=artApi('get_read_page',['art_id'=>1,'page'=>2],1,[],$session);check($r['info']['can_read']===0,'Foreign owner/module/row/type/price vouchers cannot unlock the current chapter');noArtSecrets($r);
purchase(1,3,3);$r=artApi('get_read_page',['art_id'=>1,'page'=>4294967295],1,[],$session);check($r['info']['page']===3 && $r['info']['can_read']===1 && $r['info']['purchase_page']===3,'An oversized valid page is normalized before authorizing the actual final page');noArtSecrets($r,['BODY-PAGE-3']);
purchase(1,2,3);$r=artApi('get_read_page',['art_id'=>1,'page'=>2],1,[],$session);check($r['info']['can_read']===1,'An exact current-page voucher authorizes only that chapter');noArtSecrets($r,['BODY-PAGE-2']);
$r=artApi('get_read_page',['art_id'=>1,'page'=>1],1,[],$session);check($r['info']['can_read']===0,'Other paid pages remain private');noArtSecrets($r);
// Preserve the existing article-specific rule: a purchased chapter also permits a group lacking reading access.
purchase(3,2,3);$r=artApi('get_read_page',['art_id'=>1,'page'=>2],3,[],$session);check($r['info']['can_read']===1,'A group without article read permission retains its existing paid-voucher path');noArtSecrets($r,['BODY-PAGE-2']);
$restore();\think\facade\Db::name('art')->where('art_id',1)->update(['art_pwd'=>'']);
foreach([0,1] as $whole){$GLOBALS['config']['user']['art_points_type']=(string)$whole;
    foreach([0,3] as $points){\think\facade\Db::name('art')->where('art_id',1)->update(['art_points'=>$points,'art_points_detail'=>$points]);
        foreach([0=>false,1=>false,2=>true,3=>false,4=>true] as $uid=>$vip){$r=artApi('get_read_page',['art_id'=>1,'page'=>1],$uid);$expected=$vip || ($points===0 && $uid!==3);check($r['info']['can_read']===($expected?1:0),'Free/paid and whole/per-page modes retain ordinary/VIP/group permission behavior');noArtSecrets($r,$expected?['BODY-PAGE-1']:[]);}
    }
}
$restore();$GLOBALS['config']['user']['art_points_type']='1';$session=$grant();purchase(1,0,9);
foreach([1,2,3] as $page){$r=artApi('get_read_page',['art_id'=>1,'page'=>$page],1,[],$session);check($r['info']['can_read']===1 && $r['info']['points_hint']===9,'Whole-work sid0/nid0 vouchers cover each actual chapter');noArtSecrets($r,['BODY-PAGE-'.$page]);}
$restore();$GLOBALS['config']['user']['status']=0;$r=artApi('get_read_page',['art_id'=>1,'page'=>1]);check($r['info']['can_read']===0 && $r['info']['password_required'],'Disabling members never disables the independent article password');noArtSecrets($r);
$session=$grant();$r=artApi('get_read_page',['art_id'=>1,'page'=>1],0,[],$session);check($r['info']['can_read']===1,'Member-system-disabled mode still works after password verification');noArtSecrets($r,['BODY-PAGE-1']);$restore();

foreach(['page'=>[[],0,-1,'1e2','2.0','4294967296','18446744073709551615'], 'art_id'=>[[],0,-1,'1e0','1.0','4294967296']] as $field=>$values){foreach($values as $value){$r=artApi('get_read_page',array_replace(['art_id'=>1,'page'=>2],[$field=>$value]),2);check($r['code']===1001,'Invalid article IDs/page scalar forms are rejected before coercion');noArtSecrets($r);}}
foreach(['art_status'=>0,'art_recycle_time'=>time()] as $field=>$value){\think\facade\Db::name('art')->where('art_id',1)->update([$field=>$value]);foreach(['get_detail','get_read_page','verify_pwd'] as $action){$r=artApi($action,['art_id'=>1,'pwd'=>'PWD-ART'],2);check($r['code']!==1,'Draft/recycled rows are absent from metadata, body and password APIs');noArtSecrets($r);} \think\facade\Db::name('art')->where('art_id',1)->update([$field=>$field==='art_status'?1:0]);}
foreach(['',[],0] as $password){$r=artApi('verify_pwd',['art_id'=>1,'pwd'=>$password]);check($r['code']===1001,'Empty/array/non-string passwords return a controlled error');noArtSecrets($r);}
$r=artApi('verify_pwd',['art_id'=>1,'pwd'=>'wrong']);check($r['code']===1022,'Wrong article password retains the frontend error code');
$r=artApi('verify_pwd',['art_id'=>1,'pwd'=>'PWD-ART'],0,['last_pwd'=>time()]);check($r['code']===1003,'The real session throttle blocks rapid verification');
$session=$grant();\think\facade\Db::name('art')->where('art_id',1)->update(['art_pwd'=>'CHANGED']);$r=artApi('get_read_page',['art_id'=>1],2,[],$session);check($r['info']['can_read']===0 && $r['info']['password_required'],'Changing a password invalidates the existing fingerprint grant');noArtSecrets($r);
$restore();foreach([['2-1-1'=>'1'],['1-1-1'=>'1'],['2-1-2'=>['version'=>1,'fingerprint'=>hash('sha256',"2-1-2\0PWD-ART")]]] as $state){$r=artApi('get_read_page',['art_id'=>1],2,$state);check($r['info']['can_read']===0,'Legacy, other-media and other-article grants do not authorize this article');noArtSecrets($r);}
\think\facade\Db::name('art')->where('art_id',1)->update(['art_pwd'=>'0']);$session=$grant(0,'0');$r=artApi('get_read_page',['art_id'=>1],2,[],$session);check($r['info']['can_read']===1,'String-zero passwords remain real passwords and verify correctly');noArtSecrets($r,['BODY-PAGE-1']);
$restore();\think\facade\Db::name('art')->where('art_id',1)->update(['art_pwd'=>'','art_points'=>0,'art_points_detail'=>0,'art_content'=>'0']);$r=artApi('get_read_page',['art_id'=>1],0);check($r['info']['content_html']==='0' && $r['info']['page_total']===1,'The body string zero is a valid single chapter');
\think\facade\Db::name('art')->where('art_id',1)->update(['art_content'=>'']);$r=artApi('get_read_page',['art_id'=>1]);check($r['code']===1002,'No body returns a controlled missing-resource response');
$restore();

// Empty chapter slots keep their original coordinates but must never advertise a paid purchase.
\think\facade\Db::name('art')->where('art_id',1)->update(['art_pwd'=>'','art_content'=>'$$$$$$0']);
$r=artApi('get_read_page',['art_id'=>1,'page'=>2],1);check($r['info']['page']===2 && $r['info']['page_total']===3 && !$r['info']['purchase_supported'] && !$r['info']['can_read'],'An empty chapter retains its coordinate without offering a per-page purchase');
$r=artApi('get_read_page',['art_id'=>1,'page'=>2],2);check($r['info']['can_read']===1 && $r['info']['content_html']==='' && !$r['info']['purchase_supported'],'VIP access to an empty slot does not renumber the directory or advertise a charge');
$r=artApi('get_read_page',['art_id'=>1,'page'=>3],1);check($r['info']['purchase_supported'] && $r['info']['purchase_page']===3,'A nonempty string-zero chapter remains eligible for a real per-page purchase');
$GLOBALS['config']['user']['art_points_type']='1';$r=artApi('get_read_page',['art_id'=>1,'page'=>2],1);check($r['info']['page']===2 && $r['info']['purchase_supported'] && $r['info']['purchase_page']===3,'Whole-work purchasing selects the first nonempty chapter while preserving the current empty coordinate');
\think\facade\Db::name('art')->where('art_id',1)->update(['art_content'=>'$$$']);
foreach(['0','1'] as $mode){$GLOBALS['config']['user']['art_points_type']=$mode;$r=artApi('get_read_page',['art_id'=>1,'page'=>2],1);check($r['info']['page']===2 && !$r['info']['purchase_supported'],'An all-empty multi-chapter work offers neither per-page nor whole-work purchasing');}
$restore();

// Long chapters must never wrap/truncate their purchase coordinate to a smaller stored sid.
$chapters=[];for($page=1;$page<=300;$page++)$chapters[]='CHAPTER-'.$page;
\think\facade\Db::name('art')->where('art_id',1)->update(['art_pwd'=>'','art_content'=>implode('$$$',$chapters)]);
purchase(1,44,3);foreach([256,300,65536,4294967295] as $page){$r=artApi('get_read_page',['art_id'=>1,'page'=>$page],1);check($r['info']['page']===min($page,300) && $r['info']['can_read']===0 && !$r['info']['purchase_supported'],'Unrepresentable per-page purchase coordinates are not truncated into existing vouchers');}
$r=artApi('get_read_page',['art_id'=>1,'page'=>300],2);check($r['info']['can_read']===1 && $r['info']['content_html']==='CHAPTER-300','A VIP can read a valid chapter above the purchase sid limit');
$GLOBALS['config']['user']['art_points_type']='1';purchase(1,0,9);$r=artApi('get_read_page',['art_id'=>1,'page'=>300],1);check($r['info']['can_read']===1 && $r['info']['purchase_supported'] && $r['info']['purchase_page']===1,'Whole-work access retains chapter300 while choosing a representable real chapter for purchasing');
$restore();

// The original framework detail cache must not revive old public bodies after permission changes.
\think\facade\Db::name('art')->where('art_id',1)->update(['art_pwd'=>'','art_points'=>0,'art_points_detail'=>0]);$GLOBALS['config']['app']['cache_core']=1;
$cache->data['resource_fixture_art_detail_1_']=(new \app\common\model\Art())->infoData(['art_id'=>1],'*',0)['info'];\think\facade\Db::name('art')->where('art_id',1)->update($original);
$r=artApi('get_read_page',['art_id'=>1],2);check(!$r['info']['can_read'] && $r['info']['password_required'],'API authorization bypasses stale core detail cache');noArtSecrets($r);
artRequest(['id'=>1,'page'=>2],2,[],'detail');$probe=new ArtPageProbe();$tpl=$probe->detail();noArtSecrets($probe->assigned);check(str_ends_with($tpl,'content/art.html'),'Missing theme password templates resolve to the real standalone fallback');
$GLOBALS['config']['app']['cache_core']=0;$restore();

// Public adjacent article titles exclude both unpublished and recycled rows.
\think\facade\Db::name('art')->insert(array_replace($original,['art_id'=>2,'art_name'=>'DRAFT-NEIGHBOR','art_status'=>0]));
\think\facade\Db::name('art')->insert(array_replace($original,['art_id'=>3,'art_name'=>'RECYCLED-NEIGHBOR','art_recycle_time'=>time()]));
\think\facade\Db::name('art')->insert(array_replace($original,['art_id'=>4,'art_name'=>'VISIBLE-NEIGHBOR']));
$r=artApi('get_detail',['art_id'=>1]);check(($r['info']['art_next']['art_id']??0)===4 && !str_contains(json_encode($r),'DRAFT-NEIGHBOR') && !str_contains(json_encode($r),'RECYCLED-NEIGHBOR'),'Adjacent directory metadata excludes draft and recycled articles');noArtSecrets($r);
\think\facade\Db::name('art')->where('art_id','>',1)->delete();

// The old generic Ajax list is another public article-body/password exit.
artRequest(['mid'=>2]);$ajax=(new \ReflectionClass(\app\index\controller\Ajax::class))->newInstanceWithoutConstructor();$ajax->_param=['mid'=>2,'limit'=>10,'page'=>1,'tid'=>0];
$r=json_decode($ajax->data()->getContent(),true);check($r['code']===1 && count($r['list'])===1,'Actual legacy Ajax article lists retain public rows');noArtSecrets($r);
$sqlTrace=[];$r=artApi('get_read_page',['art_id'=>1,'page'=>2],1);check(count(array_filter($sqlTrace,fn($sql)=>preg_match('/^(INSERT|UPDATE|DELETE)/',$sql)))===0,'Normal resource reads never debit balances or create purchase rows');
