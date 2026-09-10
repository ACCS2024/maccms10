<?php
// Real controller assignments and shipped templates; unrelated headers/advertising are excluded.
$engine=new \think\Template(['cache_path'=>$temp.'/templates/','tpl_cache'=>false,'taglib_pre_load'=>'app\\common\\taglib\\Maccms','default_filter'=>'']);
$render=function(string $source,array $vars)use($engine):string{ob_start();try{$engine->display($source,$vars);return (string)ob_get_contents();}finally{ob_end_clean();}};
$display=['maccms'=>['path'=>MAC_PATH,'path_tpl'=>'/fixture/','mid'=>2,'site_name'=>'Fixture','site_url'=>'fixture.invalid','site_wapurl'=>'fixture.invalid','site_email'=>'fixture@example.invalid','mob_status'=>0,'http_type'=>'https://','site_description'=>'Public description']];
$exports=[];
$restore();
foreach(['detail','read','ajax_detail','rss'] as $action){artRequest(['id'=>1,'page'=>2],2,[],$action);$page=new ArtPageProbe();if($action==='ajax_detail'){request()->withServer(['HTTP_X_REQUESTED_WITH'=>'XMLHttpRequest']);} $page->$action();noArtSecrets($page->assigned);check(count($page->assigned['obj']['art_page_list'])===3,'All frontend routes retain a safe chapter directory even when the password is missing');}
$session=$grant();purchase(1,2,3);
foreach(['detail','read','ajax_detail','rss'] as $action){artRequest(['id'=>1,'page'=>2],1,[],$action,$session);$page=new ArtPageProbe();if($action==='ajax_detail'){request()->withServer(['HTTP_X_REQUESTED_WITH'=>'XMLHttpRequest']);}$page->$action();noArtSecrets($page->assigned,$action==='rss'?[]:['BODY-PAGE-2']);check($page->assigned['param']['page']===2,'Every frontend action uses the actual authorized page');}
artRequest(['id'=>1,'page'=>200],1,[],'read',$session);$page=new ArtPageProbe();$page->read();check($page->assigned['param']['page']===3 && !$page->assigned['art_access']['can_access'],'Frontend reading normalizes the final page before checking page2-only ownership');noArtSecrets($page->assigned);
foreach([0,1,2] as $rewrite){$GLOBALS['config']['rewrite']['art_id']=$rewrite;artRequest(['id'=>1,'page'=>2],1,[],'read',$session);$page=new ArtPageProbe();$page->read();check($page->assigned['param']['id']===1 && $page->assigned['param']['page']===2,'Existing numeric reader links remain valid alongside numeric/name/encoded detail settings');noArtSecrets($page->assigned,['BODY-PAGE-2']);}
$GLOBALS['config']['rewrite']['art_id']=0;
// The actual front-end password form keeps its password bytes and uses the same article scope.
\think\facade\Db::name('art')->where('art_id',1)->update(['art_pwd'=>'a +&=0']);
artRequest(['mid'=>2,'id'=>1,'type'=>1,'pwd'=>'a +&=0']);$ajax=(new \ReflectionClass(\app\index\controller\Ajax::class))->newInstanceWithoutConstructor();$r=json_decode($ajax->pwd()->getContent(),true);check($r['code']===1,'The real Ajax article password accepts URL-sensitive password bytes');$sessionId=$app->session->getId();$app->session->save();
$r=artApi('get_read_page',['art_id'=>1,'page'=>2],1,[],$sessionId);check($r['info']['can_read']===1,'A guest-established Ajax password session works in an authenticated API read');noArtSecrets($r,['BODY-PAGE-2']);
foreach([4,5,12] as $badType){artRequest(['mid'=>2,'id'=>1,'type'=>$badType,'pwd'=>'a +&=0']);$r=json_decode($ajax->pwd()->getContent(),true);check($r['code']===1001,'An article password cannot create video/download/unknown scopes');}
$restore();
// New fallback is rendered as a whole file, including the real forms and safe local script attributes.
foreach(['password','purchase','allowed','long','whole-long'] as $state){$restore();if($state!=='password')\think\facade\Db::name('art')->where('art_id',1)->update(['art_pwd'=>'']);
    $requestedPage=2;$uid=$state==='allowed'?2:1;
    if(in_array($state,['long','whole-long'],true)){$requestedPage=300;\think\facade\Db::name('art')->where('art_id',1)->update(['art_content'=>implode('$$$',array_fill(0,300,'LONG-CHAPTER'))]);}
    if($state==='whole-long')$GLOBALS['config']['user']['art_points_type']='1';
    artRequest(['id'=>1,'page'=>$requestedPage],$uid,[],'read');$page=new ArtPageProbe();$template=$page->read();check(str_ends_with($template,'content/art.html'),'Missing reader/password templates choose the standalone fallback');
    $html=$render(file_get_contents(APP_PATH.'common/view/content/art.html'),$page->assigned+$display);
    $app->config->set(['type'=>'Think','view_path'=>$temp.'/missing-theme/','cache_path'=>$temp.'/view-cache/','tpl_cache'=>false,'default_filter'=>''],'view');\think\facade\View::assign($page->assigned+$display);$resolvedHtml=\think\facade\View::fetch($template);check($resolvedHtml===$html,'Real View facade resolves the absolute fallback even when the active theme lacks the template');
    noArtSecrets($html,$state==='allowed'?['BODY-PAGE-2']:[]);check(str_contains($html,'static/js/art-access.js') && !preg_match('/<script(?![^>]*\bsrc=)[^>]*>/',$html),'Standalone fallback uses the local production script and no inline JavaScript');
    if($state==='password')check(str_contains($html,'data-art-password') && !str_contains($html,'data-art-purchase'),'Password-gated fallback does not offer a purchase that substitutes for verification');
    if($state==='long')check(!str_contains($html,'data-art-purchase') && !str_contains($html,'LONG-CHAPTER'),'Unrepresentable single-chapter purchases have no active control and no body');
    if($state==='whole-long')check(str_contains($html,'data-page="1"') && $page->assigned['param']['page']===300,'Whole-work purchase chooses real page1 while the reader remains on page300');
    $exports[]=['state'=>$state,'html'=>$html];
}
$restore();\think\facade\Db::name('art')->where('art_id',1)->update(['art_pwd'=>'']);purchase(1,2,3);
foreach(['template/demo/html/art/detail.html','template/vozy/vo20w2/art/detail.html','template/m1938pc3_v2/html9/art/detail.html','template/stui_tpl/html/art/xiaoshuo_detail.html','template/stui_tpl/html/art/meitu_detail.html'] as $file){
    $text=file_get_contents(dirname(__DIR__,2).'/'.$file);$start=strpos($text,'{if condition="$art_static_catalog');check($start!==false,'Every legacy body template has a visible dynamic acquisition link');
    preg_match_all('/\{\/?if\b[^}]*\}/',substr($text,$start),$matches,PREG_OFFSET_CAPTURE);$depth=0;$end=0;foreach($matches[0] as [$tag,$offset]){$depth+=str_starts_with($tag,'{/')?-1:1;if($depth===0){$end=$offset+strlen($tag);break;}}$block=substr($text,$start,$end);
    foreach([0,1] as $uid){artRequest(['id'=>1,'page'=>2],$uid,[],'detail');$page=new ArtPageProbe();$page->detail();$html=$render($block,$page->assigned+$display);noArtSecrets($html,$uid===1?['BODY-PAGE-2']:[]);check($uid===1?str_contains($html,'BODY-PAGE-2'):str_contains($html,'index.php/art/read?'),'Legacy themes show only the permitted current body or a working acquisition link');}
    artRequest(['id'=>1,'page'=>2],2,[],'info');$page=new ArtPageProbe();$fresh=(new \app\common\model\Art())->infoData(['art_id'=>1],'*',0)['info'];(new \ReflectionMethod($page,'label_art_detail'))->invoke($page,$fresh,2);$html=$render($block,$page->assigned+$display);noArtSecrets($html);check(str_contains($html,'index.php/art/read?'),'Static article detail never publishes generator authorization and retains its dynamic reading link');
}
foreach(['template/default/html/rss/index.html','template/vozy/vo20w2/rss/index.html'] as $file){$source=file_get_contents(dirname(__DIR__,2).'/'.$file);$start=strpos($source,'{/maccms:vod}')+strlen('{/maccms:vod}');$end=strpos($source,'{/maccms:art}',$start);$source=substr($source,$start,$end-$start);$source=preg_replace('/\{maccms:art[^}]*\}/','',$source);
    $fresh=(new \app\common\model\Art())->infoData(['art_id'=>1],'*',0)['info'];$html=$render($source,['vo'=>$fresh]+$display);noArtSecrets($html);check(str_contains($html,'Public introduction'),'The shipped public RSS list uses an explicit public blurb, not paid body text');}
// Export actual rendered form markup for the real local JavaScript transport regression.
file_put_contents('/audit/art-access-pages.json',json_encode($exports,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
$restore();

// The default purchase widget consumes the new coordinate while all other media branches stay unchanged.
$widget=file_get_contents(dirname(__DIR__,2).'/template/default/html/widget/popedom_upgrade_gate.html');
foreach([0,1] as $whole){$restore();$GLOBALS['config']['user']['art_points_type']=(string)$whole;\think\facade\Db::name('art')->where('art_id',1)->update(['art_pwd'=>'','art_content'=>implode('$$$',array_fill(0,300,'LONG-CHAPTER'))]);
    artRequest(['id'=>1,'page'=>300],1,[],'read');$page=new ArtPageProbe();$page->read();$html=$render($widget,$page->assigned+$display);
    check($whole?str_contains($html,'data-sid="1"'):!str_contains($html,'class="qrgm js-popedom-buy-btn"'),'The shipped default widget uses a supported whole-work purchase page or omits an impossible single-chapter purchase');
    check($page->assigned['param']['page']===300,'Rendering the purchase widget never rewrites the current reader page');
}
$restore();\think\facade\Db::name('art')->where('art_id',1)->update(['art_pwd_url'=>'https://fixture.invalid/password-help']);
artRequest(['id'=>1,'page'=>2],2,[],'detail');$page=new ArtPageProbe();$page->detail();
$html=$render(file_get_contents(dirname(__DIR__,2).'/template/m1938pc3_v2/html9/art/detail_pwd.html'),$page->assigned+$display);
noArtSecrets($html);check(str_contains($html,'type="password"') && str_contains($html,'data-mid="2"') && str_contains($html,'data-type="1"') && str_contains($html,'password-help'),'The shipped legacy password template remains functional without exposing its stored password');
artRequest(['id'=>1,'page'=>2],2,[],'rss');$page=new ArtPageProbe();$page->rss();$html=$render(file_get_contents(dirname(__DIR__,2).'/template/m1938pc3_v2/html9/art/rss.html'),$page->assigned+$display);
noArtSecrets($html);check(str_contains($html,'Public introduction') && substr_count($html,'<item>')===3,'The legacy single-article RSS publishes the safe introduction and all chapter titles without bodies');
$restore();\think\facade\Db::name('art')->where('art_id',1)->update(['art_blurb'=>'']);$GLOBALS['config']['ai_seo']=['template_inject'=>'1'];
artRequest(['id'=>1,'page'=>2],2,[],'detail');$page=new ArtPageProbe();(new \ReflectionProperty(\app\common\controller\All::class,'_maccms'))->setValue($page,$display['maccms']);$page->detail();noArtSecrets($page->assigned);check(isset($page->assigned['maccms']),'Protected detail SEO is computed from the public projection');$GLOBALS['config']['ai_seo']=[];$restore();

// Make::info and Make::buildHtml both run for real and write only the temporary site's files.
$restore();$GLOBALS['config']['view']=['art_detail'=>2];$GLOBALS['config']['path']=['art_detail'=>'generated/art/{id}','page_sp'=>'-','suffix'=>'html'];
$source=file_get_contents(dirname(__DIR__,2).'/template/m1938pc3_v2/html9/art/detail.html');$source=preg_replace('/\{include\s+file="[^"]+"\s*\/?\}/','',$source);
$session=$grant(2);artRequest([],2,[],'info',$session);$make=new ArtMakeProbe();$make->renderer=fn($vars)=>$render($source,$vars+$display);
(new \ReflectionProperty(\app\admin\controller\Make::class,'_themeViewPath'))->setValue($make,dirname(__DIR__,2).'/template/m1938pc3_v2/html9/');
$make->_param=['tab'=>'art','ids'=>'1','arttype'=>[],'num'=>0,'start'=>1,'page_count'=>1,'data_count'=>0,'ac2'=>'','ref'=>0];
unset($GLOBALS['user']); // Real backend Make does not initialize a frontend identity.
$cwd=getcwd();chdir(ROOT_PATH);ob_start();try{$result=$make->info();}finally{ob_end_clean();chdir($cwd);}
check($result===null,'The actual Make article generation finishes');$files=glob(ROOT_PATH.'generated/art/*.html');check(count($files)===3,'Actual static generation preserves three separate article-page filenames');
foreach($files as $file){$html=file_get_contents($file);noArtSecrets($html);check(str_contains($html,'index.php/art/read?'),'Published static article files retain dynamic reading access without generator body/password grants');}
$_REQUEST=[];$GLOBALS['config']['view']=['art_detail'=>0];$restore();

foreach(['ajax_detail','rss'] as $action){artRequest(['id'=>1,'page'=>2],2,[],$action);request()->withServer(['HTTP_X_REQUESTED_WITH'=>'XMLHttpRequest']);$page=new ArtPageProbe();$template=$page->$action();
    check(is_file($template),'A shipped theme without article Ajax/RSS templates receives a real fallback file');$html=$render(file_get_contents($template),$page->assigned+$display);noArtSecrets($html);
    if($action==='rss')check(substr_count($html,'<item>')===3 && str_contains($html,'Public introduction'),'The RSS fallback preserves public metadata and safe chapter links without any body');
}
