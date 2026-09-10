<?php
/** Render the actual purchase gate and iframe button fragments using the real template engine. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
function url($route) { return '/fixture/index.php/'.$route; }
$temp=audit_temp_dir('purchase-views');
register_shutdown_function(static function() use ($temp): void { audit_remove_temp($temp); });
function purchaseRender(string $source,array $data): string {
    global $temp;
    $engine=new \think\Template(['cache_path'=>$temp.'/']);
    ob_start();$engine->display($source,$data);return ob_get_clean();
}
$gate=file_get_contents(dirname(__DIR__).'/template/default/html/widget/popedom_upgrade_gate.html');
$base=['maccms'=>['path'=>'/fixture/','path_tpl'=>'/fixture/template/default'],'popedom'=>['points'=>10],
    'param'=>['sid'=>2,'nid'=>3,'page'=>4]];
foreach ([[1,'vod','play',4,2,3],[1,'vod','down',5,2,3],[2,'art','',1,4,0],[12,'manga','',1,2,3]] as [$mid,$kind,$flag,$type,$sid,$nid]) {
    $data=$base;$data['maccms']['mid']=$mid;$data['obj']=[$kind.'_id'=>17,'player_info'=>['flag'=>$flag]];
    if ($mid===12) {
        $data['manga_access']=['purchase_supported'=>true,'password_required'=>false,'purchase_sid'=>2,'purchase_nid'=>3];
        $data['param']['sid']=9;$data['param']['nid']=8;
    }
    $html=purchaseRender($gate,$data);
    preg_match('/<a\b[^>]*class="[^"]*js-popedom-buy-btn[^>]*>/',$html,$match);
    check(isset($match[0]),'Normal paid '.$kind.' gate must render an actionable purchase button');
    foreach (['mid'=>$mid,'id'=>17,'type'=>$type,'sid'=>$sid,'nid'=>$nid] as $name=>$value) {
        check(str_contains($match[0],'data-'.$name.'="'.$value.'"'),'Rendered '.$kind.' gate must supply correct '.$name);
    }
    check(str_contains($html,'MAC.User.BuyPopedomRequest($btn'),'Rendered gate must use the common token/POST purchase flow');
    $data['popedom']['points']=0;$html=purchaseRender($gate,$data);
    check(!preg_match('/<a\b[^>]*class="[^"]*js-popedom-buy-btn/',$html),'A membership-only gate must not show a paid-content purchase button');
    $data['popedom']['points']=10;$data['obj'][$kind.'_id']=0;$html=purchaseRender($gate,$data);
    check(!preg_match('/<a\b[^>]*class="[^"]*js-popedom-buy-btn/',$html),'A gate without a resource id must not offer an invalid purchase');
}
// The current Manga reader supplies verified purchase coordinates independently of raw route parameters.
$data=$base;$data['maccms']['mid']=12;$data['obj']=['manga_id'=>17];
foreach ([null, ['purchase_supported'=>false,'password_required'=>false],
    ['purchase_supported'=>true,'password_required'=>true]] as $access) {
    $data['manga_access']=$access;
    $html=purchaseRender($gate,$data);
    check(!preg_match('/<a\b[^>]*class="[^"]*js-popedom-buy-btn/',$html),
        'Unresolved, unsupported or password-locked manga must not offer a purchase button');
}
foreach (['template/default/html/vod/player.html'=>4,'template/m1938pc3_v2/html9/vod/downer.html'=>5] as $file=>$type) {
    $source=file_get_contents(dirname(__DIR__).'/'.$file);
    if(!preg_match('/<a\b[^>]*onclick="window\.parent\.MAC\.User\.BuyPopedom\(this\)"[^>]*>/',$source,$match)) {
        throw new RuntimeException('Actual parent-frame purchase button missing: '.$file);
    }
    $html=purchaseRender($match[0],['obj'=>['vod_id'=>17],'param'=>['sid'=>2,'nid'=>3]]);
    foreach (['mid'=>1,'id'=>17,'type'=>$type,'sid'=>2,'nid'=>3] as $name=>$value) {
        check(str_contains($html,'data-'.$name.'="'.$value.'"'),'Actual iframe button must render valid '.$name);
    }
}
fwrite(STDOUT,'Purchase view audit passed ('.$checks." checks)\n");
