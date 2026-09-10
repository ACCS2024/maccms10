<?php
/** Render the actual legacy plan template with TP8's template engine in a temporary cache. */
require __DIR__ . '/fixtures/security_audit_order_create.php';
$directory = audit_temp_dir('member-price-template');
try {
    $source = file_get_contents(dirname(__DIR__) . '/template/default/html/user/ajax_upgrade.html');
    // The recharge modal is an independent component; keep all plan expressions/markup unchanged.
    $source = preg_replace('/\{include\s+file="widget\/recharge_modal"\s*\/\}/', '', $source);
    $template = new \think\Template(['cache_path'=>$directory . '/', 'tpl_cache'=>false]);
    foreach ([['2.4',20,'8.33'], ['8',1,'0.13'], ['201',1,null], ['100',0,'0.00'], [null,0,'0.00']] as [$scale,$points,$price]) {
        creationSeed(['scale'=>$scale,'min'=>'0']);
        creationRequest([], 'ajax_upgrade', '/index.php', 'GET');
        $group = $GLOBALS['member_groups'][3];
        foreach (['day','week','month','year'] as $period) { $group['group_points_' . $period] = $points; }
        $data = ['maccms'=>['path_tpl'=>'/fixture/'], 'obj'=>$GLOBALS['user'], 'user'=>['group'=>['group_name'=>'registered']],
            'group_list'=>[$group], 'pay_config'=>['scale'=>$scale]];
        ob_start();
        try { $template->display($source, $data); $html = ob_get_contents(); } finally { ob_end_clean(); }
        check(substr_count($html, 'class="grade"') === 4, 'Price display disabled the existing point-balance upgrade controls');
        if ($points === 0) {
            check(substr_count($html, '免费开通') === 4, 'Explicit free plan labels were removed');
        } elseif ($price === null) {
            check(substr_count($html, '仅支持积分兑换') === 4 && !str_contains($html, '￥0'), 'Unpayable periods were shown as cash-free');
        } else {
            check(substr_count($html, 'data-price="' . $price . '"') === 4 && substr_count($html, '￥' . $price) === 4,
                'Displayed price and payment metadata differ from the shared exact quote');
        }
    }
    echo "order price template audit: $checks checks passed on PHP " . PHP_VERSION . "\n";
} finally { audit_remove_temp($directory); }
