<?php
/** Render actual default login form fragments with the real template engine and isolated route metadata. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
function url($route) { return '/fixture/index.php/'.$route; }
$temp=audit_temp_dir('auto-registration-views');
register_shutdown_function(static function() use ($temp): void { audit_remove_temp($temp); });
foreach (['login','ajax_login'] as $name) {
    $source=file_get_contents(dirname(__DIR__).'/template/default/html/user/'.$name.'.html');
    if (!preg_match('/<form\b[^>]*id="fm-login"[\s\S]*?<\/form>/',$source,$match)) { throw new RuntimeException('Actual login form missing'); }
    foreach ([0,1] as $enabled) {
        $GLOBALS['config']['user']=['login_verify'=>$enabled];
        $engine=new \think\Template(['cache_path'=>$temp.'/']);
        ob_start(); $engine->display($match[0],['maccms'=>['path_tpl'=>'/fixture/template/default']]); $html=ob_get_clean();
        check(str_contains($html,'name="verify"')===($enabled===1),'The actual '.$name.' form must render a login captcha exactly when configured');
        check(str_contains($html,'auth-login-verify')===($enabled===1),'The captcha refresh target must exist exactly when the challenge is enabled');
        check(str_contains($html,'name="user_name"') && str_contains($html,'name="user_pwd"'),'Normal form credentials must remain available');
        if ($enabled) { check(str_contains($html,'/fixture/index.php/verify/index'),'The challenge image must reach the real verification route'); }
    }
}
fwrite(STDOUT,'Automatic registration view audit passed ('.$checks." checks)\n");
