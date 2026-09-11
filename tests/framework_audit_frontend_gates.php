<?php
/** Actual shared frontend gates and response types; local template/session boundaries. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
function request() { return \think\Container::getInstance()->make('request'); }
function lang($key, ...$vars) { return $key; }
function json($data) { return \think\Response::create($data, 'json'); }
function config($name, $default = null) { return \think\facade\Config::get($name, $default); }
function session($name) { return $GLOBALS['gate_session'][$name] ?? null; }
function mac_no_cahche() { $GLOBALS['gate_nocache'] = true; }
function mac_get_client_ip() { return $GLOBALS['gate_ip']; }
function mac_get_time_span($name) { return $GLOBALS['gate_span']; }
function abort($code, $message) { throw new \think\exception\HttpException($code, $message); }
class FrontendGateFixture extends \app\index\controller\Base {
    public function __construct() {}
    protected function assign($name, $value = ''): void { $GLOBALS['gate_assigned'][$name] = $value; }
    protected function fetch(string $template = '', array $vars = []): string { return 'rendered:'.$template; }
    protected function label_fetch($template, $loadcache = 1, $type = 'html') { return $this->fetch($template); }
    public function gate($name, ...$args) { return $this->$name(...$args); }
}
define('ENTRANCE', 'index');
$app = new \think\App(sys_get_temp_dir().'/frontend-gates/');
$fixture = new FrontendGateFixture();
function gateReset(bool $ajax = false): void {
    global $app;
    $GLOBALS['config'] = ['site'=>['mainland_ip_limit'=>'0', 'site_status'=>1, 'site_close_tip'=>'maintenance'],
        'app'=>['show'=>1, 'ajax_page'=>1, 'search'=>1, 'search_timespan'=>5, 'show_verify'=>0, 'search_verify'=>0, 'browser_junmp'=>0]];
    $GLOBALS['gate_session'] = []; $GLOBALS['gate_assigned'] = []; $GLOBALS['gate_nocache'] = false;
    $GLOBALS['gate_ip'] = '1.0.1.1'; $GLOBALS['gate_span'] = 60;
    $_SERVER['HTTP_USER_AGENT'] = 'ordinary-browser';
    $app->instance('request', (new \think\Request())->withServer(['HTTP_X_REQUESTED_WITH'=>$ajax ? 'XMLHttpRequest' : '']));
}
function gateCall(string $name, bool $stops, string $body = '', array $arguments = []): void {
    global $fixture;
    $finished = false; $returned = false; $response = null;
    ob_start();
    try {
        try { $fixture->gate($name, ...$arguments); $returned = true; }
        catch (\think\exception\HttpResponseException $error) { $response = $error->getResponse(); }
        finally { $finished = true; }
    } finally { $output = ob_get_clean(); }
    check($finished && $output === '', 'Gate must unwind without emitting output');
    check($returned === !$stops, 'Gate stop/pass result differs: '.$name);
    if ($stops) {
        check($response instanceof \think\Response && $response->getCode() === 200, 'Gate keeps its ordinary response status');
        check($response instanceof \think\response\Json ? $response->getData()['msg'] === $body : $response->getContent() === $body, 'Gate response differs: '.$name);
    }
}
foreach (['check_show','check_ajax','check_site_status','check_browser_jump'] as $name) { gateReset(); gateCall($name, false); }
gateReset(); gateCall('check_search', false, '', [[]]);
foreach (['show'=>'check_show','ajax_page'=>'check_ajax','search'=>'check_search'] as $option=>$name) {
    gateReset(true); $GLOBALS['config']['app'][$option] = 0;
    gateCall($name, true, $option === 'ajax_page' ? 'ajax_close' : $option.'_close', $name === 'check_search' ? [[]] : []);
}
foreach (['show'=>'check_show','search'=>'check_search'] as $option=>$name) {
    gateReset(); $GLOBALS['config']['app'][$option.'_verify'] = 1;
    $args = $option === 'search' ? [[]] : [];
    gateCall($name, true, 'rendered:public/verify', $args);
    check($GLOBALS['gate_nocache'] && $GLOBALS['gate_assigned']['type'] === $option, 'Verification preserves private rendering state');
    $GLOBALS['gate_session'][$option.'_verify'] = 1;
    gateCall($name, false, '', $args);
    $GLOBALS['gate_session'] = [];
    gateCall($name, false, '', $option === 'search' ? [[],1] : [1]);
}
gateReset(true); $GLOBALS['gate_span'] = 0;
gateCall('check_search', true, 'search_frequently5seconds', [[]]);
gateCall('check_search', false, '', [['page'=>2]]);
gateReset(); $GLOBALS['config']['site']['site_status'] = 0;
gateCall('check_site_status', true, 'rendered:public/close');
check($GLOBALS['gate_assigned']['close_tip'] === 'maintenance', 'Site close message must reach the template');
foreach (['QQ/1', 'ordinary QQ/1', 'MicroMessenger/1', 'ordinary MicroMessenger/1'] as $agent) {
    gateReset(); $GLOBALS['config']['app']['browser_junmp'] = 1; $_SERVER['HTTP_USER_AGENT'] = $agent;
    gateCall('check_browser_jump', true, 'rendered:public/browser');
}
foreach (['ordinary-browser', '', []] as $agent) {
    gateReset(); $GLOBALS['config']['app']['browser_junmp'] = 1; $_SERVER['HTTP_USER_AGENT'] = $agent;
    gateCall('check_browser_jump', false);
}
foreach ([['0','1.0.1.1',false], ['1','1.0.1.1',false], ['1','8.8.8.8',true], ['2','1.0.1.1',true], ['2','8.8.8.8',false]] as [$mode,$ip,$denied]) {
    gateReset(); $GLOBALS['config']['site']['mainland_ip_limit'] = $mode; $GLOBALS['gate_ip'] = $ip;
    gateCall('check_ip_limit', $denied, 'rendered:public/close');
}
gateReset();
try { $fixture->_empty(); check(false, 'Unknown action must stop'); }
catch (\think\exception\HttpException $error) { check($error->getStatusCode() === 404, 'Unknown action must retain the 404 status'); }
echo 'Frontend gates: '.$checks.' checks passed on PHP '.PHP_VERSION."\n";
