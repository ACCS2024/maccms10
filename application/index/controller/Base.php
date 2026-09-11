<?php
namespace app\index\controller;
use app\common\controller\All;
use ip_limit\IpLocationQuery;
class Base extends All
{
    var $_group;
    var $_user;

    public function __construct()
    {
        parent::__construct();
        
        $this->check_ip_limit();
        $this->check_site_status();
        $this->label_maccms();
        $this->check_browser_jump();
        $this->label_user();
    }

    protected function check_ip_limit()
    {
       
        // 获取IP限制配置
        $mainland_ip_limit = $GLOBALS['config']['site']['mainland_ip_limit'] ?? "0";

        // 如果为0，不限制，直接通过
        if ($mainland_ip_limit == "0") {
            return;
        }
        
        // 获取用户真实IP
        $user_ip = mac_get_client_ip();
        try {
            $ipQuery = new IpLocationQuery();
            $country_code = $ipQuery->queryProvince($user_ip);
        } catch (\Exception $e) {
            // Preserve the existing lookup-failure policy; response termination must remain outside this catch.
            return;
        }
        if (($mainland_ip_limit == "1" && $country_code === "")
            || ($mainland_ip_limit == "2" && $country_code !== "")) {
            throw new \think\exception\HttpResponseException(\think\Response::create($this->fetch('public/close')));
        }
    }

    public function _empty()
    {
        abort(404, lang('page_not_found'));
    }

    protected function check_show($aj=0)
    {
        if($GLOBALS['config']['app']['show'] ==0){
            throw new \think\exception\HttpResponseException($this->error(lang('show_close')));
        }
        if($GLOBALS['config']['app']['show_verify'] ==1 && $aj==0){
            if(empty(session('show_verify'))){
                mac_no_cahche();
                $this->assign('type','show');
                throw new \think\exception\HttpResponseException(\think\Response::create($this->label_fetch('public/verify')));
            }
        }
    }

    protected function check_ajax()
    {
        if($GLOBALS['config']['app']['ajax_page'] ==0){
            throw new \think\exception\HttpResponseException($this->error(lang('ajax_close')));
        }
    }

    protected function check_search($param,$aj=0)
    {
        if($GLOBALS['config']['app']['search'] ==0){
            throw new \think\exception\HttpResponseException($this->error(lang('search_close')));
        }
        $page = isset($param['page']) ? (int)$param['page'] : 1;
        if ($page === 1 && mac_get_time_span("last_searchtime") < $GLOBALS['config']['app']['search_timespan']) {
            throw new \think\exception\HttpResponseException($this->error(lang('search_frequently')."".$GLOBALS['config']['app']['search_timespan']."".lang('seconds')));
        }
        if($GLOBALS['config']['app']['search_verify'] ==1 && $aj ==0){
            if(empty(session('search_verify'))){
                mac_no_cahche();
                $this->assign('type','search');
                throw new \think\exception\HttpResponseException(\think\Response::create($this->label_fetch('public/verify')));
            }
        }
    }

    protected function check_site_status()
    {
        if ($GLOBALS['config']['site']['site_status'] == 0) {
            $this->assign('close_tip',$GLOBALS['config']['site']['site_close_tip']);
            throw new \think\exception\HttpResponseException(\think\Response::create($this->fetch('public/close')));
        }
    }

    protected function check_browser_jump()
    {
        if (ENTRANCE=='index' && $GLOBALS['config']['app']['browser_junmp'] == 1) {
            $agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
            if (is_string($agent) && (str_contains($agent, 'QQ/') || str_contains($agent, 'MicroMessenger'))){
                throw new \think\exception\HttpResponseException(\think\Response::create($this->fetch('public/browser')));
            }
        }
    }
}