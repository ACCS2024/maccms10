<?php
namespace app\common\controller;
use think\facade\Cache;
use think\facade\Request;

class All
{
    protected bool $persistExpiredMemberGroup = true;
    var $_ref;
    var $_cl;
    var $_ac;
    var $_tsp;
    var $_url;
    protected $_page_sf_lock = false; // 整页缓存单飞:本请求持有的锁键(产出后释放)
    protected $request;
    protected $_maccms = [];

    public function __construct()
    {
        if (method_exists($this, 'initialize')) {
            $this->initialize();
        }
        $this->request = request();
        $this->_ref = mac_get_refer();
        $this->_cl = request()->controller();
        $this->_ac = request()->action();
        $this->_tsp = date('Ymd');
    }

    protected function load_page_cache($tpl,$type='html')
    {
        // 开启防红防封时，首页不使用缓存，确保每次都进行浏览器检查
        if($tpl == 'index/index' && !empty($GLOBALS['config']['app']['browser_junmp']) && $GLOBALS['config']['app']['browser_junmp'] == 1) {
            return;
        }
        // 发布页走 Index::fetch_site_publish_view，不经此处 tpl；保留兼容旧 tpl 名
        if ($tpl == 'index/publish' || $tpl == 'index/publish_group') {
            return;
        }

        if (mac_page_cache_eligible()) {
            // Only an anonymous public catalog reaches the shared internal page cache.
            // SecurityHeaders separately checks outgoing Session/Cookie effects before transport caching.
            $GLOBALS['_mac_page_cacheable'] = (int)$GLOBALS['config']['app']['cache_time_page'];
            $cach_name = $this->page_cache_key($tpl);
            $res = Cache::get($cach_name);
            if (empty($res)) {
                // 防击穿:抢锁者回源产出(label_fetch set 后释放);未抢到者短等他人结果,超时再自行产出
                if (mac_cache_lock_acquire($cach_name, 15)) {
                    $this->_page_sf_lock = $cach_name;
                } else {
                    $res = mac_cache_singleflight_wait($cach_name);
                }
            }
            if (!empty($res)) {
                // 修复后台开启页面缓存时，模板json请求解析问题
                // https://github.com/magicblack/maccms10/issues/965
                $accept = request()->header('accept');
                if($type=='json' || (is_string($accept) && str_contains($accept, 'application/json'))){
                    $res = json_encode($res);
                }
                if (!headers_sent()) {
                    // This direct response bypasses the outer Session/security middleware.
                    header('Cache-Control: private, no-store');
                }
                echo $res;
                die;
            }
        }
    }

    /**
     * 整页缓存键(load 与 fetch 共用,保证一致);含 host/移动端标记/缓存标识/模板/查询参数,
     * 不含用户维度(仅匿名命中,见 mac_page_cache_eligible)。
     */
    protected function page_cache_key($tpl)
    {
        return 'public-v2_' . ($_SERVER['HTTP_HOST'] ?? '') . '_'. MAC_MOB . '_'. $GLOBALS['config']['app']['cache_flag']. '_' .$tpl .'_'. http_build_query(mac_param_url());
    }

    protected function label_fetch($tpl,$loadcache=1,$type='html')
    {
        if($loadcache==1){
            $this->load_page_cache($tpl,$type);
        }
        $html = $this->fetch($tpl);
        if($GLOBALS['config']['app']['compress'] == 1){
            $html = mac_compress_html($html);
        }
        if (mac_page_cache_eligible()) {
            $cach_name = $this->page_cache_key($tpl);
            Cache::set($cach_name,$html,$GLOBALS['config']['app']['cache_time_page']);
        }
        // 释放整页缓存单飞锁(本请求产出完毕)
        if ($this->_page_sf_lock) {
            mac_cache_lock_release($this->_page_sf_lock);
            $this->_page_sf_lock = false;
        }
        // 已移除 site_polyfill 注入:该功能会向所有前台页面插入第三方脚本
        // https://polyfill-js.cn/v3/polyfill.min.js,并同时把页面 referrer 策略
        // 从 no-referrer 放宽为 always。polyfill.io 及其克隆域名有供应链投毒前科,
        // 不接受这种外部可控的 JS 注入点。site_polyfill 配置项保留但不再产生任何输出。
        return $html;
    }

    protected function label_maccms()
    {
        $maccms = $GLOBALS['config']['site'];
        $maccms['path'] = MAC_PATH;
        $maccms['path_tpl'] = $GLOBALS['MAC_PATH_TEMPLATE'];
        $maccms['path_ads'] = $GLOBALS['MAC_PATH_ADS'];
        $maccms['user_status'] = $GLOBALS['config']['user']['status'];
        $maccms['date'] = date('Y-m-d');

        $maccms['search_hot'] = $GLOBALS['config']['app']['search_hot'];
        $maccms['art_extend_class'] = $GLOBALS['config']['app']['art_extend_class'];
        $maccms['vod_extend_class'] = $GLOBALS['config']['app']['vod_extend_class'];
        $maccms['vod_extend_state'] = $GLOBALS['config']['app']['vod_extend_state'];
        $maccms['vod_extend_version'] = $GLOBALS['config']['app']['vod_extend_version'];
        $maccms['vod_extend_area'] = $GLOBALS['config']['app']['vod_extend_area'];
        $maccms['vod_extend_lang'] = $GLOBALS['config']['app']['vod_extend_lang'];
        $maccms['vod_extend_year'] = $GLOBALS['config']['app']['vod_extend_year'];
        $maccms['vod_extend_weekday'] = $GLOBALS['config']['app']['vod_extend_weekday'];
        $maccms['actor_extend_area'] = $GLOBALS['config']['app']['actor_extend_area'];

        $maccms['http_type'] = $GLOBALS['http_type'];
        $maccms['http_url'] = $GLOBALS['http_type'] . ($_SERVER['SERVER_NAME'] ?? '') . ((($_SERVER['SERVER_PORT'] ?? 80) == 80) ? '' : ':' . ($_SERVER['SERVER_PORT'] ?? 80)) . ($_SERVER['REQUEST_URI'] ?? '');
        $maccms['seo'] = $GLOBALS['config']['seo'];
        $GLOBALS['type_id'] = $GLOBALS['type_id'] ?? 0;
        $GLOBALS['type_pid'] = $GLOBALS['type_pid'] ?? 0;
        $GLOBALS['aid'] = $GLOBALS['aid'] ?? 0;
        $GLOBALS['mid'] = $GLOBALS['mid'] ?? 0;
        $this->assign('param', mac_param_url());
        $this->assign('popedom', ['code' => 1, 'msg' => '', 'trysee' => 0, 'confirm' => 0]);
        $maccms['controller_action'] = $this->_cl .'/'.$this->_ac;

        if(!empty($GLOBALS['mid'])) {
            $maccms['mid'] = $GLOBALS['mid'];
        }
        else{
            $maccms['mid'] = mac_get_mid($this->_cl);
        }
        if(!empty($GLOBALS['aid'])) {
            $maccms['aid'] = $GLOBALS['aid'];
        }
        else{
            $maccms['aid'] = mac_get_aid($this->_cl,$this->_ac);
        }
        $this->_maccms = $maccms;
        $this->assign( ['maccms'=>$maccms] );
        // 默认模板主题配置
        $this->assign('tplconfig', $GLOBALS['mctheme']);
        $this->assign('mac_vod_playlink', mac_tpl_vod_playlink_on() ? 1 : 0);
    }

    protected function page_error($msg='')
    {
        if(empty($msg)){
            $msg=lang('controller/an_error_occurred');
        }
        $url = \think\facade\Request::isAjax() ? '' : 'javascript:history.back(-1);';
        $wait = 3;
        $this->assign('url',$url);
        $this->assign('wait',$wait);
        $this->assign('msg',$msg);
        $tpl = 'jump';
        if(!empty($GLOBALS['config']['app']['page_404'])){
            $tpl = $GLOBALS['config']['app']['page_404'];
        }
        // 后台的「404 模板」是一个自由文本框(system/config.html:825),而主题是第三方产物 ——
        // 一旦填的名字在当前主题里不存在(默认值 '404' 在本仓库自带的 vozy 主题里就没有),
        // label_fetch 抛 TemplateNotFoundException,于是【每一个 404 都变成 500】。
        // 对内容站这是实打实的 SEO 损失,而且症状出现在"页面本来就不存在"的路径上,最难被发现。
        // 逐级降级:配置的模板 → jump(主题基本都有) → 纯文本 404,任何一级都不让它变成 5xx。
        $tplRoot = isset($GLOBALS['MAC_ROOT_TEMPLATE']) ? $GLOBALS['MAC_ROOT_TEMPLATE'] : '';
        $suffix  = '.' . ltrim((string)config('view.view_suffix') ?: 'html', '.');
        if ($tplRoot !== '' && !is_file($tplRoot . 'public/' . $tpl . $suffix)) {
            $tpl = 'jump';
        }
        header("HTTP/1.1 404 Not Found");
        header("Status: 404 Not Found");
        if ($tplRoot !== '' && !is_file($tplRoot . 'public/' . $tpl . $suffix)) {
            header('Content-Type: text/html; charset=utf-8');
            exit('<!doctype html><meta charset="utf-8"><title>404</title><h1>404</h1><p>'
                . htmlspecialchars((string)$msg, ENT_QUOTES) . '</p>');
        }
        $html = $this->label_fetch('public/'.$tpl);
        exit($html);
    }

    protected function label_user()
    {
        // api 模块需填充 $GLOBALS['user']，供 check_user_popedom 等与前台一致的阅读权限判断
        if (ENTRANCE != 'index' && ENTRANCE != 'api') {
            return;
        }
        $hasLoginCookies = cookie('user_id') !== null || cookie('user_name') !== null || cookie('user_check') !== null;
        $user = ['user_id'=>0,'user_name'=>lang('controller/visitor'),'user_portrait'=>'static_new/images/touxiang.png','group_id'=>1,'points'=>0,'user_points'=>0];
        $group_list = (new \app\common\model\Group())->getCache();
        // checkLogin owns Cookie/Bearer precedence, validation and account/group expiry.
        // A valid Bearer does not require a parallel set of login Cookies.
        $authorization = request()->header('authorization');
        $res = ['code' => 1001];
        if (($authorization === null || is_string($authorization)) && ($hasLoginCookies || $authorization !== null && $authorization !== '')) {
            $res = (new \app\common\model\User())->checkLogin($this->persistExpiredMemberGroup);
        }
        if($res['code'] == 1){
            $user = $res['info'];
        }
        else{
            if($hasLoginCookies){
                cookie('user_id','0');
                cookie('user_name',lang('controller/visitor'));
                cookie('user_check','');
            }
            $user['group'] = $group_list[1];
        }
        // 顶栏 VIP 徽标等：与会员组逻辑一致（付费组 max(group_id)>=3），不依赖未使用的 is_member cookie
        $user['vip_nav'] = 0;
        if (!empty($user['user_id']) && !empty($user['group_id'])) {
            $gids = array_map('intval', explode(',', (string)$user['group_id']));
            $gids = array_filter($gids);
            if (!empty($gids) && max($gids) >= 3) {
                $user['vip_nav'] = 1;
            }
        }
        $GLOBALS['user'] = $user;
        // 安全加固:模板变量 user 会渲染进每个登录页的 HTML。剥离会话伪造相关字段后再下发——
        // user_random 是构造登录 cookie(md5(user_random-name-id-))与 JWT 的密钥、user_pwd 为口令哈希,
        // 不属任何前台展示需求;避免自定义主题误打印 {$user.user_random} 或经 XSS 读取 DOM 致会话伪造。
        // $GLOBALS['user'] 仍保留完整行供服务端逻辑使用(服务端不读这两个字段)。
        $tpl_user = $user;
        unset($tpl_user['user_pwd'], $tpl_user['user_random']);
        $this->assign('user',$tpl_user);
    }

    protected function label_comment()
    {
        $comment = config('maccms.comment');
        $this->assign('comment',$comment);
    }

    /**
     * 详情页：将 AI SEO 或默认字段合并到 maccms，供模板使用 page_detail_* 变量
     */
    protected function mergeDetailSeoIntoMaccms($mid, array $info, $seoAi)
    {
        $cfg = isset($GLOBALS['config']['ai_seo']) ? $GLOBALS['config']['ai_seo'] : [];
        if (empty($cfg['template_inject']) || (string)$cfg['template_inject'] !== '1') {
            return;
        }
        if (empty($this->_maccms)) {
            return;
        }
        $mac = $this->_maccms;
        $row = [];
        if ($seoAi) {
            if (is_object($seoAi) && method_exists($seoAi, 'toArray')) {
                $row = $seoAi->toArray();
            } elseif (is_array($seoAi)) {
                $row = $seoAi;
            }
        }
        $siteName = isset($GLOBALS['config']['site']['site_name']) ? (string)$GLOBALS['config']['site']['site_name'] : '';
        if ((int)$mid === 1) {
            $defaultTitle = (string)$info['vod_name'] . ($siteName !== '' ? ' - ' . $siteName : '');
            $defaultKw = mac_format_text(trim((string)$info['vod_tag'] . ',' . (string)$info['vod_class']), true);
            $defaultDesc = trim(strip_tags((string)$info['vod_blurb']));
            if ($defaultDesc === '') {
                $defaultDesc = mac_substring(strip_tags((string)$info['vod_content']), 160);
            }
        } else {
            $defaultTitle = (string)$info['art_name'] . ($siteName !== '' ? ' - ' . $siteName : '');
            $defaultKw = mac_format_text(trim((string)$info['art_tag'] . ',' . (string)$info['art_class']), true);
            $defaultDesc = trim(strip_tags((string)$info['art_blurb']));
            if ($defaultDesc === '') {
                $plain = str_replace('$$$', '', strip_tags((string)$info['art_content']));
                $defaultDesc = mac_substring($plain, 160);
            }
        }
        $mac['page_detail_title'] = mac_filter_xss(!empty($row['seo_title']) ? (string)$row['seo_title'] : $defaultTitle);
        $mac['page_detail_keywords'] = mac_filter_xss(!empty($row['seo_keywords']) ? (string)$row['seo_keywords'] : $defaultKw);
        $mac['page_detail_description'] = mac_filter_xss(!empty($row['seo_description']) ? (string)$row['seo_description'] : $defaultDesc);
        $this->assign('maccms', $mac);
    }

    protected function label_search($param)
    {
        $param = mac_filter_words($param);
        $param = mac_search_len_check($param);
        // vod/search 各个参数下都可能出现回显关键词
        if(!empty($GLOBALS['config']['app']['wall_filter'])){
            $param = mac_escape_param($param);
        }
        $this->assign('param',$param);
    }

    protected function label_type($view=0, $type_id_specified = 0)
    {
        $param = mac_param_url();
        $param = mac_filter_words($param);
        $param = mac_search_len_check($param);
        $info = mac_label_type($param, $type_id_specified);
        if(!empty($GLOBALS['config']['app']['wall_filter'])){
            $param['wd'] = mac_escape_param($param['wd']);
        }
        $this->assign('param',$param);
        $this->assign('obj',$info);
        if(empty($info)){
            return $this->error(lang('controller/get_type_err'));
        }
        if($view<2) {
            $res = $this->check_user_popedom($info['type_id'], 1);
            if($res['code']>1){
                echo $this->error($res['msg'], mac_url('user/index') );
                exit;
            }
        }
        return $info;
    }

    protected function label_actor($total='')
    {
        $param = mac_param_url();
        $this->assign('param',$param);
    }

    protected function label_actor_detail($info=[],$view=0)
    {
        $param = mac_param_url();
        $this->assign('param',$param);
        if(empty($info)) {
            $res = mac_label_actor_detail($param);
            if ($res['code'] > 1) {
                $this->page_error($res['msg']);;
            }
            $info = $res['info'];
        }

        if(empty($info['actor_tpl'])){
            $info['actor_tpl'] = $info['type']['type_tpl_detail'];
        }

        if($view <2) {
            $popedom = $this->check_user_popedom($info['type_id'], 2,$param,'actor',$info);
            $this->assign('popedom',$popedom);

            if($popedom['code']>1){
                $this->assign('obj',$info);

                if($popedom['confirm']==1){
                    echo $this->fetch('actor/confirm');
                    exit;
                }

                echo $this->error($popedom['msg'], mac_url('user/index') );
                exit;
            }
        }

        $this->assign('obj',$info);
        $this->assign('comment_mid', 8);
        $this->assign('comment_rid', $info['actor_id']);
        $comment = config('maccms.comment');
        $this->assign('comment',$comment);
        return $info;
    }


    protected function label_role($total='')
    {
        $param = mac_param_url();
        $param = mac_filter_words($param);
        $param = mac_search_len_check($param);
        if(!empty($GLOBALS['app']['wall_filter'])){
            $param['wd'] = mac_escape_param($param['wd']);
        }
        $this->assign('param',$param);
    }

    protected function label_role_detail($info=[])
    {
        $param = mac_param_url();
        $this->assign('param',$param);
        if(empty($info)) {
            $res = mac_label_role_detail($param);
            if ($res['code'] > 1) {
                $this->page_error($res['msg']);;
            }
            $info = $res['info'];
        }
        $this->assign('obj',$info);
        $this->assign('comment_mid', 9);
        $this->assign('comment_rid', $info['role_id']);
        $comment = config('maccms.comment');
        $this->assign('comment',$comment);

        return $info;
    }

    protected function label_website_detail($info=[],$view=0)
    {
        $param = mac_param_url();
        $this->assign('param',$param);
        if(empty($info)) {
            $res = mac_label_website_detail($param);
            if ($res['code'] > 1) {
                $this->page_error($res['msg']);;
            }
            $info = $res['info'];
        }

        if(empty($info['website_tpl'])){
            $info['website_tpl'] = $info['type']['type_tpl_detail'];
        }

        if($view <2) {
            $popedom = $this->check_user_popedom($info['type_id'], 2,$param,'website',$info);
            $this->assign('popedom',$popedom);

            if($popedom['code']>1){
                $this->assign('obj',$info);

                if($popedom['confirm']==1){
                    echo $this->fetch('website/confirm');
                    exit;
                }

                echo $this->error($popedom['msg'], mac_url('user/index') );
                exit;
            }
        }

        $this->assign('obj',$info);
        $this->assign('comment_mid', 11);
        $this->assign('comment_rid', $info['website_id']);
        $comment = config('maccms.comment');
        $this->assign('comment',$comment);

        return $info;
    }

    protected function label_topic_index($total='')
    {
        $param = mac_param_url();
        $this->assign('param',$param);

        if($total=='') {
            $where = [];
            $where['topic_status'] = 1;
            $total = (new \app\common\model\Topic())->countData($where);
        }

        $url = mac_url_topic_index(['page'=>'PAGELINK']);
        $__PAGING__ = mac_page_param($total,1,$param['page'],$url);
        $this->assign('__PAGING__',$__PAGING__);
    }

    protected function label_topic_detail($info=[])
    {
        $param = mac_param_url();
        $this->assign('param',$param);
        if(empty($info)) {
            $res = mac_label_topic_detail($param);
            if ($res['code'] > 1) {
                $this->page_error($res['msg']);;
            }
            $info = $res['info'];
        }
        $this->assign('obj',$info);
        $this->assign('comment_mid', 3);
        $this->assign('comment_rid', $info['topic_id']);

        $comment = config('maccms.comment');
        $this->assign('comment',$comment);

        return $info;
    }

    protected function label_art_detail($info=[],$view=0,$fullPointsPopedom=false,$publicCatalog=false)
    {
        $raw = array_merge(request()->param(), $_REQUEST);
        if (!\app\common\util\ContentResource::scalarParameters($raw)
            || (array_key_exists('page', $raw) && \app\common\util\ContentResource::positiveInt($raw['page']) === null)) {
            $this->page_error(lang('param_err'));
        }
        if (empty($info) && (empty($GLOBALS['config']['rewrite']['art_id'])
            ? \app\common\util\ContentResource::positiveInt($raw['id'] ?? null) === null
            : !is_string($raw['id'] ?? null) || $raw['id'] === '')) {
            $this->page_error(lang('param_err'));
        }
        $param = mac_param_url();
        if (empty($info)) {
            $res = mac_label_art_detail($param, 0);
            if ($res['code'] !== 1) {
                $this->page_error($res['msg']);
            }
            $info = $res['info'];
        }
        if ((int)($info['art_status'] ?? 0) !== 1 || (int)($info['art_recycle_time'] ?? 0) !== 0) {
            $this->page_error(lang('obtain_err'));
        }
        $info['art_tpl'] = ($info['art_tpl'] ?? '') ?: ($info['type']['type_tpl_detail'] ?? '');
        if ($view < 2 && !$fullPointsPopedom && !$publicCatalog) {
            $detailPermission = $this->check_user_popedom($info['type_id'], 2);
            if ($detailPermission['code'] > 1) {
                echo $this->error($detailPermission['msg'], mac_url('user/index'));
                exit;
            }
        }
        $context = \app\common\util\ContentResource::artContext($info, $param);
        if ($context['code'] !== 1 && $fullPointsPopedom) {
            $this->page_error($context['msg']);
        }
        $param['id'] = (int)$info['art_id'];
        $param['page'] = $context['code'] === 1 ? $context['page'] : 1;
        // Admin generation has no frontend user context. Static catalogs and RSS must never
        // query creator purchases or inherit a creator's password verification result.
        $publicOnly = $view >= 2 || strtolower(request()->action()) === 'rss';
        if ($publicOnly) {
            $access = ['code'=>3001, 'msg'=>'正文请进入阅读页查看', 'can_access'=>false,
                'password_required'=>\app\common\util\ContentPassword::artState($info)['required'],
                'points_hint'=>$context['points'] ?? 0, 'points'=>0, 'purchase_supported'=>false,
                'purchase_page'=>0, 'trysee'=>0, 'confirm'=>0];
        } else {
            $access = $context['code'] === 1 ? $this->check_art_resource_access($info, ['page'=>$param['page']])
                : $context + ['can_access'=>false, 'password_required'=>!\app\common\util\ContentPassword::artState($info)['verified'],
                    'points_hint'=>0, 'purchase_supported'=>false, 'purchase_page'=>0, 'trysee'=>0, 'confirm'=>0];
        }
        $authorizedPage = !$publicOnly && $access['can_access'] ? $param['page'] : null;
        $template = \app\common\util\ContentResource::artTemplate($info, $authorizedPage);
        $this->assign('param', $param);
        $this->assign('popedom', $access);
        $this->assign('art_access', $access);
        $this->assign('art_read_link', \app\common\util\ContentResource::artReadLink($info, $param['page']));
        $this->assign('art_static_catalog', $publicOnly);
        $this->assign('obj', $template);
        $seo_ai = (new \app\common\model\SeoAiResult())->getByObject(2, (int)$info['art_id']);
        $this->assign('seo_ai', $seo_ai);
        // An absent public blurb must not turn protected body text into a public SEO description.
        $this->mergeDetailSeoIntoMaccms(2, \app\common\util\ContentResource::artTemplate($info), $seo_ai);
        $url = mac_url_art_detail($info, ['page'=>'PAGELINK']);
        $this->assign('__PAGING__', mac_page_param($template['art_page_total'], 1, $param['page'], $url));
        $this->assign('comment_mid', 2);
        $this->assign('comment_rid', $info['art_id']);
        $this->label_comment();
        return $info;
    }

    protected function check_art_resource_access(array $info, array $param): array
    {
        $context = \app\common\util\ContentResource::artContext($info, $param);
        if ($context['code'] !== 1) {
            return $context + ['can_access'=>false, 'trysee'=>0, 'confirm'=>0, 'purchase_supported'=>false];
        }
        $permission = $this->check_user_popedom((int)$info['type_id'], 3,
            ['id'=>$context['id'], 'page'=>$context['page']], 'art_read', $info);
        $password = \app\common\util\ContentPassword::artState($info);
        $allowed = (int)$permission['code'] === 1 && empty($permission['trysee']) && $password['verified'];
        if (!$context['purchase_supported'] && (int)$permission['code'] === 3003) {
            $permission['points'] = 0;
            $permission['confirm'] = 0;
            $permission['msg'] = '本章暂不支持单章购买，请升级会员阅读';
        }
        if (!$password['verified']) {
            $permission['code'] = 6001;
            $permission['msg'] = '需要验证内容密码';
            $permission['trysee'] = 0;
        }
        return $permission + ['can_access'=>$allowed, 'password_required'=>!$password['verified'],
            'password_verified'=>$password['verified'], 'password_help_url'=>$password['help_url'],
            'points_hint'=>$context['points'], 'purchase_supported'=>$context['purchase_supported'],
            'purchase_page'=>$context['purchase_page'], 'trysee'=>0, 'confirm'=>0];
    }

    protected function label_manga_detail($info=[],$view=0,$fullPointsPopedom=false)
    {
        $param = mac_param_url();
        $this->assign('param',$param);

        if(empty($info)) {
            $res = mac_label_manga_detail($param);
            if ($res['code'] > 1) {
                $this->page_error($res['msg']);;
            }
            $info = $res['info'];
        }
        if(empty($info['manga_tpl'])){
            $info['manga_tpl'] = $info['type']['type_tpl_detail'];
        }

        if($view <2) {
            if ($fullPointsPopedom) {
                $popedom = $this->check_user_popedom($info['type_id'], 3, $param, 'manga_play', $info);
                $this->assign('popedom',$popedom);

                if($popedom['code']>1){
                    $this->assign('obj',$info);

                    // 不再跳转确认页，直接进入阅读页，由模板内的权限引导进行购买/充值
                }
            } else {
                $popedom = $this->check_user_popedom($info['type_id'], 2);
                if($popedom['code']>1){
                    echo $this->error($popedom['msg'], mac_url('user/index') );
                    exit;
                }
            }
        }

        $this->assign('obj',$info);
        $this->assign('comment_mid', 12);
        $this->assign('comment_rid', $info['manga_id']);
        $this->label_comment();

        return $info;
    }

    protected function label_vod_detail($info=[],$view=0)
    {
        $param = mac_param_url();

        $this->assign('param',$param);
        if(empty($info)) {
            $res = mac_label_vod_detail($param, 0);
            if ($res['code'] > 1){
                $this->page_error($res['msg']);
            }
            $info = $res['info'];
        }

        if(empty($info['vod_tpl'])){
            $info['vod_tpl'] = $info['type']['type_tpl_detail'];
        }
        if(empty($info['vod_tpl_play'])){
            $info['vod_tpl_play'] = $info['type']['type_tpl_play'];
        }
        if(empty($info['vod_tpl_down'])){
            $info['vod_tpl_down'] = $info['type']['type_tpl_down'];
        }

        if($view <2) {
            $res = $this->check_user_popedom($info['type']['type_id'], 2);
            if($res['code']>1){
                echo $this->error($res['msg'], mac_url('user/index') );
                exit;
            }
        }
        $this->assign('obj', \app\common\util\ContentResource::vodTemplate($info));
        $seo_ai = (new \app\common\model\SeoAiResult())->getByObject(1, intval($info['vod_id']));
        $this->assign('seo_ai', $seo_ai);
        $this->mergeDetailSeoIntoMaccms(1, $info, $seo_ai);
        $this->assign('comment_mid', 1);
        $this->assign('comment_rid', $info['vod_id']);
        $this->label_comment();

        return $info;
    }

    protected function label_vod_role($info=[],$view=0)
    {
        $param = mac_param_url();
        $this->assign('param', $param);

        if (empty($info)) {
            $res = mac_label_vod_detail($param, 0);
            if ($res['code'] > 1) {
                $this->page_error($res['msg']);
            }
            $info = $res['info'];
        }
        $role = mac_label_vod_role(['rid'=>intval($info['vod_id'])]);
        if ($role['code'] > 1) {
            return $this->error($role['msg']);
        }
        $info['role'] = $role['list'];

        $this->assign('obj', \app\common\util\ContentResource::vodTemplate($info));
    }

    protected array $vodPurchaseRecords = [];

    private function vodPurchaseKey(array $where): string
    {
        return implode(':', array_map(static fn($field) => (int)($where[$field] ?? 0),
            ['user_id', 'ulog_mid', 'ulog_type', 'ulog_rid', 'ulog_points']));
    }

    /** Read only known catalog coordinates; duplicate behavior logs cannot inflate the result. */
    private function prepareVodPurchases(array $info, string $flag, array $context): void
    {
        $uid = (int)($GLOBALS['user']['user_id'] ?? 0);
        if ($uid < 1 || $context['points'] === 0) {
            return;
        }
        $where = ['user_id' => $uid, 'ulog_mid' => 1, 'ulog_type' => $context['ulog_type'],
            'ulog_rid' => $context['id'], 'ulog_points' => $context['points']];
        $key = $this->vodPurchaseKey($where);
        if (array_key_exists($key, $this->vodPurchaseRecords)) {
            return;
        }
        $this->vodPurchaseRecords[$key] = [];
        $coordinates = [];
        if ($context['whole']) {
            $coordinates[0] = [0];
        } else {
            foreach ($info['vod_' . $flag . '_list'] ?? [] as $sid => $source) {
                foreach (is_array($source['urls'] ?? null) ? $source['urls'] : [] as $nid => $episode) {
                    if (is_array($episode) && is_string($episode['url'] ?? null) && $episode['url'] !== '') {
                        $coordinates[(int)$sid][] = (int)$nid;
                    }
                }
            }
        }
        if ($coordinates === []) {
            return;
        }
        $readBatch = function (array $batch) use ($where, $key): void {
            $rows = (new \app\common\model\Ulog())->field('ulog_sid,ulog_nid')->distinct(true)->where($where)
                ->where(static function ($query) use ($batch) {
                    foreach ($batch as $sid => $nids) {
                        $query->whereOr(static function ($sourceQuery) use ($sid, $nids) {
                            $sourceQuery->where('ulog_sid', $sid)->whereIn('ulog_nid', $nids);
                        });
                    }
                })->select()->toArray();
            foreach ($rows as $row) {
                $this->vodPurchaseRecords[$key][(int)$row['ulog_sid'] . ':' . (int)$row['ulog_nid']] = true;
            }
        };
        $batch = [];
        $count = 0;
        foreach ($coordinates as $sid => $nids) {
            foreach ($nids as $nid) {
                $batch[$sid][] = $nid;
                if (++$count === 500) {
                    $readBatch($batch);
                    $batch = [];
                    $count = 0;
                }
            }
        }
        if ($batch !== []) {
            $readBatch($batch);
        }
    }

    private function vodPurchaseInfo(array $where): array
    {
        if ((int)($GLOBALS['user']['user_id'] ?? 0) < 1) {
            return ['code' => 1002];
        }
        $key = $this->vodPurchaseKey($where);
        if (array_key_exists($key, $this->vodPurchaseRecords)) {
            return ['code' => isset($this->vodPurchaseRecords[$key][(int)$where['ulog_sid'] . ':' . (int)$where['ulog_nid']]) ? 1 : 1002];
        }
        return (new \app\common\model\Ulog())->infoData($where);
    }

    protected function check_vod_resource_access(array $info, string $flag, array $param): array
    {
        $context = \app\common\util\ContentResource::vodContext($info, $flag, $param);
        if ($context['code'] !== 1) {
            return $context + ['can_access' => false, 'trysee' => 0, 'confirm' => 0];
        }
        return $this->vodAccessForContext($info, $flag, $context);
    }

    private function vodAccessForContext(array $info, string $flag, array $context): array
    {
        $trysee = $flag === 'play' ? max(0, (int)($info['vod_trysee'] ?? 0) ?: (int)($GLOBALS['config']['user']['trysee'] ?? 0)) : 0;
        $permission = $this->check_user_popedom((int)$info['type_id'], $flag === 'play' ? 3 : 4,
            ['id' => $context['id'], 'sid' => $context['sid'], 'nid' => $context['nid']], $flag, $info, $trysee);
        $password = \app\common\util\ContentPassword::vodState($info, $flag);
        $allowed = (int)$permission['code'] === 1 && empty($permission['trysee']) && $password['verified'];
        if (!$password['verified']) {
            $permission['code'] = 6001;
            $permission['msg'] = '需要验证内容密码';
            $permission['trysee'] = 0;
        }
        return $permission + ['can_access' => $allowed, 'password_required' => !$password['verified'],
            'password_verified' => $password['verified'], 'password_help_url' => $password['help_url'],
            'preview_available' => false, 'points_hint' => $context['points'], 'trysee' => 0, 'confirm' => 0];
    }

    private function vodResourceTemplate(array $info, string $flag): array
    {
        $view = \app\common\util\ContentResource::vodTemplate($info);
        $view['player_info'] = $info['player_info'] ?? [];
        if ($flag === 'down') {
            $context = \app\common\util\ContentResource::vodContext($info, 'down', $info['player_info']);
            foreach ($view['vod_down_list'] as $sid => &$source) {
                foreach ($source['urls'] as $nid => &$episode) {
                    $url = $info['vod_down_list'][$sid]['urls'][$nid]['url'] ?? '';
                    $allowed = false;
                    if ($context['code'] === 1 && is_string($url) && $url !== '') {
                        // Coordinates come from the parsed catalog, never from a client. Reuse the
                        // validated row/price so a directory does not reparse all N episodes N times.
                        $item = array_replace($context, ['sid' => (int)$sid, 'nid' => (int)$nid]);
                        $allowed = $this->vodAccessForContext($info, 'down', $item)['can_access'];
                    }
                    $episode['authorized'] = $allowed;
                    $episode['url'] = $allowed ? $url : '';
                }
                unset($episode);
            }
            unset($source);
        }
        return $view;
    }

    protected function label_vod_play($flag='play',$info=[],$view=0,$pe=0)
    {
        if ($view >= 2) {
            $this->page_error('播放和下载资源需要动态授权，暂不能生成静态页面');
        }
        // The legacy URL parser casts coordinates and trims every input value. Validate before it
        // so arrays cannot become a different episode or a PHP 8 error, while keeping rewritten IDs.
        $raw = array_merge(request()->param(), $_REQUEST);
        if (!\app\common\util\ContentResource::scalarParameters($raw)) {
            $this->page_error(lang('param_err'));
        }
        $sid = array_key_exists('sid', $raw) ? \app\common\util\ContentResource::positiveInt($raw['sid']) : 1;
        $nid = array_key_exists('nid', $raw) ? \app\common\util\ContentResource::positiveInt($raw['nid']) : 1;
        if ($sid === null || $nid === null || (empty($info) &&
            (empty($GLOBALS['config']['rewrite']['vod_id'])
                ? \app\common\util\ContentResource::positiveInt($raw['id'] ?? null) === null
                : !is_string($raw['id'] ?? null) || $raw['id'] === ''))) {
            $this->page_error(lang('param_err'));
        }
        $param = mac_param_url();
        $param['sid'] = $sid;
        $param['nid'] = $nid;
        $this->assign('param',$param);

        if(empty($info)) {
            $res = mac_label_vod_detail($param, 0);
            if ($res['code'] > 1) {
                $this->page_error($res['msg']);
            }
            $info = $res['info'];
        }
        if(empty($info['vod_tpl'])){
            $info['vod_tpl'] = $info['type']['type_tpl_detail'];
        }
        if(empty($info['vod_tpl_play'])){
            $info['vod_tpl_play'] = $info['type']['type_tpl_play'];
        }
        if(empty($info['vod_tpl_down'])){
            $info['vod_tpl_down'] = $info['type']['type_tpl_down'];
        }


        $context = \app\common\util\ContentResource::vodContext($info, $flag, $param);
        if ($context['code'] !== 1) {
            $this->page_error($context['msg']);
        }
        $param['id'] = $context['id'];
        $param['sid'] = $context['sid'];
        $param['nid'] = $context['nid'];
        $this->assign('param', $param);
        if ($flag === 'down') {
            $this->prepareVodPurchases($info, $flag, $context);
        }
        $access = $this->check_vod_resource_access($info, $flag, $param);

        $urlfun='mac_url_vod_'.$flag;
        $listfun = 'vod_'.$flag.'_list';
        $popedom = $access;
        $vod_popedom_locked = !$access['can_access'];
        $this->assign('popedom',$popedom);

        if (!empty($vod_popedom_locked)) {
            $player_info = [
                'flag' => $flag,
                'encrypt' => 0,
                'trysee' => 0,
                'points' => $context['points'],
                'link' => '',
                'link_next' => '',
                'link_pre' => '',
                'url' => '',
                'url_next' => '',
                'name' => (string)($info['vod_'.$flag.'_list'][$param['sid']]['urls'][$param['nid']]['name'] ?? ''),
                'from' => '',
                'server' => '',
                'note' => '',
                'id' => $param['id'],
                'sid' => $param['sid'],
                'nid' => $param['nid'],
                'vod_data' => [
                    'vod_name'     => $info['vod_name'],
                    'vod_actor'    => $info['vod_actor'],
                    'vod_director' => $info['vod_director'],
                    'vod_class'    => $info['vod_class'],
                ],
            ];
            // 无权限时仍生成上/下集播放页链接，便于游客切换集数（各集仍受权限门控）
            if ($context['previous_nid'] !== null) {
                $player_info['link_pre'] = $urlfun($info, ['sid' => $param['sid'], 'nid' => $context['previous_nid']]);
            }
            if ($context['next_nid'] !== null) {
                $player_info['link_next'] = $urlfun($info, ['sid' => $param['sid'], 'nid' => $context['next_nid']]);
            }
            $info['player_info'] = $player_info;
            $this->assign('obj', $this->vodResourceTemplate($info, $flag));
            $favPlay = mac_user_fav_state((int)($GLOBALS['user']['user_id'] ?? 0), 1, (int)($info['vod_id'] ?? 0));
            $this->assign('vod_play_fav_ulog_id', $favPlay['fav_ulog_id']);
            $this->assign('vod_play_is_fav', $favPlay['is_fav']);
            $this->assign('player_data','');
            $this->assign('player_js','');
            $this->assign('comment_mid', 1);
            $this->assign('comment_rid', $info['vod_id']);
            $this->label_comment();
            $__vodTagwall = mac_vod_play_tagwall_payload($info);
            $this->assign('vod_play_tagwall_enabled', $__vodTagwall['enabled']);
            $this->assign('vod_play_tagwall_json', $__vodTagwall['json']);
            return $info;
        }

        $player_info=[];
        $player_info['flag'] = $flag;
        $player_info['encrypt'] = intval($GLOBALS['config']['app']['encrypt']);
        $player_info['trysee'] = 0;
        $player_info['points'] = $context['points'];
        $player_info['link'] = $urlfun($info,['sid'=>'{sid}','nid'=>'{nid}']);
        $player_info['link_next'] = '';
        $player_info['link_pre'] = '';
        $player_info['vod_data'] = [
            'vod_name'     => $info['vod_name'],
            'vod_actor'    => $info['vod_actor'],
            'vod_director' => $info['vod_director'],
            'vod_class'    => $info['vod_class'],
        ];
        if($context['previous_nid'] !== null){
            $player_info['link_pre'] = $urlfun($info,['sid'=>$param['sid'],'nid'=>$context['previous_nid']]);
        }
        $__src  = $info[$listfun][$param['sid']] ?? [];
        $__urls = is_array($__src['urls'] ?? null) ? $__src['urls'] : [];

        if($context['next_nid'] !== null){
            $player_info['link_next'] = $urlfun($info,['sid'=>$param['sid'],'nid'=>$context['next_nid']]);
        }
        $player_info['url'] = (string)($__urls[$param['nid']]['url'] ?? '');
        $player_info['url_next'] = '';
        // 当前集名。主题原本自己去 $obj.vod_down_list[sid].urls[nid].name 重算一遍,
        // 影片没有该来源时就读到未定义键(一次 /voddown/ 刷 5 条 warning,标题还是空的)。
        // 控制器这里已经把来源解析完了,直接给出来,主题引用 {$obj.player_info.name} 即可。
        $player_info['name'] = (string)($__urls[$param['nid']]['name'] ?? '');

        if(substr($player_info['url'],0,6) == 'upload'){
            $player_info['url'] = MAC_PATH . $player_info['url'];
        }
        if(substr($player_info['url_next'],0,6) == 'upload'){
            $player_info['url_next'] = MAC_PATH . $player_info['url_next'];
        }

        $player_info['from'] = (string)($__src['from'] ?? '');
        $__epFrom = (string)($__urls[$param['nid']]['from'] ?? '');
        if($__epFrom !== '' && $__epFrom != $player_info['from']){
            $player_info['from'] = $__epFrom;
        }
        $player_info['server'] = (string)($__src['server'] ?? '');
        $player_info['note'] = (string)($__src['note'] ?? '');

        if($GLOBALS['config']['app']['encrypt']=='1'){
            $player_info['url'] = mac_escape($player_info['url']);
            $player_info['url_next'] = mac_escape($player_info['url_next']);
        }
        elseif($GLOBALS['config']['app']['encrypt']=='2'){
            $player_info['url'] = base64_encode(mac_escape($player_info['url']));
            $player_info['url_next'] = base64_encode(mac_escape($player_info['url_next']));
        }
        $player_info['id'] = $param['id'];
        $player_info['sid'] = $param['sid'];
        $player_info['nid'] = $param['nid'];
        $info['player_info'] = $player_info;
        $this->assign('obj', $this->vodResourceTemplate($info, $flag));
        $seo_ai = (new \app\common\model\SeoAiResult())->getByObject(1, intval($info['vod_id']));
        $this->assign('seo_ai', $seo_ai);
        $this->mergeDetailSeoIntoMaccms(1, $info, $seo_ai);
        $favPlay = mac_user_fav_state((int)($GLOBALS['user']['user_id'] ?? 0), 1, (int)($info['vod_id'] ?? 0));
        $this->assign('vod_play_fav_ulog_id', $favPlay['fav_ulog_id']);
        $this->assign('vod_play_is_fav', $favPlay['is_fav']);

        $this->assign('player_data', '<script type="text/javascript">var player_aaaa=' . json_encode($player_info) . '</script>');
        $_pcRoot = (defined('ROOT_PATH') ? ROOT_PATH : './');
        $_pcFile = $_pcRoot . 'static/js/playerconfig.js';
        $_pjFile = $_pcRoot . 'static/js/player.js';
        $_pcVer = @is_file($_pcFile) ? @filemtime($_pcFile) : $this->_tsp;
        $_pjVer = @is_file($_pjFile) ? @filemtime($_pjFile) : $this->_tsp;
        $this->assign('player_js', '<script type="text/javascript" src="' . MAC_PATH . 'static/js/playerconfig.js?t='.$_pcVer.'"></script><script type="text/javascript" src="' . MAC_PATH . 'static/js/player.js?t=a'.$_pjVer.'"></script>');
        $this->assign('comment_mid', 1);
        $this->assign('comment_rid', $info['vod_id']);
        $this->label_comment();
        $__vodTagwall = mac_vod_play_tagwall_payload($info);
        $this->assign('vod_play_tagwall_enabled', $__vodTagwall['enabled']);
        $this->assign('vod_play_tagwall_json', $__vodTagwall['json']);
        return $info;
    }

    /**
     * 用户组/积分阅读与播放权限（前台 index 与 api 模块共用）
     */
    protected function check_user_popedom($type_id, $popedom, $param = [], $flag = '', $info = [], $trysee = 0)
    {
        $user = $GLOBALS['user'];
        $group_ids = explode(',', $user['group_id']);
        $group_list = (new \app\common\model\Group())->getCache();

        $res = false;
        $read_popedoms = [$popedom];
        foreach ($group_ids as $group_id) {
            if (!isset($group_list[$group_id])) {
                continue;
            }
            $group = $group_list[$group_id];
            if (strpos(',' . $group['group_type'], ',' . $type_id . ',') === false) {
                continue;
            }
            foreach ($read_popedoms as $p) {
                if (!empty($group['group_popedom'][$type_id][$p])) {
                    $res = true;
                    break 2;
                }
            }
        }

        $pre = $flag;
        $col = 'detail';
        if ($flag == 'play' || $flag == 'down') {
            $pre = 'vod';
            $col = $flag;
        } elseif ($flag == 'art_read') {
            $pre = 'art';
            $col = 'detail';
        } elseif ($flag == 'manga_play') {
            $pre = 'manga';
            $col = 'detail';
        }

        $points = 0;
        if (in_array($pre, ['art', 'manga'], true)) {
            $points = mac_content_read_points_amount($pre, $info);
        } elseif (in_array($pre, ['vod', 'actor', 'website'], true)) {
            $points = (int) ($info[$pre . '_points_' . $col] ?? 0);
            if (($GLOBALS['config']['user'][$pre . '_points_type'] ?? '') == '1') {
                $points = (int) ($info[$pre . '_points'] ?? 0);
            }
        }

        if ($GLOBALS['config']['user']['status'] == 0) {
        } elseif (($popedom == 2 && in_array($pre, ['art', 'actor', 'website', 'manga'])) || ($popedom == 3 && in_array($flag, ['art_read', 'manga_play']))) {
            $has_permission = false;
            $has_trysee = false;
            $check_p = in_array($flag, ['art_read', 'manga_play']) ? [3] : [2];
            foreach ($group_ids as $group_id) {
                if (!isset($group_list[$group_id])) {
                    continue;
                }
                $group = $group_list[$group_id];
                foreach ($check_p as $p) {
                    if (!empty($group['group_popedom'][$type_id][$p])) {
                        $has_permission = true;
                        break;
                    }
                }
                if ($trysee > 0) {
                    $has_trysee = true;
                }
            }

            if ($res === false) {
                if ($has_trysee) {
                    return ['code' => 1, 'msg' => lang('controller/in_try_see'), 'trysee' => $trysee];
                }
                if (in_array($flag, ['art_read', 'manga_play'], true) && $points > 0) {
                    if ($user['user_id'] > 0) {
                        $mid = mac_get_mid($pre);
                        $where = [];
                        $where['ulog_mid'] = $mid;
                        $where['ulog_type'] = 1;
                        $where['ulog_rid'] = $param['id'];
                        $where['ulog_sid'] = ($pre == 'manga') ? ($param['sid'] ?? 0) : ($param['page'] ?? 0);
                        $where['ulog_nid'] = ($pre == 'manga') ? ($param['nid'] ?? 0) : 0;
                        $where['user_id'] = $user['user_id'];
                        $where['ulog_points'] = $points;
                        if (($GLOBALS['config']['user'][$pre . '_points_type'] ?? '') == '1') {
                            $where['ulog_sid'] = 0;
                            $where['ulog_nid'] = 0;
                        }
                        $ulogRes = (new \app\common\model\Ulog())->infoData($where);
                        if ($ulogRes['code'] == 1) {
                            return ['code' => 1, 'msg' => lang('controller/popedom_ok')];
                        }
                    }
                    return ['code' => 3003, 'msg' => lang('controller/pay_play_points', [$points]), 'points' => $points, 'confirm' => 1, 'trysee' => 0];
                }
                return ['code' => 3001, 'msg' => lang('controller/no_popedom'), 'trysee' => 0];
            }

            if (max($group_ids) < 3 && $points > 0) {
                $mid = mac_get_mid($pre);
                $where = [];
                $where['ulog_mid'] = $mid;
                $where['ulog_type'] = 1;
                $where['ulog_rid'] = $param['id'];
                $where['ulog_sid'] = ($pre == 'manga') ? ($param['sid'] ?? 0) : ($param['page'] ?? 0);
                $where['ulog_nid'] = ($pre == 'manga') ? ($param['nid'] ?? 0) : 0;
                $where['user_id'] = $user['user_id'];
                $where['ulog_points'] = $points;
                if (($GLOBALS['config']['user'][$pre . '_points_type'] ?? '') == '1') {
                    $where['ulog_sid'] = 0;
                    $where['ulog_nid'] = 0;
                }
                $res = (new \app\common\model\Ulog())->infoData($where);

                if ($res['code'] > 1) {
                    return ['code' => 3003, 'msg' => lang('controller/pay_play_points', [$points]), 'points' => $points, 'confirm' => 1, 'trysee' => 0];
                }
            }
        } elseif ($popedom == 3) {
            $has_permission = false;
            foreach ($group_ids as $group_id) {
                if (!isset($group_list[$group_id])) {
                    continue;
                }
                $group = $group_list[$group_id];
                if (!empty($group['group_popedom'][$type_id][5])) {
                    $has_permission = true;
                    break;
                }
            }

            if ($res === false) {
                if ($has_permission && max($group_ids) < 3) {
                    return ['code' => 3002, 'msg' => lang('controller/in_try_see'), 'trysee' => $trysee];
                } else {
                    return ['code' => 3001, 'msg' => lang('controller/no_popedom'), 'trysee' => 0];
                }
            }
            if (max($group_ids) < 3 && $points > 0) {
                $where = [];
                $where['ulog_mid'] = 1;
                $where['ulog_type'] = $flag == 'play' ? 4 : 5;
                $where['ulog_rid'] = $param['id'];
                $where['ulog_sid'] = $param['sid'];
                $where['ulog_nid'] = $param['nid'];
                $where['user_id'] = $user['user_id'];
                $where['ulog_points'] = $points;
                if ($GLOBALS['config']['user']['vod_points_type'] == '1') {
                    $where['ulog_sid'] = 0;
                    $where['ulog_nid'] = 0;
                }
                $res_ulog = $this->vodPurchaseInfo($where);

                if ($res_ulog['code'] > 1) {
                    return ['code' => 3003, 'msg' => lang('controller/pay_play_points', [$points]), 'points' => $points, 'confirm' => 1, 'trysee' => 0];
                }
            }
        } else {
            if ($res === false) {
                return ['code' => 1001, 'msg' => lang('controller/no_popedom')];
            }
            if ($popedom == 4) {
                if (max($group_ids) == 1 && $points > 0) {
                    return ['code' => 4001, 'msg' => lang('controller/charge_data'), 'trysee' => 0];
                } elseif (max($group_ids) == 2 && $points > 0) {
                    $where = [];
                    $where['ulog_mid'] = 1;
                    $where['ulog_type'] = $flag == 'play' ? 4 : 5;
                    $where['ulog_rid'] = $param['id'];
                    $where['ulog_sid'] = $param['sid'];
                    $where['ulog_nid'] = $param['nid'];
                    $where['user_id'] = $user['user_id'];
                    $where['ulog_points'] = $points;
                    if ($GLOBALS['config']['user']['vod_points_type'] == '1') {
                        $where['ulog_sid'] = 0;
                        $where['ulog_nid'] = 0;
                    }
                    $res = $this->vodPurchaseInfo($where);

                    if ($res['code'] > 1) {
                        return ['code' => 4003, 'msg' => lang('controller/pay_down_points', [$points]), 'points' => $points, 'confirm' => 1, 'trysee' => 0];
                    }
                }
            } elseif ($popedom == 5) {
                $has_permission = false;
                $has_trysee = false;
                foreach ($group_ids as $group_id) {
                    if (!isset($group_list[$group_id])) {
                        continue;
                    }
                    $group = $group_list[$group_id];
                    if (!empty($group['group_popedom'][$type_id][3])) {
                        $has_permission = true;
                    }
                    if (!empty($group['group_popedom'][$type_id][5])) {
                        $has_trysee = true;
                    }
                }

                if (!$has_permission && $has_trysee && max($group_ids) < 3) {
                    $where = [];
                    $where['ulog_mid'] = 1;
                    $where['ulog_type'] = $flag == 'play' ? 4 : 5;
                    $where['ulog_rid'] = $param['id'];
                    $where['ulog_sid'] = $param['sid'];
                    $where['ulog_nid'] = $param['nid'];
                    $where['user_id'] = $user['user_id'];
                    $where['ulog_points'] = $points;
                    if ($GLOBALS['config']['user']['vod_points_type'] == '1') {
                        $where['ulog_sid'] = 0;
                        $where['ulog_nid'] = 0;
                    }
                    $res = $this->vodPurchaseInfo($where);

                    if ($points > 0 && $res['code'] == 1) {
                        return ['code' => 5001, 'msg' => lang('controller/popedom_ok')];
                    }

                    if ($user['user_id'] > 0) {
                        if ($points > intval($user['user_points'])) {
                            return ['code' => 5002, 'msg' => lang('controller/not_enough_points', [$points, $user['user_points']]), 'trysee' => $trysee];
                        } else {
                            return ['code' => 5001, 'msg' => lang('controller/try_see_end', [$points, $user['user_points']]), 'trysee' => $trysee];
                        }
                    } else {
                        if ($points > 0) {
                            return ['code' => 5002, 'msg' => lang('controller/not_enough_points', [$points, $user['user_points']]), 'trysee' => $trysee];
                        } else {
                            return ['code' => 5001, 'msg' => lang('controller/try_see_end', [$points, $user['user_points']]), 'trysee' => $trysee];
                        }
                    }
                }
            }
        }

        return ['code' => 1, 'msg' => lang('controller/popedom_ok')];
    }

    /**
     * 最近一次 success()/error() 的结果码(1=成功 0=失败)。
     *
     * 这两个方法都是【抛 HttpResponseException 来返回响应】——那是 ThinkPHP 的正常
     * 控制流,不是崩溃。调用方(如 api/Timming 的定时任务分发)只拿到一个异常,无法
     * 区分"任务成功收尾"还是"任务报错收尾",于是只能一律当失败处理。留下这个标记
     * 让调用方能判,不改变任何既有响应行为。
     */
    public static int $lastJumpCode = 1;

    protected function success($msg = '', $url = null, $data = '', $wait = 3)
    {
        self::$lastJumpCode = 1;
        if (\think\facade\Request::isAjax()) {
            return json(['code' => 1, 'msg' => $msg, 'data' => $data]);
        }
        $this->assign(['code' => 1, 'msg' => $msg, 'url' => $url ?? 'javascript:history.back();', 'wait' => $wait, 'type' => 'success']);
        throw new \think\exception\HttpResponseException(\think\Response::create(\think\facade\View::fetch('public/jump')));
    }

    protected function error($msg = '', $url = null, $data = '', $wait = 3)
    {
        self::$lastJumpCode = 0;
        if (\think\facade\Request::isAjax()) {
            return json(['code' => 0, 'msg' => $msg, 'data' => $data]);
        }
        $this->assign(['code' => 0, 'msg' => $msg, 'url' => $url ?? 'javascript:history.back();', 'wait' => $wait, 'type' => 'error']);
        throw new \think\exception\HttpResponseException(\think\Response::create(\think\facade\View::fetch('public/jump')));
    }

    protected function assign($name, $value = ''): void
    {
        \think\facade\View::assign(is_array($name) ? $name : [$name => $value]);
    }

    protected function fetch(string $template = '', array $vars = []): string
    {
        if ($vars) {
            \think\facade\View::assign($vars);
        }
        return \think\facade\View::fetch($template);
    }
}
