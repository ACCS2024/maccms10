<?php
/*
'软件名称：苹果CMS  源码库：https://github.com/magicblack
'--------------------------------------------------------
'Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
'遵循Apache2开源协议发布，并提供免费使用。
'--------------------------------------------------------
*/

use think\View;

error_reporting(E_ERROR | E_PARSE );

/**
 * TP5 时代由入口/框架提供的运行环境常量,TP8 全仓零定义。
 *
 * 定义点放在 common.php 而不是各入口文件,原因有二:
 *   1. common.php 由 think\App::load() 从 appPath 统一加载,五个入口 + CLI 全覆盖;
 *   2. 生产站的后台入口是随机文件名(防扫描)且被部署脚本排除,改入口文件到不了它。
 *
 * PHP 8 下未定义常量是致命 Error(不是 PHP 7 的 notice + 字符串回退),
 * 不走 set_error_handler,MacApp 的诊断降级救不了 —— 参见
 * application/api/controller/Timming.php:index() 的 IS_CLI 消费点。
 */
if (!defined('IS_CLI')) {
    define('IS_CLI', PHP_SAPI === 'cli');
}



function get_array_unique_id_list($list, $need_sort = false) {
    $list = array_unique($list);
    $list = array_map('intval', $list);
    $list = array_filter($list);
    $list = array_values($list);
    $need_sort && sort($list);
    return $list;
}

if (!function_exists('str_starts_with')) {
    function str_starts_with($haystack, $needle) {
        return (string)$needle !== '' && strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}
if (!function_exists('str_ends_with')) {
    function str_ends_with($haystack, $needle) {
        return $needle !== '' && substr($haystack, -strlen($needle)) === (string)$needle;
    }
}
if (!function_exists('str_contains')) {
    function str_contains($haystack, $needle) {
        return $needle !== '' && mb_strpos($haystack, $needle) !== false;
    }
}

/**
 * 视频分类封面方向：使用后台「页面配置」theme[list_cover][vod]；子分类沿父链查找。
 *
 * @param int $typeId 当前分类 ID
 * @return string h|v
 */
function mac_tpl_vod_type_cover($typeId)
{
    $typeId = (int) $typeId;
    $tplconfig = $GLOBALS['mctheme'];
    $theme = isset($tplconfig['theme']) && is_array($tplconfig['theme']) ? $tplconfig['theme'] : [];

    $pageRows = $theme['list_cover']['vod'] ?? [];
    if (!is_array($pageRows)) {
        $pageRows = [];
    }
    $pageMap = [];
    foreach ($pageRows as $row) {
        if (!is_array($row) || empty($row['id'])) {
            continue;
        }
        $id = (string) $row['id'];
        $c = isset($row['cover']) ? (string) $row['cover'] : 'v';
        $pageMap[$id] = ($c === 'h') ? 'h' : 'v';
    }

    $typeList = (new \app\common\model\Type())->getCache('type_list');
    if (!is_array($typeList)) {
        $typeList = [];
    }

    $resolve = function ($startId, array $map) use ($typeList) {
        $tid = (int) $startId;
        while ($tid > 0) {
            if (isset($map[(string) $tid])) {
                return $map[(string) $tid];
            }
            if (!isset($typeList[$tid])) {
                break;
            }
            $tid = (int) ($typeList[$tid]['type_pid'] ?? 0);
        }

        return null;
    };

    $hit = $resolve($typeId, $pageMap);
    if ($hit !== null) {
        return $hit;
    }

    return 'v';
}

/**
 * 漫画列表封面方向：theme[list_cover][manga]。
 *
 * @return string h|v
 */
function mac_tpl_manga_cover()
{
    $tplconfig = $GLOBALS['mctheme'];
    $theme = isset($tplconfig['theme']) && is_array($tplconfig['theme']) ? $tplconfig['theme'] : [];
    $raw = isset($theme['list_cover']['manga']) ? (string) $theme['list_cover']['manga'] : 'v';

    return ($raw === 'h') ? 'h' : 'v';
}

/**
 * 小说/资讯列表封面方向：theme[list_cover][art]。
 *
 * @return string h|v
 */
function mac_tpl_art_cover()
{
    $tplconfig = $GLOBALS['mctheme'];
    $theme = isset($tplconfig['theme']) && is_array($tplconfig['theme']) ? $tplconfig['theme'] : [];
    $raw = isset($theme['list_cover']['art']) ? (string) $theme['list_cover']['art'] : 'v';

    return ($raw === 'h') ? 'h' : 'v';
}

/**
 * 主题「视频卡片/列表点击进播放页」是否开启（theme.playlink.btn）。
 * 与 $GLOBALS['mctheme'] / assign('tplconfig') 同源，避免模板里多层数组判断不一致。
 */
function mac_tpl_vod_playlink_on()
{
    $mc = isset($GLOBALS['mctheme']) && is_array($GLOBALS['mctheme']) ? $GLOBALS['mctheme'] : (config('mctheme') ?: []);
    $theme = isset($mc['theme']) && is_array($mc['theme']) ? $mc['theme'] : [];
    if (empty($theme['playlink']) || !is_array($theme['playlink'])) {
        return false;
    }
    $btn = $theme['playlink']['btn'] ?? null;
    if ($btn === null || $btn === '') {
        return false;
    }
    return $btn === '1' || $btn === 1 || $btn === true;
}

/**
 * 播放页「热门标签墙」数据：全站 maccms.app.search_hot + 本片 vod_tag / vod_class / 分类名。
 * 须在 $GLOBALS['config'] 已由 Init 行为赋值后调用（与模板 {php} 不同，避免匿名函数内 `}` 与 Think 标签 `}` 冲突导致整块 PHP 编译失败）。
 *
 * @param array $info mac_label_vod_detail 的 info
 * @return array{enabled:bool,json:string}
 */
function mac_vod_play_tagwall_payload($info)
{
    $info = is_array($info) ? $info : [];
    $split = function ($raw, $pattern) {
        $raw = trim((string) $raw);
        if ($raw === '') {
            return [];
        }
        $parts = preg_split($pattern, $raw, -1, PREG_SPLIT_NO_EMPTY);
        if (!is_array($parts)) {
            return [];
        }

        return array_values(array_filter(array_map('trim', $parts)));
    };
    $hotRaw = '';
    if (!empty($GLOBALS['config']['app']['search_hot'])) {
        $hotRaw = (string) $GLOBALS['config']['app']['search_hot'];
    }
    $hot = array_slice($split($hotRaw, '/[,，\s]+/u'), 0, 48);
    $local = [];
    if (!empty($info['vod_tag'])) {
        $local = array_merge($local, $split($info['vod_tag'], '/[,，\/|、\s]+/u'));
    }
    if (!empty($info['vod_class'])) {
        $local = array_merge($local, $split($info['vod_class'], '/[,，\/|、\s]+/u'));
    }
    if (count($local) === 0 && !empty($info['type']['type_name'])) {
        $local[] = trim((string) $info['type']['type_name']);
    }
    $local = array_slice(array_values(array_unique(array_filter($local))), 0, 40);
    $enabled = (count($hot) + count($local)) > 0;
    $json = json_encode(['hot' => $hot, 'local' => $local], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS);

    return ['enabled' => $enabled, 'json' => $json];
}

/**
 * 首页热门推荐 Tab（latest2–latest5）：读取 theme.hotvod.tabs。
 * 无配置时返回空数组，不做默认兜底。
 *
 * @param array $theme mctheme.theme
 * @return array<int, array{id:string,name:string,icon_l:string,icon_b:string}>
 */
function mac_theme_index_hotvod_tabs(array $theme)
{
    $tabsCfg = isset($theme['hotvod']['tabs']) && is_array($theme['hotvod']['tabs']) ? $theme['hotvod']['tabs'] : [];
    if (count($tabsCfg) === 0) {
        return [];
    }

    $typeModel = (new \app\common\model\Type());
    $out = [];

    for ($i = 0; $i < 4; $i++) {
        if (!isset($tabsCfg[$i]) || !is_array($tabsCfg[$i])) {
            continue;
        }
        $row = $tabsCfg[$i];
        $id = isset($row['id']) ? trim((string) $row['id']) : '';
        if ($id === '') {
            continue;
        }

        $name = isset($row['name']) ? trim((string) $row['name']) : '';
        if ($name === '') {
            $vo2 = $typeModel->getCacheInfo((int) $id);
            $name = !empty($vo2['type_name']) ? (string) $vo2['type_name'] : '';
        }

        $out[] = [
            'id' => $id,
            'name' => $name,
            'icon_l' => isset($row['icon_l']) ? trim((string) $row['icon_l']) : '',
            'icon_b' => isset($row['icon_b']) ? trim((string) $row['icon_b']) : '',
        ];
    }

    return $out;
}

//访问日志记录，根目录创建log目录
function slog($logs)
{
    $ymd = date('Y-m-d-H');
    $now = date('Y-m-d H:i:s');
    $toppath = "./log/$ymd.txt";
    $ts = @fopen($toppath,"a+");
    @fputs($ts, $now .' '. $logs ."\r\n");
    @fclose($ts);
}
//foreach($_GET as $k=>$v){ $getData .= $k.'='.$v.'&'; }
//foreach($_POST as $k=>$v){ $postData .= $k.'='.$v.'&'; }
//foreach($_COOKIE as $k=>$v){ $cookieData .= $k.'='.$v.'&'; }
//$log = $_SERVER['PHP_SELF'] . '---get:' .$getData .'---post:' . $postData .'---'. json_encode($_POST).'---cookie:' . $cookieData ;
//slog($log);

// 是否IP
function mac_string_is_ip($string) {
    return preg_match('/^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$/', $string) === 1;
}

// 应用公共文件
function mac_return($msg,$code=1,$data=''){
    if(is_array($msg)){
        return json_encode($msg);
    }
    else {
        $rs = ['code' => $code, 'msg' => $msg, 'data'=>'' ];
        if(is_array($data)) $rs['data'] = $data;
        return json_encode($rs);
    }
}

function mac_run_statistics()
{
    $t2 = microtime(true) - MAC_START_TIME;
    $size = memory_get_usage();
    $memory = mac_format_size($size);
    unset($unit);
    return 'Processed in: '.round($t2,4).' second(s),&nbsp;' . $memory . ' Mem On.';
}

function mac_format_size($s=0)
{
    if($s==0){ return '0 kb'; }
    $unit=array('b','kb','mb','gb','tb','pb');
    return round($s/pow(1024,($i=floor(log($s,1024)))),2).' '.$unit[$i];
}

function mac_read_file($f)
{
    return @file_get_contents($f);
}

function mac_write_file($f,$c='')
{
    $dir = dirname($f);
    if(!is_dir($dir)){
        mac_mkdirss($dir);
    }
    return @file_put_contents($f, $c);
}

function mac_mkdirss($path,$mode=0777)
{
    if (!is_dir(dirname($path))){
        mac_mkdirss(dirname($path));
    }
    if(!file_exists($path)){
        return mkdir($path,$mode);
    }
    return true;
}

function mac_rmdirs($dirname, $withself = true)
{
    if (!is_dir($dirname))
        return false;
    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dirname, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($files as $fileinfo)
    {
        $todo = ($fileinfo->isDir() ? 'rmdir' : 'unlink');
        $todo($fileinfo->getRealPath());
    }
    if ($withself)
    {
        @rmdir($dirname);
    }
    return true;
}

function mac_arr2file($f,$arr='')
{
    if(is_array($arr)){
        $con = var_export($arr,true);
    } else{
        $con = $arr;
    }
    $con = "<?php\nreturn $con;";
    mac_write_file($f, $con);
    // opcache清理以实时生效配置
    if (function_exists('opcache_invalidate')) {
        opcache_invalidate($f, true);
    }
}

/**
 * 保存配置到 extra 文件（用于主题配置等）
 * @param string $f 文件路径
 * @param array $arr 配置数组
 * @return bool
 */
function mac_save_config_data($f, $arr = '')
{
    if (!is_array($arr)) {
        return false;
    }
    mac_arr2file($f, $arr);
    return true;
}

function mac_replace_text($txt,$type=1)
{
    if($type==1){
        return str_replace('#',Chr(13),$txt);
    }
    return str_replace(chr(13),'#',str_replace(chr(10),'',$txt));
}

function mac_compress_html($s){
    $s = str_replace(array("\r\n","\n","\t"), array('','','') , $s);
    $pattern = array (
        "/> *([^ ]*) *</",
        "/[\s]+/",
        "/<!--[\\w\\W\r\\n]*?-->/",
        // "/\" /",
        "/ \"/",
        "'/\*[^*]*\*/'"
    );
    $replace = array (
        ">\\1<",
        " ",
        "",
        //"\"",
        "\"",
        ""
    );
    return preg_replace($pattern, $replace, $s);
}

function mac_build_regx($regstr,$regopt)
{
    return '/'.str_replace([
        '/',
        '$',
        '+',
        '-',
        '{',
    ],[
        '\/',
        '\$',
        '\+',
        '\-',
        '\{',
    ],$regstr).'/'.$regopt;
}

function mac_reg_replace($str,$rule,$value)
{
    $res='';
    $rule = mac_build_regx($rule,"is");
    if (!empty($str)){
        $res = preg_replace($rule,$value,$str);
    }
    return $res;
}

function mac_reg_match($str,$rule)
{
    $res='';
    $rule = mac_build_regx($rule,"is");
    preg_match_all($rule,$str,$mc);
    $mfv=$mc[1];
    foreach($mfv as $f=>$v){
        $res = trim(preg_replace("/[ \r\n\t\f]{1,}/"," ",$v));
        break;
    }
    unset($mc);
    return $res;
}

function mac_redirect($url,$obj='')
{
    echo '<script>'.$obj.'location.href="' .$url .'";</script>';
    exit;
}

function mac_alert($str)
{
    echo '<script>alert("' .$str. '\t\t");history.go(-1);</script>';
}

function mac_alert_url($str,$url)
{
    echo '<script>alert("' .$str. '\t\t");location.href="' .$url .'";</script>';
}

function mac_jump($url,$sec=0)
{
    echo '<script>setTimeout(function (){location.href="'.$url.'";},'.($sec*1000).');</script><span>'.lang('pause').''.$sec.''.lang('continue_in_second').'  >>>  </span><a href="'.$url.'" >'.lang('browser_jump').'</a><br>';
}

/**
 * jumpurl 安全净化(安全加固,不兼容旧脏数据):
 * 仅放行干净的 http/https 绝对地址(长度<=150,不含引号/尖括号/空白/反斜杠/反引号/控制字符),
 * 其余(javascript:/data: 伪协议、XSS 引号闭合、注入脚本)一律返回空串。
 * cs_jump 跳转木马正是滥用此字段——入库(各模型 saveData)与模板输出两端都必须经过它。
 */
function mac_safe_jumpurl($url)
{
    $url = trim((string)$url);
    if ($url === '' || strlen($url) > 150) {
        return '';
    }
    if (preg_match('/[\x00-\x20\x22\x27\x3c\x3e\x5c\x60\x7f]/', $url)) {
        return '';
    }
    if (!preg_match('#^https?://[A-Za-z0-9\-._~%:/?\#\[\]@!$&()*+,;=]+$#', $url)) {
        return '';
    }
    return $url;
}

/**
 * 批量净化一行数据里的所有 *_jumpurl 字段——用于采集/接收等绕过 saveData 的直接入库路径。
 */
function mac_clean_jumpurl_fields($row)
{
    if (!is_array($row)) {
        return $row;
    }
    foreach (['vod_jumpurl','art_jumpurl','actor_jumpurl','type_jumpurl','website_jumpurl','manga_jumpurl'] as $k) {
        if (isset($row[$k])) {
            $row[$k] = mac_safe_jumpurl($row[$k]);
        }
    }
    return $row;
}

if (!function_exists('mac_playurl_has_injection')) {
    /**
     * 检测 播放/下载地址 里是否夹带 HTML 属性截断注入。
     *
     * 背景（cs_jump 的进化版）：老攻击链往 vod_jumpurl 塞跳转，已被 mac_safe_jumpurl 挡住；
     * 攻击者改往 vod_play_url 塞：
     *   正片$https://xiazai.it.com/" onload="top.location.replace('https://xiazai.it.com/')" x="
     * 播放页把 play_url 直接拼进 iframe 的 src="..."，那个 " 提前闭合 src，再挂一个
     * onload 事件把整页 top.location 跳到挂马站。本站实测已有 709 条被这样劫持。
     *
     * 合法的 play_url 形如  第1集$https://x/a/index.m3u8#第2集$...  （$/$$$/# 分隔），
     * 实测 18 万条干净数据【零例外】不含：双/单引号、尖括号、反引号、反斜杠、空白字符、
     * on..= 事件处理器、js/vbs/data 伪协议。命中任一即判为注入。
     *
     * 返回 true = 有注入特征，调用方应拒绝写入 / 跳过该条。
     */
    function mac_playurl_has_injection($url): bool {
        $cur = (string)$url;
        if ($cur === '') { return false; }
        // 逐层 rawurldecode 后每层都查 —— 防 %22(")/%20(空格)/%3d(=)/%3c(<) 这类
        // URL 编码绕过。攻击者在我上一版(只查字面字符)部署后，立刻改用编码变体：
        //   正片$https://xiazai.it.com/%22%20onload%3d%22top.location.replace(%27...%27)...
        // 实测 18.3 万条合法 play_url【零例外】不含 % 编码，故解码后再查不会误伤。
        // 最多解 4 层，覆盖多重编码。
        for ($i = 0; $i < 4; $i++) {
            if (preg_match('/["\'<>`\\\\]|\s/', $cur)) { return true; }
            if (preg_match('/\bon\w+\s*=|javascript:|vbscript:|data:\s*text\/html/i', $cur)) { return true; }
            $dec = rawurldecode($cur);
            if ($dec === $cur) { break; }
            $cur = $dec;
        }
        return false;
    }
}

if (!function_exists('mac_vod_has_injection')) {
    /**
     * 入库前对一条 vod 数据的多个高危字段一次性做注入检测。命中返回触发的字段名，否则 ''。
     *
     * 覆盖两类向量（都是 mac_filter_xss 挡不住的）：
     *  1) URL 字段（play/down 地址、各种封面图）—— 属性截断。
     *     mac_filter_xss 对 URL 只 strip_tags、不转义引号，所以 1.jpg" onload=" 这种
     *     能突破 <img src="..."> / iframe src="..."。用 mac_playurl_has_injection
     *     （逐层 urldecode 后查引号/尖括号/空白/on事件/伪协议）单独把关。
     *     实测 18 万条合法 pic/play 零误伤。
     *  2) HTML 字段（vod_content / vod_blurb）—— 存储型 XSS。这两个字段【保留 HTML】
     *     不做实体转义（否则正文格式全毁），所以要专门查 <script>/<iframe>/<embed>/
     *     <object>/on事件/js|vbs 伪协议。实测 5000 条合法正文对这些模式零命中。
     *
     * 注：vod_jumpurl 不在此列 —— 它由 mac_clean_jumpurl_fields()/mac_safe_jumpurl()
     * 走「清洗」而非「整条拒绝」，两者分工不同。
     */
    function mac_vod_has_injection($v): string {
        if (!is_array($v)) { return ''; }
        foreach (['vod_play_url','vod_down_url','vod_pic','vod_pic_thumb','vod_pic_slide','vod_pic_original'] as $f) {
            if (isset($v[$f]) && $v[$f] !== '' && mac_playurl_has_injection($v[$f])) { return $f; }
        }
        foreach (['vod_content','vod_blurb'] as $f) {
            if (isset($v[$f]) && preg_match('/<script\b|<iframe\b|<embed\b|<object\b|javascript:|vbscript:|\bon\w+\s*=/i', (string)$v[$f])) {
                return $f;
            }
        }
        return '';
    }
}

function mac_echo($str)
{
    echo $str.'<br>';
    ob_flush();flush();
}

function mac_day($t,$f='',$c='#FF0000')
{
    if(empty($t)) { return ''; }
    if(is_numeric($t)){
        $t = date('Y-m-d H:i:s',$t);
    }
    $now = date('Y-m-d',time());
    if($f=='color' && strpos(','.$t,$now)>0){
        return '<font color="' .$c. '">' .$t. '</font>';
    }
    return  $t;
}

function mac_friend_date($time)
{
    if (!$time)
        return false;
    $fdate = '';
    $d = time() - intval($time);
    $ld = $time - mktime(0, 0, 0, 0, 0, date('Y')); //得出年
    $md = $time - mktime(0, 0, 0, date('m'), 0, date('Y')); //得出月
    $byd = $time - mktime(0, 0, 0, date('m'), date('d') - 2, date('Y')); //前天
    $yd = $time - mktime(0, 0, 0, date('m'), date('d') - 1, date('Y')); //昨天
    $dd = $time - mktime(0, 0, 0, date('m'), date('d'), date('Y')); //今天
    $td = $time - mktime(0, 0, 0, date('m'), date('d') + 1, date('Y')); //明天
    $atd = $time - mktime(0, 0, 0, date('m'), date('d') + 2, date('Y')); //后天
    if ($d == 0) {
        $fdate = lang('just');
    } else {
        switch ($d) {
            case $d < $atd:
                $fdate = date('Y'.lang('year').'m'.lang('month').'d'.lang('day'), $time);
                break;
            case $d < $td:
                $fdate = lang('day_after_tomorrow') . date('H:i', $time);
                break;
            case $d < 0:
                $fdate = lang('tomorrow') . date('H:i', $time);
                break;
            case $d < 60:
                $fdate = $d . lang('seconds_ago');
                break;
            case $d < 3600:
                $fdate = floor($d / 60) . lang('minutes_ago');
                break;
            case $d < $dd:
                $fdate = floor($d / 3600) . lang('hours_ago');
                break;
            case $d < $yd:
                $fdate = lang('yesterday') . date('H:i', $time);
                break;
            case $d < $byd:
                $fdate = lang('day_before_yesterday') . date('H:i', $time);
                break;
            case $d < $md:
                $fdate = date('m'.lang('month').'d'.lang('day').' H:i', $time);
                break;
            case $d < $ld:
                $fdate = date('m'.lang('month').'d'.lang('day'), $time);
                break;
            default:
                $fdate = date('Y'.lang('year').'m'.lang('month').'d'.lang('day'), $time);
                break;
        }
    }
    return $fdate;
}

function mac_get_time_span($sn)
{
    $lastTime = session($sn);

    if(empty($lastTime)){
        $lastTime= "1228348800";
    }
    $res = time() - intval($lastTime);
    session($sn,time());
    return $res;
}

function mac_get_rndstr($length=32,$f='')
{
    $pattern = "234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if($f=='num'){
        $pattern = '1234567890';
    }
    elseif($f=='letter'){
        $pattern = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    }
    $len = strlen($pattern) -1;
    $res='';
    for($i=0; $i<$length; $i++){
        $res .= $pattern[mt_rand(0,$len)];
    }
    // 开头为0的随机替换为1~9，优化导出格式问题
    if (str_starts_with($res, '0')) {
        $res = mt_rand(1, 9) . substr($res, 1);
    }
    return $res;
}

function mac_convert_encoding($str,$nfate,$ofate){
    if ($ofate=="UTF-8"){ return $str; }
    if ($ofate=="GB2312"){ $ofate="GBK"; }

    if(function_exists("mb_convert_encoding")){
        $str=mb_convert_encoding($str,$nfate,$ofate);
    }
    else{
        $ofate.="//IGNORE";
        $str=iconv($nfate ,$ofate ,$str);
    }
    return $str;
}

function mac_get_refer()
{
    return trim(urldecode($_SERVER["HTTP_REFERER"] ?? ''));
}

function mac_extends_list($flag)
{
    $path = './application/common/extend/'.$flag;
    $file_list = glob($path . '/*.php',GLOB_NOSORT );
    $res=[];
    $res['ext_list'] = [];
    $res['ext_html'] = '';
    foreach($file_list as $k=>$v) {
        $cl = str_replace([$path . '/', '.php'], '', $v);
        $cp = 'app\\common\\extend\\'.$flag.'\\' . $cl;
        if (class_exists($cp)) {
            $c = new $cp;
            $res['ext_list'][$cl] = $c->name;
            if(file_exists( './application/admin/view/extend/'.$flag.'/'.strtolower($cl) .'.html')) {
                $res['ext_html'] .= \think\facade\View::fetch('admin@extend/'.$flag.'/' . strtolower($cl), ['editor' => strtolower($cl), 'cl' => $cl, 'config' => new \app\common\util\SafeConfig($GLOBALS['config'] ?? [])]);
            }
        }
    }
    return $res;
}

function mac_send_sms($to,$code,$type_flag,$type_des,$msg)
{
    if(empty($GLOBALS['config']['sms']['type'])){
        return ['code'=>9005,'msg'=> lang('sms_not_config')];
    }
    $pattern = "/^1[345789][0-9]{9}$/";
    if(!preg_match($pattern,$to)){
        return ['code'=>999,'msg'=>lang('phone_format_err')];
    }
    if(empty($code)){
        return ['code'=>998,'msg'=>lang('title_not_empty')];
    }
    if(empty($type_flag)){
        return ['code'=>997,'msg'=>lang('tpl_not')];
    }


    $cp = 'app\\common\\extend\\sms\\' . ucfirst($GLOBALS['config']['sms']['type']);
    if (class_exists($cp)) {
        $c = new $cp;
        return $c->submit($to,$code,$type_flag,$type_des,$msg);
    }
    else{
        return ['code'=>991,'msg'=>lang('sms_not')];
    }
}

function mac_send_mail($to,$title,$body,$conf=[])
{
    if(empty($GLOBALS['config']['email']['type'])){
        return ['code'=>9005,'msg'=>lang('email_not_config')];
    }
    $pattern = '/\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*/';
    if(!preg_match( $pattern, $to)){
        return ['code'=>999,'msg'=>lang('email_format_err')];
    }
    if(empty($title)){
        return ['code'=>998,'msg'=>lang('title_not_empty')];
    }
    if(empty($body)){
        return ['code'=>997,'msg'=>lang('body_not_empty')];
    }

    $cp = 'app\\common\\extend\\email\\' . ucfirst($GLOBALS['config']['email']['type']);
    if (class_exists($cp)) {
        $c = new $cp;
        return $c->submit($to,$title,$body,$conf);
    }
    else{
        return ['code'=>991,'msg'=>lang('email_not')];
    }
}

/**
 * 安全加固(V3/CSRF):返回稳定的 per-session CSRF 令牌(生成一次、整会话复用,
 * 不一次性销毁),供后台 head meta 输出、全局 ajax 头 X-CSRF-Token 使用。
 * 与控制器内 mac_validate('Token') 用的一次性 __token__ 分开存放,互不干扰。
 */
function mac_csrf_token()
{
    $t = session('__csrf_token__');
    if (empty($t) || !is_string($t)) {
        if (function_exists('random_bytes')) {
            $t = bin2hex(random_bytes(16));
        } else {
            $t = md5(uniqid('', true) . mt_rand());
        }
        session('__csrf_token__', $t);
    }
    return $t;
}

/**
 * 安全加固:本地自动迁移(无需手动执行 SQL)。
 * 幂等检测并应用必要的库结构变更,用标记文件记录已应用版本;版本不变则跳过。
 * 完全本地、不联网。新增迁移时把 $version 递增并在下方追加幂等检测块即可自动生效。
 */
function mac_security_auto_migrate()
{
    $version = 'v2';
    $marker  = APP_PATH . 'data' . DIRECTORY_SEPARATOR . 'update' . DIRECTORY_SEPARATOR . 'sec_schema.lock';
    if (is_file($marker) && trim((string)@file_get_contents($marker)) === $version) {
        return;
    }
    try {
        $prefix = config('database.connections.mysql.prefix');
        // 迁移 v1:扩宽口令列以容纳 bcrypt(60+字符),旧 char(32)/varchar(32) 存不下
        $cols = ['admin' => 'admin_pwd', 'user' => 'user_pwd'];
        foreach ($cols as $t => $c) {
            $table = $prefix . $t;
            $info = \think\facade\Db::query(
                "SELECT CHARACTER_MAXIMUM_LENGTH AS len FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?",
                [$table, $c]
            );
            if (!empty($info) && isset($info[0]['len']) && (int)$info[0]['len'] < 255) {
                \think\facade\Db::execute("ALTER TABLE `" . str_replace('`', '', $table) . "` MODIFY `" . $c . "` VARCHAR(255) NOT NULL DEFAULT ''");
            }
        }

        // 迁移 v2:前台热查询复合索引(类目+状态+排序),解决单列索引无法"过滤+排序"导致的 filesort/全扫。
        // 幂等:列与索引名存在性检查;缺列自动跳过(兼容不同版本库)。
        // 注:大表(数十万行+)首次 ADD INDEX 在 MyISAM 下会锁表数秒~分钟;海量库建议先用后台「数据库优化」按钮低峰执行。
        $idxPlan = [
            // 注:类目类复合索引以高选择性的 type_id/type_id_1 打头(vod_status 几乎恒为1、选择性低,
            // 放首列会被优化器弃用),实现"等值type + 等值status + 排序列"单索引消除 filesort;
            // 全站榜单/最新无类目过滤,用 (status, 排序列)。
            'vod' => [
                'idx_type_st_time'  => ['type_id', 'vod_status', 'vod_time'],
                'idx_type1_st_time' => ['type_id_1', 'vod_status', 'vod_time'],
                'idx_type_st_hits'  => ['type_id', 'vod_status', 'vod_hits'],
                'idx_st_level_time' => ['vod_status', 'vod_level', 'vod_time'],
                'idx_st_time'       => ['vod_status', 'vod_time'],
                'idx_st_hits_day'   => ['vod_status', 'vod_hits_day'],
                'idx_st_hits_week'  => ['vod_status', 'vod_hits_week'],
                'idx_st_hits_month' => ['vod_status', 'vod_hits_month'],
            ],
            'art' => [
                'idx_type_st_time'  => ['type_id', 'art_status', 'art_time'],
                'idx_type1_st_time' => ['type_id_1', 'art_status', 'art_time'],
                'idx_type_st_hits'  => ['type_id', 'art_status', 'art_hits'],
                'idx_st_level_time' => ['art_status', 'art_level', 'art_time'],
                'idx_st_hits_month' => ['art_status', 'art_hits_month'],
            ],
            'manga' => [
                'idx_type_st_time'  => ['type_id', 'manga_status', 'manga_time'],
                'idx_type1_st_time' => ['type_id_1', 'manga_status', 'manga_time'],
                'idx_type_st_hits'  => ['type_id', 'manga_status', 'manga_hits'],
                'idx_st_level_time' => ['manga_status', 'manga_level', 'manga_time'],
                'idx_st_hits_month' => ['manga_status', 'manga_hits_month'],
            ],
            'comment' => [
                'idx_rid_status_id'  => ['comment_rid', 'comment_status', 'comment_id'],
                'idx_mid_rid_status' => ['comment_mid', 'comment_rid', 'comment_status'],
            ],
            'gbook' => [
                'idx_rid_status_id' => ['gbook_rid', 'gbook_status', 'gbook_id'],
            ],
        ];
        foreach ($idxPlan as $t => $idxs) {
            foreach ($idxs as $name => $icols) {
                mac_db_add_index_if_absent($prefix . $t, $name, $icols);
            }
        }

        @file_put_contents($marker, $version);
    } catch (\Exception $e) {
        // 迁移失败不阻断后台访问,标记不写入 → 下次请求自动重试
    }
}

/**
 * Meilisearch 索引设置自动同步(无需手动在后台点"初始化")。
 * 仅当 Meili 已启用时执行:把 indexSettingsPayload(filterable/sortable/ranking 等)
 * 自动 PATCH 到索引。版本号取 payload 内容哈希——今后任意修改设置即自动触发一次重应用。
 * 仅改设置、不重推文档(filterable 新增字段由 Meili 异步对既有文档重建过滤结构)。
 * Meili 不可达时不写标记 → 下次后台请求自动重试,完全本地不阻断、不联官方。
 */
function mac_meili_settings_auto_sync()
{
    if (!class_exists('\\app\\common\\util\\MeilisearchService')) {
        return;
    }
    $svc = '\\app\\common\\util\\MeilisearchService';
    try {
        if (!$svc::enabled()) {
            return; // Meili 关闭:无需同步,零开销
        }
        $payload = $svc::indexSettingsPayload();
        $ver = 'ms_' . substr(md5(json_encode($payload)), 0, 12);
        $marker = APP_PATH . 'data' . DIRECTORY_SEPARATOR . 'update' . DIRECTORY_SEPARATOR . 'meili_settings.lock';
        if (is_file($marker) && trim((string)@file_get_contents($marker)) === $ver) {
            return; // 当前设置版本已应用
        }
        $svc::ensureIndex();          // 索引不存在则建(建时已应用一次设置)
        $r = $svc::updateSettings();  // 既有索引:PATCH 最新 filterable/sortable
        if (!empty($r['ok'])) {
            @file_put_contents($marker, $ver);
        }
    } catch (\Throwable $e) {
        // 静默:不阻断后台访问
    }
}

/**
 * 性能/环境体检(只读检测 + 引导)。
 * 用于后台首页:检测服务器侧需用户自行开启的项(OPcache/Redis/引擎/PHP 版本/Meili),
 * 给出"状态 + 怎么开"的引导;本函数只读、绝不修改环境,且每项都吞异常,绝不让首页报错。
 *
 * @return array<int, array{label:string, ok:bool, optional:bool, detail:string, guide:string}>
 */
function mac_perf_env_checks()
{
    // HTTP requests populate $GLOBALS['config'] in AppInit. Console commands do not
    // run middleware, so fall back to the loaded maccms config for accurate `think info` output.
    $runtimeConfig = isset($GLOBALS['config']) && is_array($GLOBALS['config'])
        ? $GLOBALS['config']
        : (array)config('maccms');
    $app = isset($runtimeConfig['app']) && is_array($runtimeConfig['app']) ? $runtimeConfig['app'] : [];
    $checks = [];
    $push = function ($label, $ok, $detail, $guide, $optional = false) use (&$checks) {
        $checks[] = ['label' => $label, 'ok' => (bool)$ok, 'optional' => (bool)$optional, 'detail' => (string)$detail, 'guide' => (string)$guide];
    };

    // 1) OPcache 字节码缓存
    $opOn = false;
    try { $opOn = function_exists('opcache_get_status') && (int)ini_get('opcache.enable') === 1; } catch (\Throwable $e) {}
    $push('OPcache 字节码缓存', $opOn, $opOn ? '已开启' : '未开启',
        $opOn ? '' : '把 docker/php/opcache.ini 复制到 PHP 的 conf.d 目录后 reload(详见 docker/README.md)。零风险、显著降 CPU 与延迟。');

    // 2) 缓存后端
    $ct = isset($app['cache_type']) ? strtolower((string)$app['cache_type']) : 'file';
    $redisExt = false;
    try { $redisExt = extension_loaded('redis'); } catch (\Throwable $e) {}
    if ($ct === 'redis') {
        $reach = false;
        try {
            $h = app('cache')->store()->handler();
            if (class_exists('\\Redis', false) && $h instanceof \Redis) { $h->ping(); $reach = true; }
        } catch (\Throwable $e) {}
        $push('缓存后端', $reach, $reach ? 'Redis(连通正常)' : 'Redis(连接失败)',
            $reach ? '' : '检查 Redis 主机/端口/密码或服务是否启动;连接超时已为秒级,故障会快速降级不挂站。');
    } else {
        $push('缓存后端', false, '文件缓存',
            $redisExt
                ? '部署 Redis 后,在本「系统配置」把缓存方式切 redis,高并发下显著优于文件缓存。'
                : '先为 PHP 安装 redis 扩展(pecl install redis 后启用),再到「系统配置」切 redis。');
    }

    // 3) 会话存储
    $st = isset($app['session_type']) ? strtolower((string)$app['session_type']) : '';
    $push('会话存储', $st === 'redis', $st === 'redis' ? 'Redis' : '文件',
        $st === 'redis' ? '' : '「系统配置」会话存储切 redis,去除文件 session 写锁导致的同用户请求串行(需缓存为 redis)。');

    // 4) 数据库引擎(MyISAM 表锁)
    try {
        $prefix = (string)config('database.connections.mysql.prefix');
        $like = str_replace('_', '\\_', $prefix) . '%';
        $rows = \think\facade\Db::query(
            "SELECT COUNT(*) AS c FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND ENGINE = 'MyISAM' AND TABLE_NAME LIKE ?",
            [$like]
        );
        $my = (int)($rows[0]['c'] ?? 0);
        $push('数据库引擎', $my === 0, $my === 0 ? '全部 InnoDB' : ($my . ' 张表仍是 MyISAM'),
            $my === 0 ? '' : '「数据库」页点"转 InnoDB",根治 MyISAM 表锁导致的采集/高并发卡顿(低峰执行)。');
    } catch (\Throwable $e) {}

    // 5) PHP 版本
    $phpOk = PHP_VERSION_ID >= 80000;
    $push('PHP 版本', $phpOk, PHP_VERSION,
        $phpOk ? '' : 'PHP 7.4 已停止官方支持;评估升级到 8.1+(性能更好、仍受安全维护)。');

    // 6) Meilisearch(可选增强,关闭不算问题)
    try {
        if (class_exists('\\app\\common\\util\\MeilisearchService')) {
            $on = \app\common\util\MeilisearchService::enabled();
            $push('Meilisearch 搜索', true, $on ? '已启用' : '未启用(关键词走 LIKE 回退)',
                $on ? '' : '可选:部署 Meili 后在「Meilisearch」页启用,大幅提升搜索;关闭则自动回退,不影响功能。', true);
        }
    } catch (\Throwable $e) {}

    // 7) 整页缓存(匿名安全可用,读侧最大杠杆)
    $cp = isset($app['cache_page']) && (string)$app['cache_page'] === '1';
    $push('整页缓存(匿名)', $cp, $cp ? '已开启' : '未开启',
        $cp ? '' : '「系统配置」页面缓存设为开:匿名访客整页缓存(登录用户自动绕过、不串号),读侧提速最大。', !$cp);

    // 8) 输出压缩(gzip/HTML)
    try {
        $zlib = strtolower((string)ini_get('zlib.output_compression'));
        $gzipOn = ($zlib === '1' || $zlib === 'on') || (!empty($app['compress']) && (string)$app['compress'] === '1');
        $push('输出压缩', $gzipOn, $gzipOn ? '已开启' : '未开启',
            $gzipOn ? '' : '在 Web 服务器开 gzip/brotli(或 php.ini zlib.output_compression / 后台 HTML 压缩),降带宽与 TTFB。', !$gzipOn);
    } catch (\Throwable $e) {}

    // 9) PHP OPcache JIT(需 PHP 8+)
    try {
        $jit = function_exists('opcache_get_status') ? strtolower((string)ini_get('opcache.jit')) : '';
        $jitOn = PHP_VERSION_ID >= 80000 && $jit !== '' && $jit !== '0' && $jit !== 'off' && $jit !== 'disable';
        $push('PHP JIT', $jitOn, PHP_VERSION_ID >= 80000 ? ($jitOn ? '已开启' : '未开启') : '需 PHP 8+',
            $jitOn ? '' : (PHP_VERSION_ID >= 80000 ? 'php.ini 设 opcache.jit=tracing、opcache.jit_buffer_size=64M。' : '升级 PHP 8.1+ 后启用 JIT。'), true);
    } catch (\Throwable $e) {}

    // 10) InnoDB 缓冲池(热数据常驻内存)
    try {
        $rows = \think\facade\Db::query("SHOW VARIABLES LIKE 'innodb_buffer_pool_size'");
        $bpMb = (int)round((int)($rows[0]['Value'] ?? 0) / 1048576);
        if ($bpMb > 0) {
            $push('InnoDB 缓冲池', $bpMb >= 256, $bpMb . ' MB',
                $bpMb >= 256 ? '' : '建议把 innodb_buffer_pool_size 调到物理内存的 50–70%,热数据常驻内存、显著降磁盘 IO。', true);
        }
    } catch (\Throwable $e) {}

    // 11) API 限流(防公开接口被高频请求刷爆 CPU)
    $apiRl = !empty($app['anti_scrape_api_enabled']) && (string)$app['anti_scrape_api_enabled'] === '1';
    $push('API 限流', $apiRl, $apiRl ? '已开启' : '未开启',
        $apiRl ? '' : '「系统配置」开启 API 防爬/限流:公开 JSON 接口按 IP 限频,防被高频请求刷爆 CPU(采集 provide/推送 receive 已默认免限,不影响)。');

    // 12) 关键性能索引(高频查询的覆盖索引)
    try {
        $prefix = (string)config('database.connections.mysql.prefix');
        $perfIndexes = [
            [$prefix . 'type',    'idx_type_pid_sort'],
            [$prefix . 'vod',     'idx_vod_type_status_time'],
            [$prefix . 'vod',     'idx_vod_type1_status_time'],
            [$prefix . 'vod',     'idx_vod_status_time'],
            [$prefix . 'visit',   'idx_visit_time'],
            [$prefix . 'user',    'idx_user_reg_time'],
            [$prefix . 'comment', 'idx_comment_lookup'],
            [$prefix . 'comment', 'idx_comment_sub'],
        ];
        $missing = 0;
        foreach ($perfIndexes as [$tbl, $idx]) {
            $rows = \think\facade\Db::query(
                "SELECT COUNT(*) AS c FROM information_schema.STATISTICS
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?",
                [$tbl, $idx]
            );
            if ((int)($rows[0]['c'] ?? 0) === 0) {
                $missing++;
            }
        }
        $total = count($perfIndexes);
        $push('性能索引', $missing === 0,
            $missing === 0 ? '全部已建(' . $total . '个)' : '缺少 ' . $missing . '/' . $total . ' 个',
            $missing === 0 ? '' : '「数据库」页点"补充性能索引"自动创建缺失索引(幂等，可重复执行)，创建后高频查询速度显著提升。');
    } catch (\Throwable $e) {}

    return $checks;
}

/**
 * 缓存防击穿:单飞锁。仅用于"缓存未命中、即将回源"的并发收敛。
 * - Redis 后端:SET NX EX 原子锁(真正单飞);
 * - 其它后端:has+set 尽力而为(非原子,竞争时退化为多产出 = 现状,绝不更差);
 * - 任何异常都按"未获锁/可产出"处理,绝不阻断业务。
 * 锁带 TTL 自动过期,持有者崩溃也不会长期占锁。
 *
 * @return bool true=本请求应回源产出;false=他人正在产出(调用方可短等其结果)
 */
function mac_cache_lock_acquire($key, $ttl = 10)
{
    $ttl = max(1, (int)$ttl);
    try {
        $h = app('cache')->store()->handler();
        if (class_exists('\\Redis', false) && $h instanceof \Redis) {
            return (bool)$h->set('mac_sf:' . md5((string)$key), 1, ['nx', 'ex' => $ttl]);
        }
    } catch (\Throwable $e) {
        return true;
    }
    // 非 Redis:尽力而为
    try {
        $lk = 'mac_sf_' . md5((string)$key);
        if (\think\facade\Cache::has($lk)) {
            return false;
        }
        \think\facade\Cache::set($lk, 1, $ttl);
        return true;
    } catch (\Throwable $e) {
        return true;
    }
}

function mac_cache_lock_release($key)
{
    try {
        $h = app('cache')->store()->handler();
        if (class_exists('\\Redis', false) && $h instanceof \Redis) {
            $h->del('mac_sf:' . md5((string)$key));
            return;
        }
    } catch (\Throwable $e) {
    }
    try {
        \think\facade\Cache::delete('mac_sf_' . md5((string)$key));
    } catch (\Throwable $e) {
    }
}

/**
 * API 分页 limit 归一化(防变参放大攻击)。
 * 把任意 limit 收敛到两档 {10,20}:≤10→10,>10→20(封顶20);未传/非法→默认 20。
 * 攻击者狂变 limit=1,2,3,… 只会落到 10 或 20 两个值,无法制造大量不同查询/响应;
 * 同时把单页行数封到 ≤20,杜绝 ?limit=百万 放大。COUNT 缓存按 where 取键、与 limit 无关,不受影响。
 */
function mac_api_norm_limit($raw)
{
    $raw = (int)$raw;
    return ($raw > 0 && $raw <= 10) ? 10 : 20;
}

/**
 * 整页缓存是否对当前请求生效。
 * 安全:仅 index 入口 + 开关开 + GET + 匿名访客(maccms 前台登录基于 cookie;登录用户页面含
 * 用户名/VIP/积分等用户态,整页缓存会串号,故登录用户一律绕过)。匿名 GET 前台本就不开 session,
 * 缓存页天然无 Set-Cookie、对 CDN 友好。
 */
function mac_page_cache_eligible()
{
    if (!defined('ENTRANCE') || ENTRANCE !== 'index') {
        return false;
    }
    $app = isset($GLOBALS['config']['app']) && is_array($GLOBALS['config']['app']) ? $GLOBALS['config']['app'] : [];
    if (empty($app['cache_page']) || (string)$app['cache_page'] !== '1' || empty($app['cache_time_page'])) {
        return false;
    }
    if (strtoupper(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET') !== 'GET') {
        return false;
    }
    $uid = 0;
    try {
        $uid = intval(cookie('user_id'));
    } catch (\Throwable $e) {
        $uid = isset($_COOKIE['user_id']) ? intval($_COOKIE['user_id']) : 0;
    }
    return $uid <= 0;
}

/**
 * 缓存未命中时的单飞等待:抢锁失败者短等他人产出(有硬上限,绝不长挂)。
 * 返回他人产出的值(命中)或 null(超时,调用方自行产出)。
 * @param string $cacheKey 业务缓存键(读它判断他人是否已产出)
 */
function mac_cache_singleflight_wait($cacheKey, $maxMs = 1000, $stepMs = 50)
{
    $steps = max(1, (int)($maxMs / max(1, $stepMs)));
    for ($i = 0; $i < $steps; $i++) {
        usleep($stepMs * 1000);
        try {
            $v = \think\facade\Cache::get($cacheKey);
        } catch (\Throwable $e) {
            $v = null;
        }
        if (!empty($v)) {
            return $v;
        }
    }
    return null;
}

/**
 * 幂等添加索引:仅当所有列存在且同名索引不存在时执行 ADD INDEX。
 */
function mac_db_add_index_if_absent($table, $indexName, array $cols)
{
    $table = str_replace('`', '', $table);
    foreach ($cols as $c) {
        $r = \think\facade\Db::query("SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=? LIMIT 1", [$table, $c]);
        if (empty($r)) {
            return; // 缺列,跳过(兼容旧版库)
        }
    }
    $r = \think\facade\Db::query("SELECT 1 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND INDEX_NAME=? LIMIT 1", [$table, $indexName]);
    if (!empty($r)) {
        return; // 索引已存在
    }
    $colSql = implode(',', array_map(function ($c) {
        return '`' . str_replace('`', '', $c) . '`';
    }, $cols));
    \think\facade\Db::execute("ALTER TABLE `{$table}` ADD INDEX `{$indexName}` ({$colSql})");
}

/**
 * 性能(P2):API 层关键词搜索统一接入 Meilisearch。
 * 返回改写后的 [where, order, total](命中ID集 + 相关性排序 + Meili 预估总数)或 false(由调用方走原 LIKE)。
 * 安全:Meili 未启用 / 无关键词 / 桥接异常 / 无命中 / where 含无法映射的过滤 一律返回 false → 回退原 LIKE,绝不改变既有结果集语义。
 *
 * 注意分页:命中 where 形如 `pk IN(本页ID)`,即 Meili 已按 $page/$num/$start 完成分页。
 *   - 调用方用 getListByCond 时:Meili 命中后 offset 必须传 0(否则二次分页,第 2 页起为空)。
 *   - 调用方用 listData 时:Meili 命中后须以 page=1/start=0 调用(避免二次分页),再用本函数返回的 total 覆盖 $res['total']/'pagecount'。
 *
 * @param string $module vod|art|manga|actor|role|website
 * @param array  $where  原始查询条件(含关键词 LIKE,桥接会自行剥离文本搜索键)
 * @param string $kw     关键词
 * @param int    $page   页码(1 起)
 * @param int    $num    每页条数
 * @param mixed  $order  当前排序(未命中相关性时透传)
 * @param int    $start  附加偏移(offset 型分页传 offset,page 型分页传 0)
 * @return array|false   [where, order, total] 或 false
 */
function mac_meili_api_apply($module, $where, $kw, $page = 1, $num = 20, $order = '', $start = 0)
{
    $kw = trim((string)$kw);
    if ($kw === '' || !class_exists('\\app\\common\\util\\MeilisearchService') || !\app\common\util\MeilisearchService::enabled()) {
        return false;
    }
    $page  = $page > 0 ? (int)$page : 1;
    $num   = $num > 0 ? (int)$num : 20;
    $start = $start > 0 ? (int)$start : 0;
    try {
        $B = '\\app\\common\\util\\MeilisearchListBridge';
        switch ($module) {
            case 'vod':     $m = $B::applyForVod($where, $kw, '', '', '', '', '', $page, $num, $start, $order); break;
            case 'art':     $m = $B::applyForArt($where, $kw, '', '', '', $page, $num, $start, $order); break;
            case 'manga':   $m = $B::applyForManga($where, $kw, '', '', '', $page, $num, $start, $order); break;
            case 'actor':   $m = $B::applyForActor($where, $kw, '', $page, $num, $start, $order); break;
            case 'role':    $m = $B::applyForRole($where, $kw, '', '', $page, $num, $start, $order); break;
            case 'website': $m = $B::applyForWebsite($where, $kw, '', '', '', $page, $num, $start, $order); break;
            default:        return false;
        }
        if (is_array($m) && isset($m['where'])) {
            return [$m['where'], (isset($m['order']) ? $m['order'] : $order), (isset($m['total']) ? $m['total'] : null)];
        }
        return false;
    } catch (\Throwable $e) {
        return false;
    }
}

/**
 * 安全加固(V4):口令哈希。新口令用 bcrypt;校验兼容旧的 32位 md5,
 * 旧 md5 校验通过后由调用方透明 rehash 升级为 bcrypt。
 */
function mac_password_hash($pwd)
{
    return password_hash((string)$pwd, PASSWORD_DEFAULT);
}

function mac_password_verify($pwd, $hash)
{
    $hash = (string)$hash;
    $pwd  = (string)$pwd;
    if ($hash === '') {
        return false;
    }
    if (strlen($hash) === 32 && ctype_xdigit($hash)) {
        return hash_equals(strtolower($hash), md5($pwd));
    }
    return password_verify($pwd, $hash);
}

function mac_password_need_rehash($hash)
{
    $hash = (string)$hash;
    if (strlen($hash) === 32 && ctype_xdigit($hash)) {
        return true;
    }
    return password_needs_rehash($hash, PASSWORD_DEFAULT);
}

/**
 * 安全加固(V1/SSRF):远程URL安全校验。
 * 仅允许 http/https;拒绝私网/保留/回环/链路本地(含云元数据 169.254.169.254)IP;
 * 解析主机名后逐个IP校验;无法解析则拒绝(fail-closed)。
 */
function mac_ip_is_public($ip)
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}

function mac_is_safe_remote_url($url)
{
    $url = trim((string)$url);
    if ($url === '') {
        return false;
    }
    $p = @parse_url($url);
    if (!$p || empty($p['scheme']) || empty($p['host'])) {
        return false;
    }
    if (!in_array(strtolower($p['scheme']), ['http', 'https'], true)) {
        return false;
    }
    $host = trim($p['host'], '[]');
    $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ips[] = $host;
    } else {
        if (function_exists('dns_get_record')) {
            $recs = @dns_get_record($host, DNS_A | DNS_AAAA);
            if (is_array($recs)) {
                foreach ($recs as $r) {
                    if (!empty($r['ip']))   { $ips[] = $r['ip']; }
                    if (!empty($r['ipv6'])) { $ips[] = $r['ipv6']; }
                }
            }
        }
        if (!$ips) {
            $ip4 = @gethostbyname($host);
            if ($ip4 && $ip4 !== $host) { $ips[] = $ip4; }
        }
    }
    if (!$ips) {
        return false;
    }
    foreach ($ips as $ip) {
        if (!mac_ip_is_public($ip)) {
            return false;
        }
    }
    return true;
}

function mac_check_back_link($url)
{
    $res=[];
    $res['code'] = 0;
    $res['msg'] = lang('param_err');

    if(empty($url)){
        return json($res);
    }
    // 安全加固(V1/SSRF):仅允许公网 http/https 目标,防探测内网/云元数据
    if(!mac_is_safe_remote_url($url)){
        return json($res);
    }

    $site_url = $GLOBALS['config']['site']['site_url'];
    $site_wapurl = $GLOBALS['config']['site']['site_wapurl'];
    $html = mac_curl_get($url);
    $msg = '';
    $code = 1;

    $ok = lang('back_link').lang('normal');
    $err = lang('back_link').lang('abnormal');

    $msg .= '['.$site_url.']';
    if(strpos($html,$site_url)!==false){
        $code=1;
        $msg .=$ok;
    }
    else{
        $code=101;
        $msg .=$err;
    }

    $msg .= '，['.$site_wapurl.']';
    if(strpos($html,$site_wapurl)!==false){
        $code =1;
        $msg .=$ok;
    }
    else{
        $code=101;
        $msg .=$err;
    }
    $res['code'] = $code;
    $res['msg'] = $msg;

    return $res;
}

function mac_list_to_tree($list, $pk='id',$pid = 'pid',$child = 'child',$root=0)
{
    $tree = array();
    if(is_array($list)) {
        $refer = array();
        foreach ($list as $key => $data) {
            // 确保每个节点都有 child 键(叶子节点为空数组),避免模板 {volist name="x.child"} 在 PHP8 下未定义键 → 500
            if (!isset($list[$key][$child])) {
                $list[$key][$child] = [];
            }
            $refer[$data[$pk]] =& $list[$key];
        }

        foreach ($list as $key => $data) {
            $parentId = $data[$pid];

            if ($root == $parentId) {
                $tree[] =& $list[$key];

            }else{
                if (isset($refer[$parentId])) {
                    $parent =& $refer[$parentId];
                    $parent[$child][] =& $list[$key];
                }
            }
        }
    }
    return $tree;
}

function mac_str_correct($str,$from,$to)
{
    return str_replace($from,$to,$str ?? '');
}

function mac_buildregx($regstr,$regopt)
{
    return '/'.str_replace('/','\/',$regstr).'/'.$regopt;
}

function mac_em_replace($s)
{
    return preg_replace("/\[em:(\d{1,})?\]/","<img src=\"". MAC_PATH ."static/images/face/$1.gif\" border=0/>",$s);
}

function mac_page_param($record_total, $page_size, $page_current, $page_url,$page_half=5)
{
    $page_param = array();
    $page_num = array();

    if ($record_total == 0) {
        return ['record_total'=>0,'page_current'=>$page_current,'page_total'=>0,
                'page_url'=>$page_url,'page_prev'=>1,'page_next'=>1,'page_num'=>[],'page_sp'=>''];
    }
    if(empty($page_half)){
        $page_half=5;
    }

    $page_param['record_total'] = $record_total;
    $page_param['page_current'] = $page_current;

    $page_total = ceil($record_total / $page_size);
    $page_param['page_total'] = $page_total;
    $page_param['page_sp'] = MAC_PAGE_SP;

    $page_prev = $page_current - 1;
    if ($page_prev <= 0) {
        $page_prev = 1;
    }
    $page_next = $page_current + 1;
    if ($page_next > $page_total) {
        $page_next = $page_total;
    }
    $page_param['page_prev'] = $page_prev;
    $page_param['page_next'] = $page_next;

    if ($page_total <= $page_half) {
        for ($i = 1; $i <= $page_total; $i++) {
            $page_num[$i] = $i;
        }
    } else {
        $page_num_left = floor($page_half / 2);
        $page_num_right = $page_total - $page_half;

        if ($page_current <= $page_num_left) {
            for ($i = 1; $i <= $page_half; $i++) {
                $page_num[$i] = $i;
            }
        } elseif ($page_current > $page_num_right) {
            for ($i = ($page_num_right + 0); $i <= $page_total; $i++) {
                $page_num[$i] = $i;
            }
        } else {
            for ($i = ($page_current - $page_num_left); $i <= ($page_current + $page_num_left); $i++) {
                $page_num[$i] = $i;
            }
        }
    }
    $page_param['page_num'] = $page_num;
    $page_param['page_num_min'] = count($page_num) ? min($page_num) : 1;
    $page_param['page_num_max'] = count($page_num) ? max($page_num) : 1;
    $page_param['page_url'] = $page_url;

    return $page_param;
}

// CurlPOST数据提交-----------------------------------------
/**
 * 安全加固:识别官方/上游服务器域名(更新/插件市场/资源站/短网址/播放器联盟等)。
 * 用于切断与官方的一切出站通信,防止上游被劫持后向本站下发恶意代码。
 */
function mac_is_official_url($url)
{
    $host = @parse_url((string)$url, PHP_URL_HOST);
    if (!$host) {
        return false;
    }
    $host = strtolower($host);
    $blocked = [
        // ── 上游官方域：升级/统计/关键词等通道，一律不通信 ──
        // update.maccms.la 是已被证实投毒的升级通道（奇安信 xlab 披露 FUNNULL/RingH23）。
        // 本站日志实测：注入的远程 JS 曾在 26 次登录后自动驱动
        // admin/update/step1.html?file=laupd<hash>，靠 step1 的 exit 与本函数双重拦下。
        'maccms.la', 'maccms.com', 'maccms.cn', 'maccms.ai', 'dplayerstatic.com',

        // ── FUNNULL/RingH23 投毒链的伪 CDN 与分发域（同一披露）──
        // 全部是仿冒知名 CDN 的抢注域名，用来托管 JS 载荷与跳转脚本，例如
        // code.jquecy.com 仿 code.jquery.com（r→c 一字之差）。
        // 老机(已下线待处置)的 template/155zy/js/{jquery-1.12.4.min,layui}.js 尾部
        // 被追加的载荷即指向 code.jquecy.com/jquery.min-3.6.8.js。
        // 这里挡在【唯一的出站卡口】上：任何现有或将来新增的代码路径想访问它们都会被拒，
        // 不依赖 /etc/hosts（换机器、重装系统都不会丢）。
        'jquecy.com', 'jsdclivr.com', 'clondflare.com', 'bytedauce.com',
        'macoms.la', 'bdustatic.com', 'jsdelivr.vip',
        'ailyunoss.com', 'ailyun-oss.com',
        'aqyaqua.com', 'zhw.sh',
    ];
    foreach ($blocked as $d) {
        if ($host === $d || substr($host, -(strlen($d) + 1)) === '.' . $d) {
            return true;
        }
    }
    return false;
}

function mac_curl_post($url,$data,$heads=array(),$cookie='',$timeout=10)
{
    // 安全加固:切断与官方服务器的通信(防止下发病毒)
    if (mac_is_official_url($url)) { return ''; }
    $timeout = max(1, (int)$timeout);
    $ch = @curl_init();
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36');
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, min(5, $timeout));  // 连接超时 ≤5s
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_HEADER,0);
    curl_setopt($ch, CURLOPT_REFERER, $url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    if(!empty($cookie)){
        curl_setopt($ch, CURLOPT_COOKIE, $cookie);
    }
    if(count($heads)>0){
        curl_setopt ($ch, CURLOPT_HTTPHEADER , $heads );
    }
    $response = @curl_exec($ch);
    if(curl_errno($ch)){//出错则显示错误信息
        //print curl_error($ch);
    }
    curl_close($ch); //关闭curl链接
    return $response;//显示返回信息
}
// CurlPOST数据提交-----------------------------------------
/**
 * SSRF 防护说明(已评审并接受残留):
 * 调用方在所有受源控制的取数点(Image::down_exec 图片下载、Collect 全部 fetch 经 checkCjUrl、
 * 外链检测)前置调用 mac_is_safe_remote_url(),解析 A/AAAA 并以 FILTER_FLAG_NO_PRIV_RANGE|
 * NO_RES_RANGE 拒绝字面内网/保留/回环/链路本地(含云元数据 169.254.169.254)IP 与内网域名;
 * 本函数另限定 http/https 协议并限制重定向跳数。
 * 已知残留(接受并记录):公网域名 302 跳转到内网、DNS-rebinding 可绕过"预检→连接"间隙——
 * 属高级且为盲打(响应不回显给请求方)。彻底封堵需连接期校验(CURLOPT_OPENSOCKETFUNCTION),
 * 但该常量在部分 PHP 构建缺失,且本函数被支付/推送/上传/采集广泛调用,改动爆炸半径大,
 * 故暂不在此公共函数实施;如需收口,优先在 Image/Collect 处做"关闭自动重定向 + 逐跳重校验"。
 */
function mac_curl_get($url,$heads=array(),$cookie='',$timeout=10)
{
    // 安全加固:切断与官方服务器的通信(防止下发病毒)
    if (mac_is_official_url($url)) { return ''; }
    $timeout = max(1, (int)$timeout);
    $ch = @curl_init();
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36');

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    // 安全加固(V1/SSRF):仅允许 http/https 协议,限制重定向次数,防止 302 跳转到 file://gopher://dict:// 等内部协议
    if (defined('CURLPROTO_HTTP')) {
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    }
    curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, min(5, $timeout));  // 连接超时 ≤5s
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_HEADER,0);
    curl_setopt($ch, CURLOPT_REFERER, $url);
    curl_setopt($ch, CURLOPT_POST, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 1);
    if(!empty($cookie)){
        curl_setopt($ch, CURLOPT_COOKIE, $cookie);
    }
    if(count($heads)>0){
        curl_setopt ($ch, CURLOPT_HTTPHEADER , $heads );
    }
    $response = @curl_exec($ch);
    if(curl_errno($ch)){//出错则显示错误信息
        //print curl_error($ch);die;
    }
    curl_close($ch); //关闭curl链接
    return $response;//显示返回信息
}


function mac_substring($str, $lenth, $start=0)
{
    $str = mac_scalar_string($str);
    $len = strlen($str);
    $r = array();
    $n = 0;
    $m = 0;

    for($i=0;$i<$len;$i++){
        $x = substr($str, $i, 1);
        $a = base_convert(ord($x), 10, 2);
        $a = substr( '00000000 '.$a, -8);

        if ($n < $start){
            if (substr($a, 0, 1) == 0) {
            }
            else if (substr($a, 0, 3) == 110) {
                $i += 1;
            }
            else if (substr($a, 0, 4) == 1110) {
                $i += 2;
            }
            $n++;
        }
        else{
            if (substr($a, 0, 1) == 0) {
                $r[] = substr($str, $i, 1);
            }else if (substr($a, 0, 3) == 110) {
                $r[] = substr($str, $i, 2);
                $i += 1;
            }else if (substr($a, 0, 4) == 1110) {
                $r[] = substr($str, $i, 3);
                $i += 2;
            }else{
                $r[] = ' ';
            }
            if (++$m >= $lenth){
                break;
            }
        }
    }
    return  join('',$r);
}


function mac_array2xml($arr,$level=1)
{
    $s = $level == 1 ? "<xml>" : '';
    foreach($arr as $tagname => $value) {
        if (is_numeric($tagname)) {
            $tagname = $value['TagName'];
            unset($value['TagName']);
        }
        if(!is_array($value)) {
            $s .= "<{$tagname}>".(!is_numeric($value) ? '<![CDATA[' : '').$value.(!is_numeric($value) ? ']]>' : '')."</{$tagname}>";
        } else {
            $s .= "<{$tagname}>" . mac_array2xml($value, $level + 1)."</{$tagname}>";
        }
    }
    $s = preg_replace("/([\x01-\x08\x0b-\x0c\x0e-\x1f])+/", ' ', $s);
    return $level == 1 ? $s."</xml>" : $s;
}


function mac_xml2array($xml)
{
    libxml_disable_entity_loader(true);
    $result= json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
    return $result;
}

function mac_array_rekey($arr,$key)
{
    $list = [];
    foreach($arr as $k=>$v){
        $list[$v[$key]] = $v;
    }
    return $list;
}

function mac_array_filter($arr,$str)
{
    if(!is_array($arr)){
        $arr = explode(',',$arr);
    }
    $arr = array_filter($arr);
    if(empty($arr)){
        return false;
    }
    //方式一
    $new_str = str_replace($arr,'*',$str);
    //$badword1 = array_combine($arr,array_fill(0,count($arr),'*'));
    //$new_str = strtr($str, $badword1);
    return $new_str != $str;
}

function mac_parse_sql($sql='',$limit=0,$prefix=[])
{
    // 被替换的前缀
    $from = '';
    // 要替换的前缀
    $to = '';

    // 替换表前缀
    if (!empty($prefix)) {
        $to   = current($prefix);
        $from = current(array_flip($prefix));
    }

    if ($sql != '') {
        // 纯sql内容
        $pure_sql = [];

        // 多行注释标记
        $comment = false;

        // 按行分割，兼容多个平台
        $sql = str_replace(["\r\n", "\r"], "\n", $sql);
        $sql = explode("\n", trim($sql));
        $cnm = 'a版权所有magicblack，源码https://github.com/magicblack'  /* 原base64已还原 */;
        // 循环处理每一行
        foreach ($sql as $key => $line) {
            // 跳过空行
            if ($line == '') {
                continue;
            }

            // 跳过以#或者--开头的单行注释
            if (preg_match("/^(#|--)/", $line)) {
                continue;
            }

            // 跳过以/**/包裹起来的单行注释
            if (preg_match("/^\/\*(.*?)\*\//", $line)) {
                continue;
            }

            // 多行注释开始
            if (substr($line, 0, 2) == '/*') {
                $comment = true;
                continue;
            }

            // 多行注释结束
            if (substr($line, -2) == '*/') {
                $comment = false;
                continue;
            }

            // 多行注释没有结束，继续跳过
            if ($comment) {
                continue;
            }

            // 替换表前缀
            if ($from != '') {
                $line = str_replace('`'.$from, '`'.$to, $line);
            }
            if ($line == 'BEGIN;' || $line =='COMMIT;') {
                continue;
            }
            // sql语句
            array_push($pure_sql, $line);
        }

        // 只返回一条语句
        if ($limit == 1) {
            return implode("",$pure_sql);
        }


        // 以数组形式返回sql语句
        $pure_sql = implode("\n",$pure_sql);
        $pure_sql = explode(";\n", $pure_sql);
        return $pure_sql;
    } else {
        return $limit == 1 ? '' : [];
    }
}

function mac_interface_type()
{
    $key = $GLOBALS['config']['app']['cache_flag']. '_'. 'interface_type';
    $data = think\facade\Cache::get($key);
    if(empty($data)){
        $config = config('maccms.interface');
        $vodtype = str_replace([chr(10),chr(13)],['','#'],$config['vodtype']);
        $arttype = str_replace([chr(10),chr(13)],['','#'],$config['arttype']);
        $actortype = str_replace([chr(10),chr(13)],['','#'],$config['actortype']);
        $websitetype = str_replace([chr(10),chr(13)],['','#'],$config['websitetype']);
        $mangatype = str_replace([chr(10),chr(13)],['','#'],isset($config['mangatype']) ? $config['mangatype'] : '');

        $data =[];
        $type_arr = explode('#',$vodtype);
        foreach($type_arr as $k=>$v){
            list($from, $to) = explode('=', $v);
            $data['vodtype'][$to] = $from;
        }

        $type_arr = explode('#',$arttype);
        foreach($type_arr as $k=>$v){
            list($from, $to) = explode('=', $v);
            $data['arttype'][$to] = $from;
        }

        $type_arr = explode('#',$actortype);
        foreach($type_arr as $k=>$v){
            list($from, $to) = explode('=', $v);
            $data['actortype'][$to] = $from;
        }

        $type_arr = explode('#',$websitetype);
        foreach($type_arr as $k=>$v){
            list($from, $to) = explode('=', $v);
            $data['websitetype'][$to] = $from;
        }

        if(!empty($mangatype)){
            $type_arr = explode('#',$mangatype);
            foreach($type_arr as $k=>$v){
                if(strpos($v,'=')!==false){
                    list($from, $to) = explode('=', $v);
                    $data['mangatype'][$to] = $from;
                }
            }
        }
        if(empty($data['mangatype'])){
            $data['mangatype'] = [];
        }

        think\facade\Cache::set($key,$data);
    }

    $type_list = (new \app\common\model\Type())->getCache('type_list');
    $type_names = [];
    foreach($type_list as $k=>$v){
        $type_names[$v['type_name']] = $v['type_id'];
    }

    foreach($data['vodtype'] as $k=>$v){
        $data['vodtype'][$k] = (int)$type_names[$v];
    }
    foreach($data['arttype'] as $k=>$v){
        $data['arttype'][$k] = (int)$type_names[$v];
    }
    foreach($data['actortype'] as $k=>$v){
        $data['actortype'][$k] = (int)$type_names[$v];
    }
    foreach($data['websitetype'] as $k=>$v){
        $data['websitetype'][$k] = (int)$type_names[$v];
    }
    if(!empty($data['mangatype'])){
        foreach($data['mangatype'] as $k=>$v){
            $data['mangatype'][$k] = (int)$type_names[$v];
        }
    }
    return $data;
}

function mac_rep_pse_rnd($psearr,$txt,$id=0)
{
    if(empty($psearr)){
        return $txt;
    }
    $i=count($psearr);
    if(empty($txt)){
        if(empty($id)){
            $r = mt_rand(0,$i-1);
        }
        else{
            $r = $id % $i;
        }
        $res= $psearr[$r];
    }
    else{
        if(empty($id)){
            $id = crc32($txt);
        }
        $j=mb_strpos($txt,"<br>");
        $k=mb_strlen($txt);
        if($j==0){ $j=mb_strpos($txt,"<br/>"); }
        if($j==0){ $j=mb_strpos($txt,"<br />"); }
        if($j==0){ $j=mb_strpos($txt,"</p>"); }
        if($j==0){ $j=mb_strpos($txt,"。"); }
        if($j==0){ $j=mb_strpos($txt,"！"); }
        if($j==0){ $j=mb_strpos($txt,"!"); }
        if($j==0){ $j=mb_strpos($txt,"？"); }
        if($j==0){ $j=mb_strpos($txt,"?"); }
        if($j>0){
            $res= mac_substring($txt,$j-1) . $psearr[$id % $i] . mac_substring($txt,$k-$j,$j);
        }
        else{
            $res= $psearr[$id % $i]. $txt;
        }
    }
    return $res;
}

function mac_txt_explain($txt, $decode = false)
{
    // 先将HTML实体中的#临时替换为特殊占位符
    $placeholder = '___HTML_ENTITY_HASH___';
    $txt = preg_replace('/&#(\d+);/', $placeholder . '$1;', $txt);
    $txt = preg_replace('/&#x([0-9a-fA-F]+);/', $placeholder . 'x$1;', $txt);
    // 安全地按#分割
    $txtarr = explode('#', $txt);
    // 还原HTML实体中的#
    foreach($txtarr as &$item) {
        $item = str_replace($placeholder, '&#', $item);
    }
    unset($item);
    $data=[];
    foreach($txtarr as $v){
        if (stripos($v, '=') === false) {
            continue;
        }
        list($from, $to) = explode('=', $v, 2);
        if ($decode === true && stripos($from, '&') !== false && stripos($from, ';') !== false) {
            $from = html_entity_decode($from, ENT_QUOTES, 'UTF-8');
        }
        if ($decode === true && stripos($to, '&') !== false && stripos($to, ';') !== false) {
            $to = html_entity_decode($to, ENT_QUOTES, 'UTF-8');
        }
        $data['from'][] = $from;
        $data['to'][] = $to;
    }
    return $data;
}

function mac_rep_pse_syn($psearr,$txt)
{
    if(empty($txt)){ $txt=""; }
    if(is_array($psearr['from']) && is_array($psearr['to'])){
        $txt = str_replace($psearr['from'],$psearr['to'],$txt);
    }
    return $txt;
}

function mac_get_tag($title,$content){
    $url = 'http://api.dplayerstatic.com'  /* 原base64已还原 */.'/keyword/index?name='.rawurlencode($title).'&txt='.rawurlencode($title).rawurlencode(mac_substring(strip_tags($content),200));
    $data = mac_curl_get($url);
    $json = @json_decode($data,true);
    if($json){
        if($json['code']==1){
            return implode(',',$json['data']);
        }
    }
    return false;
}

function mac_get_client_ip()
{
    static $final;
    if (!is_null($final)) {
        return $final;
    }
    $ips = [];
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'] ?? '')) {
        $ips[] = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '';
    }
    if (!empty($_SERVER['HTTP_ALI_CDN_REAL_IP'] ?? '')) {
        $ips[] = $_SERVER['HTTP_ALI_CDN_REAL_IP'] ?? '';
    }
    if (!empty($_SERVER['HTTP_CLIENT_IP'] ?? '')) {
        $ips[] = $_SERVER['HTTP_CLIENT_IP'] ?? '';
    }
    if (!empty($_SERVER['HTTP_PROXY_USER'] ?? '')) {
        $ips[] = $_SERVER['HTTP_PROXY_USER'] ?? '';
    }
    $real_ip = getenv('HTTP_X_REAL_IP');
    if (!empty($real_ip)) {
        $ips[] = $real_ip;
    }
    if (!empty($_SERVER['REMOTE_ADDR'] ?? '')) {
        $ips[] = $_SERVER['REMOTE_ADDR'] ?? '';
    }
    // 选第一个最合法的，或最后一个正常的IP
    foreach ($ips as $ip) {
        $verifyResult = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE);
        if (!$verifyResult){
            continue;
        }
        $verifyResult && $final = $ip;
    }
    empty($final) && $final = '0.0.0.0';
    return $final;
}

/**
 * 前台写接口按 IP 的温和限流(默认开启,独立于 anti_scrape 全局开关),防刷评论/留言/提现等垃圾与 CPU 打满。
 * 阈值取"远高于真人(含 NAT 共享出口)峰值、却远低于自动化洪泛"的区间,故对正常用户零回归。
 * 失败开放(限流器不可用或内部异常时放行),不阻断正常业务。
 *
 * @param string $scope     逻辑名(如 fe_comment),仅 [a-z0-9_]
 * @param int    $windowSec 窗口秒
 * @param int    $maxHits   窗口内最大次数
 * @return bool   true=放行, false=超限(调用方应拒绝)
 */
function mac_fe_write_throttle($scope, $windowSec, $maxHits)
{
    if (!class_exists('\\app\\common\\util\\SlidingWindowIpLimiter')) {
        return true;
    }
    $ip = function_exists('mac_get_client_ip') ? (string)mac_get_client_ip() : (string)($_SERVER['REMOTE_ADDR'] ?? '');
    if ($ip === '' || $ip === '0.0.0.0') {
        return true;
    }
    $rl = \app\common\util\SlidingWindowIpLimiter::checkHit($ip, $scope, $windowSec, $maxHits, 'fe_write_rl');
    return !empty($rl['allowed']);
}

/**
 * 列表排序参数归一,返回安全的 ORDER BY 片段 "$prefix$by $dir"。
 * - $by 仅保留 [A-Za-z0-9_](列名/后缀本就如此),非法字符剔除;归一后为空则回退 $default。
 * - $dir 仅允许 asc/desc(大小写不敏感),否则回退 desc。
 * 目的:消除畸形 by/order 参数触发的 TP5 parseKey 异常(500),并对 ORDER BY 作字符级纵深防御。
 * 对合法输入(单字段后缀 + asc/desc)语义等价,零回归。
 *
 * @param string $prefix  列前缀,如 'vod_'(可为空)
 * @param string $by      排序字段/后缀(可能来自用户)
 * @param string $dir     排序方向(可能来自用户)
 * @param string $default $by 归一为空时的回退字段后缀(默认 'id')
 * @return string 形如 'vod_time desc'
 */
function mac_safe_order($prefix, $by, $dir, $default = 'id')
{
    $by = preg_replace('/[^A-Za-z0-9_]/', '', (string)$by);
    if ($by === '') {
        $by = $default;
    }
    $dir = strtolower(trim((string)$dir));
    $dir = ($dir === 'asc') ? 'asc' : 'desc';
    return $prefix . $by . ' ' . $dir;
}

function mac_get_ip_long($ip_addr = '')
{
    $ip_addr = !empty($ip_addr) ? $ip_addr : mac_get_client_ip();
    $ip_long = sprintf('%u',ip2long($ip_addr));
    // 排除不正确的IP
    if ($ip_long < 0 || $ip_long >= 0xFFFFFFFF) {
        $ip_long = 0;
    }
    return $ip_long;
}

function mac_get_uniqid_code($code_prefix='')
{
    $code_prefix = strtoupper($code_prefix);
    $now_date = date('YmdHis');
    $now_time = rand(100000, 999999);
    return $code_prefix . $now_date . $now_time;
}

function mac_escape($string, $in_encoding = 'UTF-8',$out_encoding = 'UCS-2') {
    $return = '';
    if (function_exists('mb_get_info')) {
        for($x = 0; $x < mb_strlen ( $string, $in_encoding ); $x ++) {
            $str = mb_substr ( $string, $x, 1, $in_encoding );
            if (strlen ( $str ) > 1) { // 多字节字符
                $return .= '%u' . strtoupper ( bin2hex ( mb_convert_encoding ( $str, $out_encoding, $in_encoding ) ) );
            } else {
                $return .= '%' . strtoupper ( bin2hex ( $str ) );
            }
        }
    }
    return $return;
}
function mac_unescape($str)
{
    $ret = '';
    $len = strlen($str);
    for ($i = 0; $i < $len; $i ++)
    {
        if ($str[$i] == '%' && $str[$i + 1] == 'u')
        {
            $val = hexdec(substr($str, $i + 2, 4));
            if ($val < 0x7f)
                $ret .= chr($val);
            else
                if ($val < 0x800)
                    $ret .= chr(0xc0 | ($val >> 6)) .
                        chr(0x80 | ($val & 0x3f));
                else
                    $ret .= chr(0xe0 | ($val >> 12)) .
                        chr(0x80 | (($val >> 6) & 0x3f)) .
                        chr(0x80 | ($val & 0x3f));
            $i += 5;
        } else
            if ($str[$i] == '%')
            {
                $ret .= urldecode(substr($str, $i, 3));
                $i += 2;
            } else
                $ret .= $str[$i];
    }
    return $ret;
}

/*特殊字段的值转换*/
function mac_get_mid_code($data)
{
    $arr = [
        1  => 'vod',
        2  => 'art',
        3  => 'topic',
        4  => 'comment',
        5  => 'gbook',
        6  => 'user',
        7  => 'label',
        8  => 'actor',
        9  => 'role',
        10 => 'plot',
        11 => 'website',
        12 => 'manga',
    ];
    return $arr[$data] ?? '';
}
function mac_get_mid_text($data)
{
    $arr = [
        1  => lang('vod'),
        2  => lang('art'),
        3  => lang('topic'),
        4  => lang('comment'),
        5  => lang('gbook'),
        6  => lang('user'),
        7  => lang('label'),
        8  => lang('actor'),
        9  => lang('role'),
        10 => lang('plot'),
        11 => lang('website'),
        12 => lang('manga'),
    ];
    return $arr[$data] ?? '';
}
function mac_get_mid($controller)
{
    $controller=strtolower($controller);
    $arr = [
        'vod'     => 1,
        'art'     => 2,
        'topic'   => 3,
        'comment' => 4,
        'gbook'   => 5,
        'user'    => 6,
        'label'   => 7,
        'actor'   => 8,
        'role'    => 9,
        'plot'    => 10,
        'website' => 11,
        'manga'   => 12,
    ];
    return $arr[$controller] ?? 0;
}

/**
 * 与 index/ajax/digg 一致：当前请求是否已对该内容点过赞（Cookie）
 */
function mac_user_has_digg($mid, $id)
{
    $mid = (int) $mid;
    $id = (int) $id;
    if ($id < 1 || $mid < 1) {
        return 0;
    }
    $pre = mac_get_mid_code($mid);
    if ($pre === null || $pre === '') {
        return 0;
    }
    $cookie = $pre . '-digg-' . $id;

    return !empty(cookie($cookie)) ? 1 : 0;
}

/**
 * 登录用户是否已收藏（ulog_type=2）
 *
 * @return array{is_fav:int,fav_ulog_id:int}
 */
function mac_user_fav_state($userId, $ulogMid, $rid)
{
    $userId = (int) $userId;
    $ulogMid = (int) $ulogMid;
    $rid = (int) $rid;
    if ($userId < 1 || $rid < 1 || $ulogMid < 1) {
        return ['is_fav' => 0, 'fav_ulog_id' => 0];
    }
    $row = (new \app\common\model\Ulog())->where([
        'user_id'   => $userId,
        'ulog_mid'  => $ulogMid,
        'ulog_type' => 2,
        'ulog_rid'  => $rid,
    ])->field('ulog_id')->find();
    if (!empty($row['ulog_id'])) {
        return ['is_fav' => 1, 'fav_ulog_id' => (int) $row['ulog_id']];
    }

    return ['is_fav' => 0, 'fav_ulog_id' => 0];
}

function mac_get_aid($controller,$action='')
{
    $controller=strtolower($controller);
    $action=strtolower($action);
    $key = $controller.'/'.$action;

    $arr=['index'=>1,'map'=>2,'rss'=>3,'gbook'=>4,'comment'=>5,'user'=>6,'label'=>7,'vod'=>10,'art'=>20,'manga'=>120,'topic'=>30,'actor'=>80,'role'=>90,'plot'=>100,'website'=>110,'live'=>130];
    $res = isset($arr[$controller]) ? $arr[$controller] : 0;

    // https://github.com/magicblack/maccms10/issues/960
    $arr=[
        'vod/type'=>11,'vod/show'=>12,'vod/search'=>13,'vod/search_hub'=>13,'vod/detail'=>14,'vod/play'=>15,'vod/down'=>16,'vod/role'=>17,'vod/plot'=>18,
        'art/type'=>21,'art/show'=>22,'art/search'=>23,'art/detail'=>24,'art/read'=>25,
        'manga/type'=>121,'manga/show'=>122,'manga/search'=>123,'manga/detail'=>124,'manga/play'=>125,
        'topic/search'=>33,'topic/detail'=>34,
        'actor/type'=>81,'actor/show'=>82,'actor/search'=>83,'actor/detail'=>84,
        'role/show'=>92,'role/search'=>93,'role/detail'=>94,
        'plot/search'=>103,'plot/detail'=>104,
        'website/type'=>111,'website/show'=>112,'website/search'=>113,'website/detail'=>114,
        'live/show'=>131,'live/play'=>132,
    ];
    if(!empty($arr[$key])){
        $res= $arr[$key];
    }
    return $res;
}

function mac_get_user_status_text($data)
{
    $arr = [
        0 => lang('disable'),
        1 => lang('enable'),
    ];
    return $arr[$data];
}
function mac_get_user_flag_text($data)
{
    $arr = [
        0 => lang('counting_points'),
        1 => lang('counting_times'),
        2 => lang('counting_ips'),
    ];
    return $arr[$data];
}

function mac_get_ulog_type_text($data)
{
    $arr = [
        1 => lang('browse'),
        2 => lang('collect'),
        3 => lang('want_see'),
        4 => lang('play'),
        5 => lang('down'),
    ];
    return $arr[$data];
}

function mac_get_plog_type_text($data)
{
    $arr = [
        1 => lang('integral_recharge'),
        2 => lang('registration_promotion'),
        3 => lang('visit_promotion'),
        4 => lang('one_level_distribution'),
        5 => lang('two_level_distribution'),
        6 => lang('three_level_distribution'),
        7 => lang('points_upgrade'),
        8 => lang('integral_consumption'),
        9 => lang('integral_withdrawal'),
        10 => lang('plog_sign_milestone_reward'),
        11 => lang('plog_task_sign_reward'),
    ];
    return isset($arr[$data]) ? $arr[$data] : '';
}

function mac_get_card_sale_status_text($data)
{
    $arr = [
        0 => lang('not_sale'),
        1 => lang('sold'),
    ];
    return $arr[$data];
}

function mac_get_card_use_status_text($data)
{
    $arr = [
        0 => lang('not_used'),
        1 => lang('used'),
    ];
    return $arr[$data];
}

function mac_get_order_status_text($data)
{
    $arr = [
        0 => lang('not_paid'),
        1 => lang('paid'),
    ];
    return $arr[$data];
}

function mac_get_user_portrait($user_id = null)
{
    $res = MAC_PATH . 'static_new/images/touxiang.png';
    if ($user_id === null && !empty($GLOBALS['user']['user_id'])) {
        $user_id = (int)$GLOBALS['user']['user_id'];
    }
    if(!empty($user_id)){
        $res2 = 'upload/user/'.($user_id % 10 ). '/'.$user_id.'.jpg';
        if(file_exists(ROOT_PATH . $res2)){
            $res = MAC_PATH . $res2;
        }
    }
    return $res;
}

function mac_scalar_string($val, $default = '')
{
    if (is_string($val)) {
        return $val;
    }
    if (is_array($val) || is_object($val)) {
        return $default;
    }
    if ($val === null || $val === false) {
        return $default;
    }
    return (string)$val;
}

function mac_filter_html($str)
{
    $str = mac_scalar_string($str);
    return strip_tags($str);
}

function mac_filter_xss($str)
{
    $str = mac_scalar_string($str);
    // 识别URL类型，跳过HTML实体转义
    // 判断是否为URL格式：http://、https://、//、mac: 开头，或包含 :// 的字符串
    $trimmed_str = trim($str);
    if (!empty($trimmed_str)) {
        // 检查是否为URL格式
        $is_url = false;

        // 检查是否以常见协议开头（最严格的判断，优先级最高）
        if (preg_match('/^(https?:\/\/|ftp:\/\/|\/\/|mac:)/i', $trimmed_str)) {
            $is_url = true;
        }
        // 检查是否包含 :// 协议标识符（包含协议但可能不是常见协议）
        elseif (strpos($trimmed_str, '://') !== false) {
            $is_url = true;
        }
        // 注意：这个条件相对宽松，但只去除HTML标签仍然安全
        elseif (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}(\/|\?|&|=|$)/', $trimmed_str)) {
            $is_url = true;
        }

        if ($is_url) {
            // URL 类型：去标签后【仍必须转义引号与尖括号】。否则"长得像 URL"的脏值
            //（如 vod_name = a.com/" onmouseover="alert(1)）会被这里的 is_url 启发式误判为
            // URL 而跳过实体转义，进而在模板的 src="..." / title="..." / alt="..." 里
            // 截断属性、挂上事件处理器（属性截断存储型 XSS）。
            // 只转义 " ' < >，保留 & = ? / 等 URL 合法字符不动 —— 真实 URL 的语义与显示
            // 完全不受影响（合法 URL 本就不含裸引号/尖括号）。
            $u = strip_tags($trimmed_str);
            $u = str_replace(['"', "'", '<', '>'], ['&quot;', '&#039;', '&lt;', '&gt;'], $u);
            return trim($u);
        }
    }

    // 普通文本：正常进行XSS过滤
    return trim(htmlspecialchars(strip_tags($trimmed_str), ENT_QUOTES));
}

function mac_restore_htmlfilter($str) {
    // 安全加固（存储型 XSS 根因）：原实现对任何含 &amp; 的串做 htmlspecialchars_decode，
    // 会把入库时 htmlentities() 转义过的评论/留言正文整段解码回真实 HTML —— 正文里只要
    // 带一个字面 & 就触发，等于亲手把存储型 XSS 放回前台（/index.php/gbook 服务端内联渲染、
    // 评论区 .html() 注入，对所有访客零点击执行，可盗管理员会话接管后台）。
    // 存储内容已在入库端正确转义，输出端必须原样吐出，绝不能再解码。保留函数名做 no-op 垫片，
    // 避免改动全部模板/调用点。
    return (string)$str;
}

/**
 * 富文本正文净化器（art_content / actor_content / manga_content / role_content /
 * website_content 等【保留 HTML】的字段）。这些字段既不能像普通字段那样整体 htmlspecialchars
 * （会毁掉排版），采集/接收(Collect::*_data 直接 insert)与后台保存(saveData 的 filter_fields
 * 【不含】content)又都从不过滤它 —— <script>/<iframe>/<svg onload>/on事件/js伪协议 可原样落库，
 * 主题一旦渲染 *_content 即存储型 XSS。
 *
 * 纯核心 PHP 实现（strip_tags 白名单 + 属性清洗 + 校验兜底），【不依赖 ext-dom/mbstring】
 * ——本项目 composer 仅要求 ext-json/pdo，采集为高频路径，绝不能引入可能缺失的扩展。
 * 语义等价浏览器：实体编码的 &lt;script&gt; 只是文本、予以保留；真正的可执行结构一律铲除。
 * 宁可丢排版也绝不放行 XSS（第 5 步兜底：残留危险标签即降级为纯文本）。
 */
function mac_html_sanitize($html) {
    $html = mac_scalar_string($html);
    if ($html === '') { return ''; }
    // 0) 去 NULL 与危险控制字符（保留 \t\n\r）
    $html = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $html);
    if (strpos($html, '<') === false) { return $html; } // 纯文本快路径

    // 1) 整枝删除"带内容"的危险元素（闭合 + 未闭合兜底），循环到稳定以拆散 <scr<script>ipt>
    $killWithContent = ['script','style','title','textarea','noscript','noembed','template','xml','svg','math','iframe','frameset'];
    for ($pass = 0; $pass < 3; $pass++) {
        $before = $html;
        foreach ($killWithContent as $t) {
            $html = preg_replace('#<'.$t.'\b[^>]*>.*?</'.$t.'\s*>#is', '', $html);
            $html = preg_replace('#</?'.$t.'\b[^>]*>?#is', '', $html);
        }
        if ($html === $before) { break; }
    }
    // 2) 删注释 / CDATA / 条件注释 / doctype / PI
    $html = preg_replace('#<!--.*?-->#s', '', $html);
    $html = preg_replace('#<!\[CDATA\[.*?\]\]>#is', '', $html);
    $html = preg_replace('#<![^>]*>#s', '', $html);
    $html = preg_replace('#<\?.*?\?>#s', '', $html);

    // 3) 标签白名单，其余标签剥离（strip_tags 保留内部文本，核心 C 解析器）
    $allowed = '<p><br><hr><b><strong><i><em><u><s><strike><del><ins><span><div>'
             . '<a><img><ul><ol><li><dl><dt><dd><table><caption><colgroup><col>'
             . '<thead><tbody><tfoot><tr><td><th><h1><h2><h3><h4><h5><h6>'
             . '<blockquote><q><pre><code><font><sub><sup><small><mark><abbr>'
             . '<figure><figcaption><section><article><header><footer><nav><aside>';
    $html = strip_tags($html, $allowed);

    // 4) 逐开标签清洗属性：删 on* 事件、srcdoc/xmlns、危险协议 URL、style 里的 js
    $html = preg_replace_callback(
        '#<([a-zA-Z][a-zA-Z0-9]*)((?:"[^"]*"|\'[^\']*\'|[^>"\'])*)>#s',
        function ($m) {
            $attrs = $m[2];
            $attrs = preg_replace('#\s+on\w+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)#i', '', $attrs);
            $attrs = preg_replace('#\s+(?:srcdoc|xmlns(?::\w+)?)\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)#i', '', $attrs);
            $attrs = preg_replace_callback(
                '#\s+([a-zA-Z:_-]+)\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)#s',
                function ($a) {
                    $an = strtolower($a[1]);
                    $av = trim($a[2], "\"'");
                    // 解码实体 + 去空白/控制字符，破解 &#106;avascript: / java\tscript: 类绕过
                    $probe = strtolower(preg_replace('/[\x00-\x20]/', '', html_entity_decode($av, ENT_QUOTES)));
                    if (preg_match('#^(?:javascript|vbscript|livescript|mocha|data|about|blob):#', $probe)
                        && !preg_match('#^data:image/(?:png|jpe?g|gif|webp|bmp|x-icon)#', $probe)) {
                        return '';
                    }
                    if ($an === 'style'
                        && preg_match('#expression\s*\(|javascript\s*:|vbscript\s*:|behavior\s*:|@import|-moz-binding#i', $av)) {
                        return '';
                    }
                    return $a[0];
                },
                $attrs
            );
            return '<' . $m[1] . $attrs . '>';
        },
        $html
    );

    // 5) 校验兜底：若仍残留危险开标签（异常/畸形构造绕过前面步骤），直接降级为纯文本。
    if (preg_match('#<\s*(?:script|iframe|svg|object|embed|style|form|math|applet|meta|link|base|frame)\b#i', $html)) {
        return trim(strip_tags($html));
    }
    return trim($html);
}

function mac_format_text($str, $allow_space = false)
{
    $finder = array('/', '，', '|', '、', ',,', ',,,');
    if ($allow_space === false) {
        $finder[] = ' ';
    }
    return str_replace($finder, ',', $str);
}
function mac_format_count($str)
{
    $arr = explode(',',$str);
    return count($arr);
}

function mac_txt_merge($txt,$str)
{
    if(empty($str)){
        return $txt;
    }
    if($GLOBALS['config']['collect']['vod']['class_filter'] !='0') {
        if (mb_strlen($str) > 2) {
            $str = str_replace([lang('slice')], [''], $str);
        }
        if (mb_strlen($str) > 2) {
            $str = str_replace([lang('drama')], [''], $str);
        }
    }
    $txt = mac_format_text($txt);
    $str = mac_format_text($str);
    $arr1 = explode(',',$txt);
    $arr2 = explode(',',$str);
    $arr = array_merge($arr1,$arr2);
    return join(',',array_unique( array_filter($arr)));
}

function mac_array_check_num($arr)
{
    if(!is_array($arr)){
        return false;
    }
    $res = true;
    foreach($arr as $a){
        if(!is_numeric($a)){
            $res=false;
            break;
        }
    }
    return $res;
}

function mac_like_arr($s)
{
    $tmp = explode(',',$s);
    $like_arr = [];
    foreach($tmp as $v){
        $like_arr[] = '%'.$v.'%';
    }
    return $like_arr;
}

/**
 * TP8 compatible: append LIKE condition(s) to a TP8 $where array.
 * Replaces the TP5 dict-format `$where[$field] = mac_search_wd_like($wd)` pattern.
 */
function mac_apply_like_where(array &$where, string $field, string $wd): void
{
    $wd = trim($wd);
    if ($wd === '') {
        return;
    }
    $patterns = \app\common\util\OpenccConverter::likePatterns($wd);
    if (count($patterns) > 4) {
        $patterns = array_slice($patterns, 0, 4);
    }
    if (empty($patterns)) {
        $where[] = [$field, 'like', '%' . $wd . '%'];
        return;
    }
    if (count($patterns) === 1) {
        $where[] = [$field, 'like', $patterns[0]];
        return;
    }
    $where[] = function ($q) use ($field, $patterns) {
        foreach ($patterns as $i => $p) {
            $i === 0 ? $q->whereLike($field, $p) : $q->whereLike($field, $p, 'OR');
        }
    };
}

function mac_art_list($art_title,$art_note,$art_content)
{
    $art_title_list = [];
    $art_note_list = [];
    $art_content_list = [];
    if(!empty($art_title)) {
        $art_title_list = explode('$$$', $art_title);
    }
    if(!empty($art_note)) {
        $art_note_list = explode('$$$', $art_note);
    }
    if(!empty($art_content)) {
        $art_content_list = explode('$$$', $art_content);
    }
    $res_list = [];
    foreach($art_content_list as $k=>$v){
        $res_list[$k+1] = [
            'page'=> $k+1,
            'title'=>$art_title_list[$k] ?? '',
            'note'=>$art_note_list[$k] ?? '',
            'content'=>$v,
        ];
    }
    return $res_list;
}

function mac_plot_list($vod_plot_name,$vod_plot_detail)
{
    $vod_plot_name_list = [];
    $vod_plot_detail_list = [];

    if(!empty($vod_plot_name)) {
        $vod_plot_name_list = explode('$$$', $vod_plot_name);
    }
    if(!empty($vod_plot_detail)) {
        $vod_plot_detail_list = explode('$$$', $vod_plot_detail);
    }

    $res_list = [];
    foreach($vod_plot_name_list as $k=>$v){

        $res_list[$k + 1] = [
                'name' => $vod_plot_name_list[$k],
                'detail' => $vod_plot_detail_list[$k],
        ];
    }
    return $res_list;

}



function mac_play_list($vod_play_from,$vod_play_url,$vod_play_server,$vod_play_note,$flag='play')
{
    $vod_play_from_list = [];
    $vod_play_url_list = [];
    $vod_play_server_list = [];
    $vod_play_note_list = [];

    if(!empty($vod_play_from)) {
        $vod_play_from_list = explode('$$$', $vod_play_from);
    }
    if(!empty($vod_play_url)) {
        $vod_play_url_list = explode('$$$', $vod_play_url);
    }
    if(!empty($vod_play_server)) {
        $vod_play_server_list = explode('$$$', $vod_play_server);
    }
    if(!empty($vod_play_note)) {
        $vod_play_note_list = explode('$$$', $vod_play_note);
    }

    if($flag=='play'){
        $player_list = config('vodplayer');
    }
    else{
        $player_list = config('voddowner');
    }
    $server_list = config('vodserver');

    $res_list = [];
    $sort=[];
    foreach($vod_play_from_list as $k=>$v){
        $server = (string)($vod_play_server_list[$k] ?? '');
        $urls = mac_play_list_one($vod_play_url_list[$k] ?? '',$v);

        $player_info = !empty($player_list[$v]) ? $player_list[$v] : (reset($player_list) ?: []);
        $server_info = $server_list[$server] ?? [];
        if(($player_info['status'] ?? '0') == '1' || !empty($player_info)) {
            $sort[] = $player_info['sort'] ?? 0;
            $res_list[$k + 1] = [
                'sid' => $k + 1,
                'player_info' => $player_info,
                'server_info' => $server_info,
                'from' => $v,
                'url' => $vod_play_url_list[$k] ?? '',
                'server' => $server,
                'note' => $vod_play_note_list[$k] ?? '',
                'url_count' => count($urls),
                'urls' => $urls,
            ];
        }
    }

    if( (ENTRANCE!='admin' && MAC_PLAYER_SORT=='1') ||  ($GLOBALS['ismake'] ?? '')=='1' ){
        array_multisort($sort, SORT_DESC, SORT_FLAG_CASE , $res_list);
        $tmp=[];
        foreach($res_list as $k=>$v){
            $tmp[$v['sid']] = $v;
        }
        $res_list = $tmp;
    }
    return $res_list;
}

function new_stripslashes($string) {
    if(!is_array($string)) return stripslashes($string);
    foreach($string as $key => $val) $string[$key] = new_stripslashes($val);
    return $string;
}

function mac_screenshot_list($screenshot)
{
    $url_list = array();
    $array_url = explode('#',$screenshot);
    foreach($array_url as $key=>$val){
        if(empty($val)) continue;

        list($title, $url) = explode('$', $val);
        if ( empty($url) ) {
            $url_list[$key+1]['name'] = ($key+1);
            $url_list[$key+1]['url'] = $title;
        }else{
            $url_list[$key+1]['name'] = $title;
            $url_list[$key+1]['url'] = $url;
        }
    }
    return $url_list;
}

function mac_play_list_one($url_one, $from_one, $server_one=''){
    $url_list = array();
    $array_url = explode('#',$url_one);
    foreach($array_url as $key=>$val){
        if(empty($val)) continue;

        [$title, $url, $from] = array_pad(explode('$', $val, 3), 3, '');
        if ( empty($url) ) {
            $url_list[$key+1]['name'] = lang('the').($key+1).lang('episode');
            $url_list[$key+1]['url'] = $server_one.$title;
        }else{
            $url_list[$key+1]['name'] = $title;
            $url_list[$key+1]['url'] = $server_one.$url;
        }
        if(empty($from)){
            $from = $from_one;
        }
        $url_list[$key+1]['from'] = (string)$from;
        $url_list[$key+1]['nid'] = $key+1;
    }
    return $url_list;
}

function mac_manga_list($manga_play_from,$manga_play_url,$manga_play_server,$manga_play_note)
{
    $manga_play_from_list = [];
    $manga_play_url_list = [];
    $manga_play_server_list = [];
    $manga_play_note_list = [];

    if(!empty($manga_play_from)) {
        $manga_play_from_list = explode('$$$', $manga_play_from);
    }
    if(!empty($manga_play_url)) {
        $manga_play_url_list = explode('$$$', $manga_play_url);
    }
    if(!empty($manga_play_server)) {
        $manga_play_server_list = explode('$$$', $manga_play_server);
    }
    if(!empty($manga_play_note)) {
        $manga_play_note_list = explode('$$$', $manga_play_note);
    }

    $res_list = [];
    foreach($manga_play_from_list as $k=>$v){
        $server = (string)$manga_play_server_list[$k];
        $urls = mac_play_list_one($manga_play_url_list[$k],$v);

        $res_list[$k + 1] = [
            'sid' => $k + 1,
            'from' => $v,
            'url' => $manga_play_url_list[$k],
            'server' => $server,
            'note' => $manga_play_note_list[$k],
            'url_count' => count($urls),
            'urls' => $urls,
        ];
    }
    return $res_list;
}

function mac_filter_words($p)
{
    $config = config('maccms.app');
    $arr = explode(",",$config['filter_words']);
    if(is_array($p)){
        foreach($p as $k=>$v){
            $p[$k] = str_replace($arr,"***",$v);
        }
    }
    else{
        $p = str_replace($arr,"***",$p);
    }
    return $p;
}

function mac_long2ip($ip){
    $ip = long2ip($ip);
    $reg2 = '~(\d+)\.(\d+)\.(\d+)\.(\d+)~';
    return preg_replace($reg2, "$1.$2.*.*", $ip);
}
function mac_default($s,$def='')
{
    if(empty($s)){
        return $def;
    }
    return $s;
}
function mac_num_fill($num)
{
    if($num<10){
        $num = '0' . $num;
    }
    return $num;
}

function mac_multisort($arr,$col_sort,$sort_order,$col_status='',$status_val='')
{
    $sort=[];
    foreach($arr as $k=>$v){
        if($col_status!='' && $v[$col_status] != $status_val){
            unset($arr[$k]);
       } else {
            $sort[] = isset($v[$col_sort]) ? $v[$col_sort] : 0;
       }
    }
    array_multisort($sort, $sort_order, SORT_FLAG_CASE, $arr);
    return $arr;
}

function mac_get_body($text,$start,$end)
{
    if(empty($text)){ return false; }
    if(empty($start)){ return false; }
    if(empty($end)){ return false; }

    $start=stripslashes($start);
    $end=stripslashes($end);

    if(strpos($text,$start)!=""){
        $str = substr($text,strpos($text,$start)+strlen($start));
        $str = substr($str,0,strpos($str,$end));
    }
    else{
        $str='';
    }
    return $str;
}

function mac_find_array($text,$start,$end)
{
    $start=stripslashes($start);
    $end=stripslashes($end);
    if(empty($text)){ return false; }
    if(empty($start)){ return false; }
    if(empty($end)){ return false; }

    $start = str_replace(["(",")","'","?"],["\(","\)","\'","\?"],$start);
    $end = str_replace(["(",")","'","?"],["\(","\)","\'","\?"],$end);

    $labelRule = $start."(.*?)".$end;
    $labelRule = mac_buildregx($labelRule,"is");
    preg_match_all($labelRule,$text,$tmparr);
    $tmparrlen=count($tmparr[1]);
    $rc=false;
    $str='';
    $arr=[];
    for($i=0;$i<$tmparrlen;$i++) {
        if($rc){ $str .= "{array}"; }
        $str .= $tmparr[1][$i];
        $rc=true;
    }

    if(empty($str)) { return false ;}
    $str=str_replace($start,"",$str);
    $str=str_replace($end,"",$str);
    //$str=str_replace("\"\"","",$str);
    //$str=str_replace("'","",$str);
    //$str=str_replace(" ","",$str);
    if(empty($str)) { return false ;}
    return $str;
}

/*前台页面*/
function mac_param_url(){
    $input = input() ;
    $param = [];
    $tmp = $_REQUEST;
    
    $input = array_merge($input, $tmp);
    //$param['id'] = intval($input['id'] ?? 0);
    $param['page'] = intval($input['page'] ?? 0) < 1 ? 1 : intval($input['page'] ?? 0);
    $param['ajax'] = intval($input['ajax'] ?? 0);
    $param['tid'] = intval($input['tid'] ?? 0);
    $param['mid'] = intval($input['mid'] ?? 0);
    $param['rid'] = intval($input['rid'] ?? 0);
    $param['pid'] = intval($input['pid'] ?? 0);
    $param['sid'] = intval($input['sid'] ?? 0);
    $param['nid'] = intval($input['nid'] ?? 0);
    $param['uid'] = intval($input['uid'] ?? 0);
    $param['level'] = intval($input['level'] ?? 0);
    $param['score'] = intval($input['score'] ?? 0);
    $param['limit'] = intval($input['limit'] ?? 0);

    $param['id'] = htmlspecialchars(urldecode(trim($input['id'] ?? '')));
    $param['ids'] = htmlspecialchars(urldecode(trim($input['ids'] ?? '')));
    $param['wd'] = htmlspecialchars(urldecode(trim($input['wd'] ?? '')));
    $param['en'] = htmlspecialchars(urldecode(trim($input['en'] ?? '')));
    $param['state'] = htmlspecialchars(urldecode(trim($input['state'] ?? '')));
    $param['area'] = htmlspecialchars(urldecode(trim($input['area'] ?? '')));
    $param['year'] = htmlspecialchars(urldecode(trim($input['year'] ?? '')));
    $param['lang'] = htmlspecialchars(urldecode(trim($input['lang'] ?? '')));
    $param['letter'] = htmlspecialchars(trim($input['letter'] ?? ''));
    $param['actor'] = htmlspecialchars(urldecode(trim($input['actor'] ?? '')));
    $param['director'] = htmlspecialchars(urldecode(trim($input['director'] ?? '')));
    $param['tag'] = htmlspecialchars(urldecode(trim($input['tag'] ?? '')));
    $param['class'] = htmlspecialchars(urldecode(trim($input['class'] ?? '')));
    $param['order'] = htmlspecialchars(urldecode(trim($input['order'] ?? '')));
    $param['by'] = htmlspecialchars(urldecode(trim($input['by'] ?? '')));
    $param['file'] = htmlspecialchars(urldecode(trim($input['file'] ?? '')));
    $param['name'] = htmlspecialchars(urldecode(trim($input['name'] ?? '')));
    $param['url'] = htmlspecialchars(urldecode(trim($input['url'] ?? '')));
    $param['type'] = htmlspecialchars(urldecode(trim($input['type'] ?? '')));
    $param['sex'] = htmlspecialchars(urldecode(trim($input['sex'] ?? '')));
    $param['version'] = htmlspecialchars(urldecode(trim($input['version'] ?? '')));
    $param['blood'] = htmlspecialchars(urldecode(trim($input['blood'] ?? '')));
    $param['starsign'] = htmlspecialchars(urldecode(trim($input['starsign'] ?? '')));
    $param['domain'] = htmlspecialchars(urldecode(trim($input['domain'] ?? '')));

    return $param;
}

function mac_get_page($page)
{
    if(empty($page)) {
        $param = mac_param_url();
        $page = $param['page'];
    }
    return $page;
}

function mac_tpl_fetch($model,$tpl,$def='')
{
    return $model . '/' . ( empty($tpl) ? $def  : str_replace('.html','',$tpl) );
}

function mac_get_order($order,$param)
{
    if(!empty($param['order'])) {
        $order = $param['order'];
    }
    if(!in_array($order, ['asc', 'desc'])) {
        $order = 'desc';
    }
    return $order;
}

function mac_url_img($url)
{
    $url = mac_scalar_string($url);
    if ($url === '') {
        return '';
    }
    if(substr($url,0,4) == 'mac:'){
        $protocol = $GLOBALS['config']['upload']['protocol'];
        if(empty($protocol)){
            $protocol = 'http';
        }
        $url = str_replace('mac:', $protocol.':',$url);
    }
    elseif(substr($url,0,4) != 'http' && substr($url,0,2) != '//' && substr($url,0,1) != '/'){
        if($GLOBALS['config']['upload']['mode']=='remote'){
            $url = $GLOBALS['config']['upload']['remoteurl'] . $url;
        }
        else{
            $url = MAC_PATH . $url;
        }
    }
    elseif(!empty($GLOBALS['config']['upload']['img_key']) && preg_match('/'.$GLOBALS['config']['upload']['img_key'].'/',$url)){
        $url = $GLOBALS['config']['upload']['img_api'] . '' . $url;
    }
    $url = mac_filter_xss($url);
    $url = str_replace('&quot;&gt;', '', $url);
    $url = str_replace('&amp;', '&', $url);
    return $url;
}

function mac_url_content_img($content)
{
    $content = mac_scalar_string($content);
    $protocol = $GLOBALS['config']['upload']['protocol'];
    if(empty($protocol)){
        $protocol = 'http';
    }
    $content = str_replace('mac:',$protocol.':',$content);
    if(!empty($GLOBALS['config']['upload']['img_key'])){
        $rule = mac_buildregx("<img[^>]*src\s*=\s*['" . chr(34) . "]?([\w/\-\:.]*)['" . chr(34) . "]?[^>]*>", "is");
        preg_match_all($rule, $content, $matches);
        if(is_array($matches[1])){
            foreach ($matches[1] as $f => $matchfieldstr) {
                $img_src = trim(preg_replace("/[ \r\n\t\f]{1,}/", " ", $matchfieldstr));
                if(preg_match('/'.$GLOBALS['config']['upload']['img_key'].'/',$img_src)){
                    $content = str_replace($img_src,$GLOBALS['config']['upload']['img_api'] . '' . $img_src,$content);
                }
            }
        }
    }
    return $content;
}

function mac_alphaID($in, $to_num=false, $pad_up=false, $passKey='')
{
    $key = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (!empty($passKey)) {
        for ($n = 0; $n<strlen($key); $n++) {
            $i[] = substr($key,$n ,1);
        }
        $len = strlen($key);
        $passhash = hash('sha256',$passKey);
        $passhash = (strlen($passhash) < $len)
            ? hash('sha512',$passKey)
            : $passhash;
        for ($n=0; $n < $len; $n++) {
            $p[] = substr($passhash, $n ,1);
        }
        array_multisort($p, SORT_DESC, $i);
        $key = implode($i);
    }
    $base = strlen($key);
    if ($to_num) {
        $out = 0;
        $len = strlen($in);
        for ($t = 0; $t < $len; $t++) {
            $char = substr($in, $t, 1);
            $pos = strpos($key, $char);
            if ($pos === false) {
                $pos = 0;
            }
            $out = $out * $base + $pos;
        }
        if (is_numeric($pad_up)) {
            if ($pad_up > 1) {
                $out -= pow($base, $pad_up - 1);
            }
        }
    } else {
        if (is_numeric($pad_up)) {
            if ($pad_up > 1) {
                $in += pow($base, $pad_up - 1);
            }
        }
        $out = "";
        // 修复部分：改用逐位计算代替浮点运算
        while ($in > 0) {
            $remainder = $in % $base;
            $out = substr($key, $remainder, 1) . $out;
            $in = ($in - $remainder) / $base;
        }
    }
    return $out;
}

/**
 * 交给框架 url() 之前对参数做两件事,两件都是 TP8 下必须的:
 *
 * 1) 丢掉空值。TP8 的 route.url_common_param 默认 true,剩余参数走
 *    http_build_query,而它【不跳过空值】—— TP5 那边是逐个拼且带
 *    `'' !== trim($val)` 判断的。mac_url 自己又把"第 1 页"表达成
 *    $param['page']='' 这个哨兵值,于是每条链接尾巴上都挂着 `?page=`,
 *    筛选页更是 `?area=&by=time&class=&lang=&...` 一长串空参数。
 *    对搜索引擎这是一堆彼此重复的 URL,对 CDN 是白白炸开的缓存键。
 *
 * 2) 对会落到【路径段】的变量做 rawurlencode。url_common_param=true 时
 *    think\route\Url 对路由变量走的是 `(string)$vars[$key]`,不编码
 *    (false 时才 urlencode)。于是演员名/标签/关键词里的空格、/ ? # 会原样
 *    进入 href:实测 mac_url_search(['wd'=>'李四/王五']) 产出
 *    `/vodsearch/李四/王五.html`(斜杠改变了路由),['wd'=>'C?D'] 产出
 *    `/vodsearch/C?D.html`(问号之后被当查询串,关键词截断)。
 *    这些值直接来自采集数据,含空格的演员名在影视站是常态。
 *    用 rawurlencode 而不是 urlencode:路径段里空格必须是 %20,不是 +。
 *    入站侧 mac_param_url() 会 urldecode,已实测往返一致:
 *      /vodsearch/%E5%BC%A0%20%E4%B8%89.html => mac_param_url()['wd'] === '张 三'
 */
function mac_url_vars(array $param)
{
    // 会成为路由变量(路径段)的键。其余键留给 http_build_query 自己编码,
    // 在这里预编码会导致双重编码。
    static $pathVars = ['wd','id','en','name','tag','class','area','lang','letter','actor','director','year','state','level','by','order','page','file'];
    $out = [];
    foreach ($param as $k => $v) {
        if ($v === '' || $v === null || $v === false) {
            continue;
        }
        if (is_string($v) && in_array($k, $pathVars, true)
            && preg_match('/[^A-Za-z0-9._~-]/', $v)
            && rawurldecode($v) === $v) {   // 已经是编码过的值就不再编码,避免双重编码
            $v = rawurlencode($v);
        }
        $out[$k] = $v;
    }
    return $out;
}

function mac_url($model,$param=[],$info=[])
{
    foreach($param as $k=>$v){
        if(empty($v)){
            unset($param[$k]);
        }
    }

    if(!isset($param['page'])) $param['page']=1;

    if($param['page'] == 1){
        $param['page']='';
    }

    ksort($param); 

    $config = $GLOBALS['config'];
    
    $is_static_mode = isset($GLOBALS['ismake']) && $GLOBALS['ismake'] == '1';
    
    // 静态生成模式标记（用于后续URL处理）
    $replace_from = ['{id}','{en}','{page}','{type_id}','{type_en}','{type_pid}','{type_pen}','{md5}','{year}','{month}','{day}','{sid}','{nid}'];
    $replace_to = [];
    $page_sp = ($config['path']['page_sp'] ?? '');
    $path = '';


    switch ($model)
    {
        case 'index/index':
            if(($config['view']['index'] ?? 0) == 2){
                $path = 'index';
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
            }
            else{
                $url = url($model,mac_url_vars($param));
                if($url=='/PAGELINK.html'){
                    $url = '/index-PAGELINK.html';
                }
            }
            break;
        case 'map/index':
            if(($config['view']['map'] ?? 0) == 2){
                $path = 'map';
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
            }
            else{
                $url = url($model,mac_url_vars($param));
            }
            break;
        case strpos($model,'rss/')!==false:
            if(($config['view']['rss'] ?? 0) == 2){
                $path = $model;
                if($param['page'] !=''){
                    $path .= $page_sp . $param['page'];
                }

                $path .= '.xml';
            }
            else{
                $url = url($model,mac_url_vars($param),'xml');
            }
            break;
        case strpos($model,'label/')!==false:
            if(($config['view']['label'] ?? 0) == 2){
                $path = $model;
            }
            else{
                $url = url($model,mac_url_vars($param));
            }
            break;
        case 'vod/show':
        case 'art/show':
        case 'actor/show':
        case 'website/show':
            switch($config['rewrite']['type_id'] ?? 0)
            {
                case 1:
                    $id = $info['type_en'] ?? '';
                    break;
                case 2:
                    $id = mac_alphaID($info['type_id'] ?? 0,false,$config['rewrite']['encode_len'] ?? 6,$config['rewrite']['encode_key'] ?? '');
                    break;
                default:
                    $id = $info['type_id'] ?? 0;
                    break;
            }
            if(!empty($id)){
                $param['id'] = $id;
            }
            $url = url($model,mac_url_vars($param));
            break;
        case 'vod/type':
            $replace_to = [$info['type_id'],$info['type_en'],$param['page'],
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? ''),
            ];
            if(($config['view']['vod_type'] ?? 0) == 2){
                $path = ($config['path']['vod_type'] ?? '');
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                $replace_to[] = md5($info['type_id']);
                if($param['page'] !=''){
                    $path .= $page_sp . $param['page'];
                }
            }
            else{
                switch($config['rewrite']['type_id'])
                {
                    case 1:
                        $id = $info['type_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['type_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['type_id'];
                        break;
                }
                $url = url($model,['id'=>$id,'page'=>($param['page'] ?? 1)]);
            }
            break;
        case 'vod/detail':
            $replace_to = [$info['vod_id'],$info['vod_en'],'',
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? '')
            ];
            if(($config['view']['vod_detail'] ?? 0) == 2){
                $path = $config['path' ]['vod_detail'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                $replace_to[] = md5($info['vod_id']);
            }
            else{
                switch($config['rewrite']['vod_id'])
                {
                    case 1:
                        $id = $info['vod_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['vod_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['vod_id'];
                        break;
                }

                $url = url($model,['id'=> $id ]);
            }
            $replace_to = array_merge($replace_to,[date('Y',$info['vod_time']),date('m',$info['vod_time']),date('d',$info['vod_time'])]);
            break;
        case 'manga/detail':
            $replace_to = [$info['manga_id'],$info['manga_en'],'',
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? '')
            ];
            if(($config['view']['manga_detail'] ?? 0) == 2){
                $path = $config['path' ]['manga_detail'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                $replace_to[] = md5($info['manga_id']);
            }
            else{
                switch($config['rewrite']['manga_id'])
                {
                    case 1:
                        $id = $info['manga_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['manga_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['manga_id'];
                        break;
                }

                $url = url($model,['id'=> $id ]);
            }
            $replace_to = array_merge($replace_to,[date('Y',$info['manga_time']),date('m',$info['manga_time']),date('d',$info['manga_time'])]);
            break;
        case 'vod/play':
            $replace_to = [
                $info['vod_id'],$info['vod_en'],'',
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? ''),

            ];
            if(($config['view']['vod_play'] ?? 0) >=2){
                $path = $config['path' ]['vod_play'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                $replace_to[] = md5($info['vod_id']);
                if(($config['view']['vod_play'] ?? 0) ==2){
                    $path.= '.'. ($config['path']['suffix'] ?? '');
                    $path .= '?'.$info['vod_id'] . '-' . $param['sid'] . '-' . $param['nid'] ;
                }
                elseif(($config['view']['vod_play'] ?? 0) ==3){
                    $path .= ($config['path']['page_sp'] ?? '') . $param['sid'] . ($config['path']['page_sp'] ?? '') . $param['nid'] ;
                }
                elseif(($config['view']['vod_play'] ?? 0) ==4){
                    $path .= ($config['path']['page_sp'] ?? '') .''. $param['sid'] . ($config['path']['page_sp'] ?? '') . '1';
                    $path.= '.'. ($config['path']['suffix'] ?? '');
                    $path .= '?'.$info['vod_id'] . '-' . $param['sid'] . '-' . $param['nid'] ;
                }
            }
            else{
                switch($config['rewrite']['vod_id'])
                {
                    case 1:
                        $id = $info['vod_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['vod_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['vod_id'];
                        break;
                }
                $url = url($model,['id'=>$id,'sid'=>$param['sid'],'nid'=>$param['nid']]);
            }
            $replace_to = array_merge($replace_to,[date('Y',$info['vod_time']),date('m',$info['vod_time']),date('d',$info['vod_time']),$param['sid'],$param['nid']]);
            break;
        case 'manga/play':
            $replace_to = [
                $info['manga_id'],$info['manga_en'],'',
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? ''),
            ];
            if(($config['view']['manga_play'] ?? 0) >= 2){
                $path = ($config['path']['manga_play'] ?? '');
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                $replace_to[] = md5($info['manga_id']);
                if(($config['view']['manga_play'] ?? 0) == 2){
                    $path.= '.'.($config['path']['suffix'] ?? '');
                    $path .= '?'.$info['manga_id'].'-'.$param['sid'].'-'.$param['nid'];
                }
                elseif(($config['view']['manga_play'] ?? 0) == 3){
                    $path .= ($config['path']['page_sp'] ?? '').$param['sid'].($config['path']['page_sp'] ?? '').$param['nid'];
                }
            }else{
                switch($config['rewrite']['manga_id'])
                {
                    case 1:
                        $id = $info['manga_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['manga_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['manga_id'];
                        break;
                }
                $url = url($model,['id'=>$id,'sid'=>$param['sid'],'nid'=>$param['nid']]);
            }
            $replace_to = array_merge($replace_to,[date('Y',$info['manga_time']),date('m',$info['manga_time']),date('d',$info['manga_time']),$param['sid'],$param['nid']]);
            break;
        case 'vod/down':
            $replace_to = [
                $info['vod_id'],$info['vod_en'],'',
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? '')
            ];
            if(($config['view']['vod_down'] ?? 0) >= 2){
                $path = $config['path' ]['vod_down'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                $replace_to[] = md5($info['vod_id']);
                if(($config['view']['vod_down'] ?? 0) ==2){
                    $path.= '.'. ($config['path']['suffix'] ?? '');
                    $path .= '?'.$info['vod_id'] . '-' . $param['sid'] . '-' . $param['nid'] ;
                }
                elseif(($config['view']['vod_down'] ?? 0) ==3){
                    $path .= ($config['path']['page_sp'] ?? '') . $param['sid'] . ($config['path']['page_sp'] ?? '') . $param['nid'] ;
                }
                elseif(($config['view']['vod_down'] ?? 0) ==4){
                    $path .= ($config['path']['page_sp'] ?? '') .''. $param['sid'] . ($config['path']['page_sp'] ?? '') . '1';
                    $path.= '.'. ($config['path']['suffix'] ?? '');
                    $path .= '?'.$info['vod_id'] . '-' . $param['sid'] . '-' . $param['nid'] ;
                }
            }
            else{
                switch($config['rewrite']['vod_id'])
                {
                    case 1:
                        $id = $info['vod_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['vod_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['vod_id'];
                        break;
                }
                $url = url($model,['id'=>$id,'sid'=>$param['sid'],'nid'=>$param['nid']]);
            }
            $replace_to = array_merge($replace_to,[date('Y',$info['vod_time']),date('m',$info['vod_time']),date('d',$info['vod_time']),$param['sid'],$param['nid']]);
            break;
        case 'vod/role':
            $replace_to = [$info['vod_id'],$info['vod_en'],'',
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? '')
            ];
            if(($config['view']['vod_role'] ?? 0) == 2){
                $path = $config['path' ]['vod_role'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }   
                $replace_to[] = md5($info['vod_id']);
            }
            else{
                switch($config['rewrite']['vod_id'])
                {
                    case 1:
                        $id = $info['vod_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['vod_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['vod_id'];
                        break;
                }
                $url = url($model,['id'=>$id]);
            }
            $replace_to = array_merge($replace_to,[date('Y',$info['vod_time']),date('m',$info['vod_time']),date('d',$info['vod_time'])]);
            break;
        case 'vod/plot':
            $replace_to = [
                $info['vod_id'],$info['vod_en'],$param['page'],
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? '')
            ];
            if(($config['view']['vod_plot'] ?? 0) == 2){
                $path = $config['path' ]['vod_plot'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                $replace_to[] = md5($info['vod_id']);
                if($param['page']!=''){
                    $path .= $page_sp . $param['page'];
                }
            }
            else{
                switch($config['rewrite']['vod_id'])
                {
                    case 1:
                        $id = $info['vod_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['vod_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['vod_id'];
                        break;
                }
                $url = url($model,['id'=>$id,'page'=>($param['page'] ?? 1)]);
            }
            $replace_to = array_merge($replace_to,[date('Y',$info['vod_time']),date('m',$info['vod_time']),date('d',$info['vod_time'])]);
            break;
        case 'art/type':
            $replace_to = [$info['type_id'],$info['type_en'],$param['page'],
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? ''),
            ];
            if(($config['view']['art_type'] ?? 0) == 2){
                $path = ($config['path']['art_type'] ?? '');
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if(strpos($path,'{md5}')!==false){
                    $replace_to[] = md5($info['type_id']);
                }
                if($param['page']!=''){
                    $path .= $page_sp . $param['page'];
                }
            }
            else{
                switch($config['rewrite']['type_id'])
                {
                    case 1:
                        $id = $info['type_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['type_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['type_id'];
                        break;
                }
                $url = url($model,['id'=>$id,'page'=>($param['page'] ?? 1)]);
            }
            break;
        case 'art/detail':
            $replace_to = [
                $info['art_id'],$info['art_en'],'',
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? '')
            ];
            if(($config['view']['art_detail'] ?? 0) == 2){
                $path = $config['path' ]['art_detail'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                $replace_to[] = md5($info['art_id']);
                if($param['page']>1 || $param['page'] =='PAGELINK'){
                    $path .= $page_sp . $param['page'];
                }
            }
            else{
                switch($config['rewrite']['art_id'])
                {
                    case 1:
                        $id = $info['art_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['art_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['art_id'];
                        break;
                }
                $url = url($model,['id'=>$id,'page'=>($param['page'] ?? 1)]);
            }
            $replace_to = array_merge($replace_to,[date('Y',$info['art_time']),date('m',$info['art_time']),date('d',$info['art_time'])]);
            break;
        case 'topic/index':
            if(($config['view']['topic_index'] ?? 0) == 2){
                $path = $config['path' ]['topic_index'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if($param['page']>1 || $param['page'] =='PAGELINK'){
                    $path .= $page_sp . $param['page'];
                }
            }
            else{
                $url = url($model,['page'=>($param['page'] ?? 1)]);
            }
            break;
        case 'topic/detail':
            $replace_to = [$info['topic_id'],$info['topic_en'],'','','','',''];
            if(($config['view']['topic_detail'] ?? 0) == 2){
                $path = $config['path' ]['topic_detail'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if(strpos($path,'{md5}')!==false){
                    $replace_to[] = md5($info['topic_id']);
                }
            }
            else{
                switch($config['rewrite']['topic_id'])
                {
                    case 1:
                        $id = $info['topic_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['topic_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['topic_id'];
                        break;
                }
                $url = url($model,['id'=>$id]);
            }
            break;
        case 'actor/index':
            if(($config['view']['actor_index'] ?? 0) == 2){
                $path = $config['path' ]['actor_index'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if($param['page']>1 || $param['page'] =='PAGELINK'){
                    $path .= $page_sp . $param['page'];
                }
            }
            else{
                $url = url($model,['page'=>($param['page'] ?? 1)]);
            }
            break;
        case 'actor/type':
            $replace_to = [$info['type_id'],$info['type_en'],$param['page'],
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? ''),
            ];
            if(($config['view']['actor_type'] ?? 0) == 2){
                $path = ($config['path']['actor_type'] ?? '');
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if(strpos($path,'{md5}')!==false){
                    $replace_to[] = md5($info['type_id']);
                }
                if($param['page']!=''){
                    $path .= $page_sp . $param['page'];
                }
            }
            else{
                switch($config['rewrite']['type_id'])
                {
                    case 1:
                        $id = $info['type_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['type_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['type_id'];
                        break;
                }
                $url = url($model,['id'=>$id,'page'=>($param['page'] ?? 1)]);
            }
            break;
        case 'actor/detail':
            $replace_to = [$info['actor_id'],$info['actor_en'],'','','','',''];
            if(($config['view']['actor_detail'] ?? 0) == 2){
                $path = $config['path' ]['actor_detail'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if(strpos($path,'{md5}')!==false){
                    $replace_to[] = md5($info['actor_id']);
                }
            }
            else{
                switch($config['rewrite']['actor_id'])
                {
                    case 1:
                        $id = $info['actor_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['actor_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['actor_id'];
                        break;
                }
                $url = url($model,['id'=>$id]);
            }
            break;
        case 'role/index':
            if(($config['view']['role_index'] ?? 0) == 2){
                $path = $config['path' ]['role_index'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if($param['page']>1 || $param['page'] =='PAGELINK'){
                    $path .= $page_sp . $param['page'];
                }
            }
            else{
                $url = url($model,['page'=>($param['page'] ?? 1)]);
            }
            break;
        case 'role/detail':
            $replace_to = [$info['role_id'],$info['actor_en'],'','','','',''];
            if(($config['view']['role_detail'] ?? 0) == 2){
                $path = $config['path' ]['role_detail'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if(strpos($path,'{md5}')!==false){
                    $replace_to[] = md5($info['role_id']);
                }
            }
            else{
                switch($config['rewrite']['role_id'])
                {
                    case 1:
                        $id = $info['role_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['role_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['role_id'];
                        break;
                }
                $url = url($model,['id'=>$id]);
            }
            break;
        case 'plot/index':
            if(($config['view']['plot_index'] ?? 0) == 2){
                $path = $config['path' ]['plot_index'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if($param['page']>1 || $param['page'] =='PAGELINK'){
                    $path .= $page_sp . $param['page'];
                }
            }
            else{
                $url = url($model,['page'=>($param['page'] ?? 1)]);
            }
            break;
        case 'plot/detail':
            $replace_to = [
                $info['vod_id'],$info['vod_en'],'',
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? '')
            ];
            if(($config['view']['plot_detail'] ?? 0) == 2){
                $path = $config['path' ]['plot_detail'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if(strpos($path,'{md5}')!==false){
                    $replace_to[] = md5($info['vod_id']);
                }
                if($param['page']>1 || $param['page'] =='PAGELINK'){
                    $path .= $page_sp . $param['page'];
                }
            }
            else{
                switch($config['rewrite']['vod_id'])
                {
                    case 1:
                        $id = $info['vod_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['vod_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['vod_id'];
                        break;
                }
                $url = url($model,['id'=>$id,'page'=>($param['page'] ?? 1)]);
            }
            $replace_to = array_merge($replace_to,[date('Y',$info['vod_time']),date('m',$info['vod_time']),date('d',$info['vod_time'])]);
            break;
        case 'website/index':
            if(($config['view']['website_index'] ?? 0) == 2){
                $path = $config['path' ]['website_index'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if($param['page']>1 || $param['page'] =='PAGELINK'){
                    $path .= $page_sp . $param['page'];
                }
            }
            else{
                $url = url($model,['page'=>($param['page'] ?? 1)]);
            }
            break;
        case 'website/type':
            $replace_to = [$info['type_id'],$info['type_en'],$param['page'],
                $info['type_id'],($info['type']['type_en'] ?? ''),($info['type_1']['type_id'] ?? ''),($info['type_1']['type_en'] ?? ''),
            ];
            if(($config['view']['website_type'] ?? 0) == 2){
                $path = ($config['path']['website_type'] ?? '');
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if(strpos($path,'{md5}')!==false){
                    $replace_to[] = md5($info['type_id']);
                }
                if($param['page']!=''){
                    $path .= $page_sp . $param['page'];
                }
            }
            else{
                switch($config['rewrite']['type_id'])
                {
                    case 1:
                        $id = $info['type_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['type_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['type_id'];
                        break;
                }
                $url = url($model,['id'=>$id,'page'=>($param['page'] ?? 1)]);
            }
            break;
        case 'website/detail':
            $replace_to = [$info['website_id'],$info['website_en'],'','','','',''];
            if(($config['view']['website_detail'] ?? 0) == 2){
                $path = $config['path' ]['website_detail'];
                if(substr($path,strlen($path)-1,1)=='/'){
                    $path .= 'index';
                }
                if(strpos($path,'{md5}')!==false){
                    $replace_to[] = md5($info['website_id']);
                }
            }
            else{
                switch($config['rewrite']['website_id'])
                {
                    case 1:
                        $id = $info['website_en'];
                        break;
                    case 2:
                        $id = mac_alphaID($info['website_id'],false,$config['rewrite']['encode_len'],$config['rewrite']['encode_key']);
                        break;
                    default:
                        $id = $info['website_id'];
                        break;
                }
                $url = url($model,['id'=>$id]);
            }
            break;
        case 'gbook/index':
            $url = url($model,['page'=>($param['page'] ?? 1)]);
            break;
        case 'comment/index':
            $url = url($model,['page'=>($param['page'] ?? 1)]);
            break;
        default:
            $url = url($model,mac_url_vars($param));
            break;
    }
    if(!empty($path)) {
        $path = str_replace($replace_from, $replace_to, $path);
        $path = str_replace('//', '/', $path);
        $delimiter = false;
        if(substr($path,strlen($path)-6) =='/index'){
            $delimiter = true;
            $path = substr($path,0, strlen($path)-5);
        }

        if($delimiter==false && strpos($path,'.')===false){
            $path.= '.'. ($config['path']['suffix'] ?? '');
        }
        $url = $path;
        if(substr($path,0,1)!='/') {
            $url = MAC_PATH . $path;
        }
    }
    else{
        if(ENTRANCE!='index'){
            $sto= MAC_PATH ;
            if($config['rewrite']['status']==0){
                $sto = MAC_PATH .'index.php/';
            }
            if(!empty(IN_FILE)){
                $url = str_replace(IN_FILE.'/',$sto,$url);
                $url = str_replace(ENTRANCE.'/','',$url);
            }
        }
        elseif($config['rewrite']['status']==0 && strpos($url,'index.php')===false){
            if(MAC_PATH !='/'){
                $url = str_replace(MAC_PATH,'/',$url);
            }
            $url = MAC_PATH. 'index.php' . $url;
        }
        elseif($config['rewrite']['status']==1 && strpos($url,'index.php')!==false){
            $url = str_replace('index.php/','',$url);
        }

        if($config['rewrite']['suffix_hide']==1){
            $url = str_replace('.html','/',$url);
            if(strpos($model,'/show')===false && strpos($model,'/search')===false) {
                $url = str_replace(['-/','_/','-.','_.'],'/',$url);
            }
        }
        else{
            if(strpos($model,'search')===false && strpos($model,'show')===false ) {
                $url = str_replace(['-.', '/.'], '.', $url);
            }
        }
    }

    // 在静态生成模式下，对生成的URL进行后处理，去掉admin/index前缀
    if($is_static_mode && !empty($url)) {
        if(strpos($url, '/index.php/') === 0) {
            $url = preg_replace('/\/index\.php\/[^\/]+\.php\/admin\-/', '/index.php/', $url);
            $url = str_replace('/admin-', '/', $url);
        }
        if(strpos($url, 'admin-') !== false) {
            $url = str_replace('admin-', '', $url);
        }
        if(strpos($url, 'index-') !== false) {
            $url = str_replace('index-', '', $url);
        }
    }

    return $url;
}
function mac_url_page($url,$num)
{
    if(!is_string($url)){ $url = (string)($url ?? ''); }
    $url = str_replace(MAC_PAGE_SP.'PAGELINK',($num>1 ? MAC_PAGE_SP.$num : ''),$url);
    $url = str_replace('PAGELINK',$num,$url);
    return $url;
}

function mac_url_create($str,$type='actor',$flag='vod',$ac='search',$sp='&nbsp;')
{
    if(!$str){
        return '未知';
    }
    $res = [];
    // 分割时，中文关键词允许空格分割，英文不用空格（英文名中间是空格分隔的问题）
    $base_finder = array(' / ', '/', '|', ',', '，', ',,');
    $str = str_replace($base_finder, ',', $str);
    $str = trim($str, ',');
    $arr = [];
    foreach (explode(',', $str) as $tag) {
        if (preg_match("/[\x{2E80}-\x{9FFF}]+/u", $tag) && str_contains($tag, ' ')) {
            foreach (explode(' ', $tag) as $tag_exp) {
                $arr[] = $tag_exp;
            }
        } else {
            $arr[] = $tag;
        }
    }
    foreach ($arr as $k => $v) {
        $res[$k] = '<a href="'.mac_url($flag.'/'.$ac,[$type=>$v]).'" target="_blank">'.$v.'</a>'.$sp;
    }
    return implode('',$res);
}

function mac_url_search($param=[],$flag='vod')
{
    return mac_url($flag.'/search',$param);
}

function mac_url_type($info,$param=[],$flag='type')
{
    if(empty($info) || !is_array($info)){ return ''; }
    $tab = 'vod';
    if(($info['type_mid'] ?? 0) == 1){

    }
    else if(($info['type_mid'] ?? 0) == 2) {
        $tab ='art';
    }
    else if(($info['type_mid'] ?? 0) == 8) {
        $tab ='actor';
    }
    else if(($info['type_mid'] ?? 0) == 11) {
        $tab ='website';
    }
    else if(($info['type_mid'] ?? 0) == 12) {
        if(empty($param['id'])){
            $param['id'] = $info['type_id'];
        }
        return mac_url('manga/'.$flag,$param,$info);
    }
    if(empty($param['id'])){
        $param['id'] = $info['type_id'];
    }

    return mac_url($tab.'/'.$flag,$param,$info);
}

function mac_url_topic_index($param=[])
{
    return mac_url('topic/index',['page'=>($param['page'] ?? 1)]);
}

function mac_url_topic_detail($info)
{
    return mac_url('topic/detail',[],$info);
}

function mac_url_role_index($param=[])
{
    return mac_url('role/index',['page'=>($param['page'] ?? 1)]);
}

function mac_url_role_detail($info)
{
    return mac_url('role/detail',[],$info);
}
function mac_url_actor_index($param=[])
{
    return mac_url('actor/index',['page'=>($param['page'] ?? 1)]);
}
function mac_url_actor_detail($info)
{
    return mac_url('actor/detail',[],$info);
}
function mac_url_actor_search($param)
{
    return mac_url('actor/search',$param);
}
function mac_url_plot_index($param=[])
{
    return mac_url('plot/index',['page'=>($param['page'] ?? 1)]);
}
function mac_url_plot_detail($info,$param=[])
{
    return mac_url('plot/detail',['page'=>($param['page'] ?? 1)],$info);
}
function mac_url_vod_plot($info,$param=[])
{
    return mac_url('vod/plot',$param,$info);
}
function mac_url_vod_role($info,$param=[])
{
    return mac_url('vod/role',$param,$info);
}
function mac_url_website_index($param=[])
{
    return mac_url('website/index',['page'=>($param['page'] ?? 1)]);
}
function mac_url_website_detail($info)
{
    return mac_url('website/detail',[],$info);
}
function mac_url_website_search($param)
{
    return mac_url('website/search',$param);
}
function mac_url_art_index($param=[])
{
    return mac_url('art/index',['page'=>($param['page'] ?? 1)]);
}
function mac_url_art_detail($info,$param=[])
{
    return mac_url('art/detail',['page'=>($param['page'] ?? 1)],$info);
}
function mac_url_art_search($param)
{
    return mac_url('art/search',$param);
}
function mac_url_vod_index($param=[])
{
    return mac_url('vod/index',['page'=>($param['page'] ?? 1)]);
}
function mac_url_vod_detail($info)
{
    return mac_url('vod/detail',[],$info);
}
function mac_url_manga_detail($info)
{
    return mac_url('manga/detail',[],$info);
}
function mac_url_manga_play($info,$param=[])
{
    if($param=='first'){
        if(empty($info['manga_page_list']) || !is_array($info['manga_page_list'])){
            return '';
        }
        $sid = intval(key($info['manga_page_list']));
        if(empty($info['manga_page_list'][$sid]['urls']) || !is_array($info['manga_page_list'][$sid]['urls'])){
            return '';
        }
        $nid = intval(key($info['manga_page_list'][$sid]['urls']));
        if($sid==0 || $nid==0){
            return '';
        }
        $param = [];
        $param['sid'] = $sid;
        $param['nid'] = $nid;
    }
    if(intval($param['sid'])<1){
        $param['sid'] = 1;
    }
    if(intval($param['nid'])<1){
        $param['nid'] = 1;
    }

    return mac_url('manga/play',['sid'=>$param['sid'],'nid'=>$param['nid']],$info);
}
function mac_url_manga_down($info,$param=[])
{
    if($param=='first'){
        if(empty($info['manga_page_list']) || !is_array($info['manga_page_list'])){
            return '';
        }
        $sid = intval(key($info['manga_page_list']));
        if(empty($info['manga_page_list'][$sid]['urls']) || !is_array($info['manga_page_list'][$sid]['urls'])){
            return '';
        }
        $nid = intval(key($info['manga_page_list'][$sid]['urls']));
        if($sid==0 || $nid==0){
            return '';
        }
        $param = [];
        $param['sid'] = $sid;
        $param['nid'] = $nid;
    }

    if(intval($param['sid'])<1){
        $param['sid'] = 1;
    }
    if(intval($param['nid'])<1){
        $param['nid'] = 1;
    }

    return mac_url('manga/down',['sid'=>$param['sid'],'nid'=>$param['nid']],$info);
}
function mac_url_vod_search($param)
{
    return mac_url('vod/search',$param);
}
function mac_url_vod_play($info,$param=[])
{
    if($param=='first'){
        $sid = intval(key($info['vod_play_list']));
        $nid = intval(key($info['vod_play_list'][$sid]['urls']));
        if($sid==0 || $nid==0){
            return '';
        }
        $param=[];
        $param['sid'] = $sid;
        $param['nid'] = $nid;
    }
    if(intval($param['sid'])<1){
        $param['sid'] =1;
    }
    if(intval($param['nid'])<1){
        $param['nid']=1;
    }

    return mac_url('vod/play',['sid'=>$param['sid'],'nid'=>$param['nid']],$info);
}

function mac_url_vod_down($info,$param=[])
{
    if($param=='first'){
        $sid = intval(key($info['vod_down_list']));
        $nid = intval(key($info['vod_down_list'][$sid]['urls']));
        if($sid==0 || $nid==0){
            return '';
        }
        $param=[];
        $param['sid'] = $sid;
        $param['nid'] = $nid;
    }

    if(intval($param['sid'])<1){
        $param['sid'] =1;
    }
    if(intval($param['nid'])<1){
        $param['nid']=1;
    }

    return mac_url('vod/down',['sid'=>$param['sid'],'nid'=>$param['nid']],$info);
}



function mac_label_website_detail($param)
{
    $where = [];
    if($GLOBALS['config']['rewrite']['website_id']==1){
        $where['website_en'] = $param['id'];
    }
    else{
        if($GLOBALS['config']['rewrite']['website_id']==2) {
            $param['id'] = mac_alphaID($param['id'], true, $GLOBALS['config']['rewrite']['encode_len'],$GLOBALS['config']['rewrite']['encode_key'] );
        }
        $where['website_id'] = $param['id'];
    }
    $where['website_status'] = 1;
    $res = (new \app\common\model\Website())->infoData($where,'*',1);

    $GLOBALS['type_id'] = $res['info']['type_id'];
    $GLOBALS['type_pid'] = $res['info']['type']['type_pid'];
    return $res;
}
function mac_label_actor_detail($param)
{
    $where = [];
    if($GLOBALS['config']['rewrite']['actor_id']==1){
        $where['actor_en'] = $param['id'];
    }
    else{
        if($GLOBALS['config']['rewrite']['actor_id']==2) {
            $param['id'] = mac_alphaID($param['id'], true, $GLOBALS['config']['rewrite']['encode_len'],$GLOBALS['config']['rewrite']['encode_key'] );
        }
        $where['actor_id'] = $param['id'];
    }
    $where['actor_status'] = 1;
    $res = (new \app\common\model\Actor())->infoData($where,'*',1);

    $GLOBALS['type_id'] = $res['info']['type_id'];
    $GLOBALS['type_pid'] = $res['info']['type']['type_pid'];
    return $res;
}
function mac_label_role_detail($param)
{
    $where = [];
    if($GLOBALS['config']['rewrite']['role_id']==1){
        $where['role_en'] = $param['id'];
    }
    else{
        if($GLOBALS['config']['rewrite']['role_id']==2) {
            $param['id'] = mac_alphaID($param['id'], true, $GLOBALS['config']['rewrite']['encode_len'],$GLOBALS['config']['rewrite']['encode_key'] );
        }
        $where['role_id'] = $param['id'];
    }
    $where['role_status'] = 1;
    $res = (new \app\common\model\Role())->infoData($where,'*',1);

    // https://github.com/magicblack/maccms10/issues/960
    $GLOBALS['type_id'] = isset($res['info']['data']['type_id']) ? $res['info']['data']['type_id'] : 0;
    $GLOBALS['type_pid'] = isset($res['info']['data']['type_id_1']) ? $res['info']['data']['type_id_1'] : 0;
    return $res;
}
function mac_label_topic_detail($param)
{
    $where = [];
    if($GLOBALS['config']['rewrite']['topic_id']==1){
        $where['topic_en'] = $param['id'];
    }
    else{
        if($GLOBALS['config']['rewrite']['topic_id']==2) {
            $param['id'] = mac_alphaID($param['id'], true, $GLOBALS['config']['rewrite']['encode_len'],$GLOBALS['config']['rewrite']['encode_key'] );
        }
        $where['topic_id'] = $param['id'];
    }
    $where['topic_status'] = 1;
    $res = (new \app\common\model\Topic())->infoData($where,'*',1);
    return $res;
}
function mac_label_art_detail($param)
{
    $where = [];
    if($GLOBALS['config']['rewrite']['art_id']==1){
        $where['art_en'] = $param['id'];
    }
    else{
        if($GLOBALS['config']['rewrite']['art_id']==2) {
            $param['id'] = mac_alphaID($param['id'], true, $GLOBALS['config']['rewrite']['encode_len'],$GLOBALS['config']['rewrite']['encode_key'] );
        }
        $where['art_id'] = $param['id'];
    }
    $where['art_status'] = 1;
    $res = (new \app\common\model\Art())->infoData($where,'*',1);
    if($res['code'] ==1){
        if($param['page']>$res['info']['art_page_total']){ $param['page'] = $res['info']['art_page_total']; }
    }
    $GLOBALS['type_id'] = $res['info']['type_id'];
    $GLOBALS['type_pid'] = $res['info']['type']['type_pid'];

    return $res;
}
function mac_label_manga_detail($param)
{
    $where = [];
    if($GLOBALS['config']['rewrite']['manga_id']==1){
        $where['manga_en'] = $param['id'];
    }
    else{
        if($GLOBALS['config']['rewrite']['manga_id']==2) {
            $param['id'] = mac_alphaID($param['id'], true, $GLOBALS['config']['rewrite']['encode_len'],$GLOBALS['config']['rewrite']['encode_key'] );
        }
        $where['manga_id'] = $param['id'];
    }
    $where['manga_status'] = 1;
    $res = (new \app\common\model\Manga())->infoData($where,'*',1);
    if($res['code'] != 1){
        return $res;
    }
    $GLOBALS['type_id'] = $res['info']['type_id'];
    $GLOBALS['type_pid'] = $res['info']['type']['type_pid'];

    return $res;
}
function mac_label_vod_detail($param)
{
    $where = [];
    if($GLOBALS['config']['rewrite']['vod_id']==1){
        $where['vod_en'] = $param['id'];
    }
    else{
        if($GLOBALS['config']['rewrite']['vod_id']==2) {
            $param['id'] = mac_alphaID($param['id'], true, $GLOBALS['config']['rewrite']['encode_len'],$GLOBALS['config']['rewrite']['encode_key'] );
        }
        $where['vod_id'] = $param['id'];
    }
    $where['vod_status'] = 1;
    $res = (new \app\common\model\Vod())->infoData($where,'*',1);

    $GLOBALS['type_id'] = $res['info']['type_id'];
    $GLOBALS['type_pid'] = $res['info']['type']['type_pid'];
    return $res;
}

function mac_label_vod_role($param)
{
    $where = [];
    $where['role_rid'] = $param['rid'];
    $where['role_status'] = 1;
    $order='role_sort desc,role_id desc';
    $res = (new \app\common\model\Role())->listData($where,$order,1,999,0,'*',0,0);
    return $res;
}

function mac_label_type($param, $type_id_specified)
{
    if ($type_id_specified > 0) {
        $type_id = $type_id_specified;
    } else {
        if($GLOBALS['config']['rewrite']['type_id']==1){

        }
        else{
            if($GLOBALS['config']['rewrite']['type_id']==2) {
                $param['id'] = mac_alphaID($param['id'], true, $GLOBALS['config']['rewrite']['encode_len'],$GLOBALS['config']['rewrite']['encode_key'] );
            }
        }
        $type_id = $param['id'];
    }
    $type_info = (new \app\common\model\Type())->getCacheInfo($type_id);
    if (empty($type_info)) {
        return null;
    }

    $GLOBALS['type_id'] = $type_info['type_id'];
    $GLOBALS['type_pid'] = $type_info['type_pid'];

    $parent = (new \app\common\model\Type())->getCacheInfo($type_info['type_pid']);
    $type_info['parent'] = $parent;
    return $type_info;
}

function mac_data_count($tid=0,$range='all',$flag='vod')
{
    if(!in_array($flag,['vod','art','actor','role','topic','website'])) {
        $flag='vod';
    }
    if(!in_array($range,['all','today','min'])){
        $range='all';
    }

    $data = (new \app\common\model\Extend())->dataCount();
    $key = 'type_'.$range.'_'.$tid;
    if($tid>0 && in_array($flag,['vod','art']) ){

    }
    else{
        $key = $flag.'_'.$range;
    }
    return intval($data[$key]);
}

function mac_get_popedom_filter($group_type_list, $type_list = [])
{
    if (empty($type_list)) {
        $type_list = (new \app\common\model\Type())->getCache('type_list');
    }
    $type_keys = array_keys($type_list);
    $group_type_list = array_map('trim', explode(',', trim($group_type_list, ',')));
    $group_keys = [];
    foreach ($group_type_list as $group_type) {
        $group_keys = array_merge($group_keys, explode(',', $group_type));
    }
    $group_keys = get_array_unique_id_list($group_keys);
    $cha_keys = array_diff($type_keys, $group_keys);
    return implode(',', $cha_keys);
}

/**
 * VIP 专属分类 = VIP 有播放/阅读权限 - (游客 ∪ 默认会员 有播放/阅读权限)
 * 仅针对播放页权限 (popedom 3)，Vod/Art/Manga 统一用 popedom 3
 * 返回 type_id 数组
 */
function mac_get_vip_exclusive_type_ids()
{
    $cache_flag = $GLOBALS['config']['app']['cache_flag'] ?? 'maccms';
    $key = $cache_flag . '_vip_exclusive_type_ids';
    $list = \think\facade\Cache::get($key);
    if (is_array($list)) {
        return $list;
    }
    $group_list = (new \app\common\model\Group())->getCache('group_list');
    $type_list = (new \app\common\model\Type())->getCache('type_list');
    if (empty($group_list) || empty($type_list)) {
        return [];
    }
    $guest_ids = [];
    $member_ids = [];
    $vip_ids = [];
    $content_mids = [1 => 1, 2 => 1, 12 => 1]; // Vod, Art, Manga 有播放/阅读页
    foreach ($type_list as $type_id => $type_info) {
        $mid = $type_info['type_mid'] ?? 0;
        if (empty($content_mids[$mid])) {
            continue;
        }
        foreach ($group_list as $gid => $group) {
            $has = strpos(',' . ($group['group_type'] ?? ''), ',' . $type_id . ',') !== false
                && !empty($group['group_popedom'][$type_id][3]);
            if (!$has) {
                continue;
            }
            if ($gid == 1) {
                $guest_ids[$type_id] = 1;
            } elseif ($gid == 2) {
                $member_ids[$type_id] = 1;
            } else {
                $vip_ids[$type_id] = 1;
            }
        }
    }
    $ab = $guest_ids + $member_ids;
    $exclusive = array_diff_key($vip_ids, $ab);
    $list = array_keys($exclusive);
    \think\facade\Cache::set($key, $list);
    return $list;
}

/**
 * 为列表每行补充 type_is_vip_exclusive，供前台角标（SSR 模板 / CSR MacHomeCardRender）与接口 JSON 一致
 *
 * @param array $list 引用传递，行内需含 type_id（视频/文章/漫画分类 ID）
 */
function mac_append_type_is_vip_exclusive_for_rows(array &$list)
{
    if (empty($list)) {
        return;
    }
    $vip_exclusive = mac_get_vip_exclusive_type_ids();
    foreach ($list as &$row) {
        $row['type_is_vip_exclusive'] = in_array((int)($row['type_id'] ?? 0), $vip_exclusive, true) ? 1 : 0;
    }
    unset($row);
}

/**
 * 文章/漫画「阅读」实际扣费积分：与前台权限、user/ajax_buy_popedom 一致。
 * 「每数据」用 *_points；「每页/每话」优先 *_points_detail，为 0 时回退整本/整条 *_points（常见只填了 art_points 的情况）。
 *
 * @param string $pre art|manga
 * @param array  $info 详情行
 * @return int
 */
function mac_content_read_points_amount($pre, array $info)
{
    $pre = strtolower((string)$pre);
    if (!in_array($pre, ['art', 'manga'], true)) {
        return 0;
    }
    $typeKey = $pre . '_points_type';
    $ptype = isset($GLOBALS['config']['user'][$typeKey]) ? (string)$GLOBALS['config']['user'][$typeKey] : '0';
    if ($ptype === '1') {
        return (int)($info[$pre . '_points'] ?? 0);
    }
    $detail = (int)($info[$pre . '_points_detail'] ?? 0);
    if ($detail > 0) {
        return $detail;
    }

    return (int)($info[$pre . '_points'] ?? 0);
}

/**
 * 与 model Vod::listCacheData 中按分类筛选逻辑一致：自身 type_id + 直接子分类的 type_id。
 * 用于把 (type_id=X OR type_id_1=X) 改为 type_id IN (...)，便于走 type_id 索引、避免 OR 低效扫描。
 *
 * @param int $typeId 分类 ID
 * @return int[]
 */
function mac_vod_type_filter_ids_for_list($typeId)
{
    $typeId = (int)$typeId;
    if ($typeId <= 0) {
        return [];
    }
    $type_list = (new \app\common\model\Type())->getCache('type_list');
    if (empty($type_list) || !is_array($type_list)) {
        return [$typeId];
    }
    $tmp_arr = explode(',', (string)$typeId);
    $ids = [];
    foreach ($type_list as $v2) {
        if (!is_array($v2)) {
            continue;
        }
        if (in_array($v2['type_id'] . '', $tmp_arr) || in_array($v2['type_pid'] . '', $tmp_arr)) {
            $ids[] = (int)$v2['type_id'];
        }
    }
    $ids = array_values(array_unique(array_filter($ids)));
    return !empty($ids) ? $ids : [$typeId];
}

function reset_html_filename($htmlfile)
{
    $htmlpath = './';
    if(substr($htmlfile,strlen($htmlfile)-1,1)=='/'){
        $htmlfile .= 'index';
    }

    if(strpos($htmlfile,'.') ===false){
        $htmlfile .= '.'. $GLOBALS['config']['path']['suffix'];
    }

    if(strpos($htmlfile,'?')!==false){
        $htmlfile = substr($htmlfile,0,strpos($htmlfile,'?'));
    }
    $htmlfile   =   $htmlpath.$htmlfile;
    $htmlfile = str_replace('//','/', $htmlfile);

    if(MAC_PATH !='/'){
        $htmlfile = str_replace('.'.MAC_PATH, './', $htmlfile);
    }

    $htmlfile = str_replace('//','/', $htmlfile);
    return $htmlfile;
}

function mac_unicode_encode($str, $encoding = 'UTF-8', $prefix = '&#', $postfix = ';') {
    $str = iconv($encoding, 'UCS-2', $str);
    $arrstr = str_split($str, 2);
    $unistr = '';
    for($i = 0, $len = count($arrstr); $i < $len; $i++) {
        $dec = hexdec(bin2hex($arrstr[$i]));
        $unistr .= $prefix . $dec . $postfix;
    }
    return $unistr;
}
function mac_unicode_decode($unistr, $encoding = 'UTF-8', $prefix = '&#', $postfix = ';') {
    $arruni = explode($prefix, $unistr);
    $unistr = '';
    for($i = 1, $len = count($arruni); $i < $len; $i++) {
        if (strlen($postfix) > 0) {
            $arruni[$i] = substr($arruni[$i], 0, strlen($arruni[$i]) - strlen($postfix));
        }
        $temp = intval($arruni[$i]);
        $unistr .= ($temp < 256) ? chr(0) . chr($temp) : chr($temp / 256) . chr($temp % 256);
    }
    return iconv('UCS-2', $encoding, $unistr);
}

function mac_escape_param($param)
{
    if(is_array($param)){
        foreach($param as $k=>$v){
            if(!is_numeric($v) && !empty($v)){

                if($GLOBALS['config']['app']['wall_filter'] ==1){
                    $v = mac_unicode_encode($v);
                }
                elseif($GLOBALS['config']['app']['wall_filter'] ==2){
                    $v = '';
                }
                $param[$k] = $v;
            }
        }
    }
    else{
        if(!is_numeric($param) && !empty($param)){
            if($GLOBALS['config']['app']['wall_filter'] ==1){
                $param = mac_unicode_encode($param);
            }
            elseif($GLOBALS['config']['app']['wall_filter'] ==2){
                $param = '';
            }
        }
    }
    return $param;
}

function mac_search_len_check($param)
{
    $psm = array('wd','tag','class','letter','name','state','level','area','lang','version','actor','director','starsign','blood');
    foreach($psm as $v){
        if(mb_strlen($param[$v]) > $GLOBALS['config']['app']['search_len']){
            $param[$v] = mac_substring($param[$v],$GLOBALS['config']['app']['search_len']);
        }
    }
    return $param;
}

function mac_no_cahche()
{
    @header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
    @header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . 'GMT');
    @header('Cache-Control: no-cache, must-revalidate');
    @header('Pragma: no-cache');
}

function mac_filter_tags($rs)
{
    $rex = array('{:','<script','<iframe','<frameset','<object','onerror');
    if(is_array($rs)){
        foreach($rs as $k2=>$v2){
            if(!is_numeric($v2)){
                $rs[$k2] = str_ireplace($rex,'*',$rs[$k2]);
            }
        }
    }
    else{
        if(!is_numeric($rs)){
            $rs = str_ireplace($rex,'*',$rs);
        }
    }
    return $rs;
}

if (!function_exists('is_really_writable')) {

    /**
     * 判断文件或文件夹是否可写
     * @param string $file 文件或目录
     * @return    bool
     */
    function is_really_writable($file)
    {
        if (DIRECTORY_SEPARATOR === '/') {
            return is_writable($file);
        }
        if (is_dir($file)) {
            $file = rtrim($file, '/') . '/' . md5(mt_rand());
            if (($fp = @fopen($file, 'ab')) === false) {
                return false;
            }
            fclose($fp);
            @chmod($file, 0777);
            @unlink($file);
            return true;
        } elseif (!is_file($file) or ($fp = @fopen($file, 'ab')) === false) {
            return false;
        }
        fclose($fp);
        return true;
    }
}
if (!function_exists('rmdirs')) {

    /**
     * 删除文件夹
     * @param string $dirname  目录
     * @param bool   $withself 是否删除自身
     * @return boolean
     */
    function rmdirs($dirname, $withself = true)
    {
        if (!is_dir($dirname)) {
            return false;
        }
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dirname, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($files as $fileinfo) {
            $todo = ($fileinfo->isDir() ? 'rmdir' : 'unlink');
            $todo($fileinfo->getRealPath());
        }
        if ($withself) {
            @rmdir($dirname);
        }
        return true;
    }
}
if (!function_exists('copydirs')) {

    /**
     * 复制文件夹
     * @param string $source 源文件夹
     * @param string $dest   目标文件夹
     */
    function copydirs($source, $dest)
    {
        if (!is_dir($dest)) {
            mkdir($dest, 0755, true);
        }
        foreach (
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            ) as $item
        ) {
            if ($item->isDir()) {
                $sontDir = $dest . DS . $iterator->getSubPathName();
                if (!is_dir($sontDir)) {
                    mkdir($sontDir, 0755, true);
                }
            } else {
                copy($item, $dest . DS . $iterator->getSubPathName());
            }
        }
    }
}

function mac_strip_tags($string) {
    $pattern = '/&([a-zA-Z0-9#]+);/';
    
    $string = preg_replace_callback($pattern, function($matches) {
        if ($matches[0] === '&lt;') {
            return '<';
        }
        if ($matches[0] === '&gt;') {
            return '>';
        }
        if ($matches[0] === '&nbsp;') {
            return ' ';
        }
        if ($matches[0] === '&amp;') {
            return '&';
        }
        return $matches[0];
    }, $string);
    
    return strip_tags($string);
}

// ========= TP8 global helpers — model() is permanent for dynamic model loading =========
if (!function_exists('model')) {
    function model(string $name, string $layer = 'model'): object {
        $class = '\\app\\common\\' . $layer . '\\' . ucfirst($name);
        return new $class();
    }
}
if (!function_exists('input')) {
    /** @deprecated 迁移期 shim，用 request()->param/post/get() 替代 */
    function input(string $key = '', $default = null, string $filter = '') {
        $filter = $filter ?: null;
        if ($key === '') {
            return request()->param('', $default, $filter);
        }
        $dot = strpos($key, '.');
        if ($dot !== false) {
            $type = substr($key, 0, $dot);
            $name = substr($key, $dot + 1);
            switch ($type) {
                case 'post':    return request()->post($name, $default, $filter);
                case 'get':     return request()->get($name, $default, $filter);
                case 'put':     return request()->put($name, $default, $filter);
                case 'delete':  return request()->delete($name, $default, $filter);
                case 'param':   return request()->param($name, $default, $filter);
                case 'request': return request()->param($name, $default, $filter);
                case 'server':  return request()->server($name, $default);
                case 'session': return session($name);
                case 'cookie':  return request()->cookie($name, $default, $filter);
                case 'file':    return request()->file($name);
                case 'route':   return request()->route($name, $default);
                case 'env':     return env($name, $default);
            }
        }
        return request()->param($key, $default, $filter);
    }
}
if (!function_exists('url')) {
    function url(string $url = '', iterable $vars = [], bool $suffix = true, bool $domain = false): string {
        // iterable:兼容 SafeParam 等 ArrayObject(后台 {$param} 既回显又建链),转纯数组传入
        $vars = is_array($vars) ? $vars : iterator_to_array($vars);
        return (string) \think\facade\Route::buildUrl($url, $vars)->suffix($suffix)->domain($domain);
    }
}
if (!function_exists('mac_token')) {
    /**
     * 表单 CSRF token:写入并返回 Session('__token__'),供 CsrfGuard 校验。
     * TP8 的 token()/Request::buildToken() 依赖未绑定到 request 的 session(本项目未注册
     * SessionInit),会「Call to a member function set() on null」;此处直接用 Session facade。
     * 同一请求内复用,保证一页多表单 token 一致且均有效。
     */
    function mac_token(): string {
        $token = (string) \think\facade\Session::get('__token__');
        if ($token === '') {
            $token = md5(uniqid('', true));
            \think\facade\Session::set('__token__', $token);
        }
        return $token;
    }
}
if (!function_exists('mac_validate')) {
    function mac_validate(string $name): \think\Validate
    {
        $class = 'app\\common\\validate\\' . $name;
        if (!class_exists($class)) {
            throw new \RuntimeException("Validate class not found: {$class}");
        }
        return new $class();
    }
}
if (!function_exists('mac_help_url')) {
    function mac_help_url(): string {
        // 与 mac_rep_url() 同约定：本项目固定入口用 /index.php/<route>.html。
        // 该形式在伪静态站同样可达（index.php 入口恒在），而裸 '/help' 在非伪静态站
        // （本项目默认的 /index.php/xxx.html 方案）会 404。help_path 由后台可配。
        $path = \app\common\model\HelpCfg::get('help_path', 'help') ?: 'help';
        return '/index.php/' . ltrim($path, '/') . '.html';
    }
}
if (!function_exists('mac_rep_url')) {
    /**
     * 替换助手的前台地址。主题与后台「查看前台页面」都从这里取，只有一个来源。
     *
     * 路由：application/index/route/web.php:68  Route::any('macrep', 'rep/index')
     *
     * 为什么是写死的 '/index.php/macrep.html'，而不是用某个生成器 —— 两条路都试过，
     * 都不对：
     *
     *   框架的 url()      产出 /rep/index.html。本站【没配 nginx 伪静态】
     *                    （/www/server/panel/vhost/rewrite/ 下是空的），
     *                    nginx 找不到这个文件就直接 404，根本不转交 PHP。实测：
     *                        /macrep.html               404
     *                        /rep/index.html            404
     *                        /index.php/macrep.html     200  ←
     *                        /index.php/rep/index.html  200
     *                    前台其余链接同理，nginx 日志里全是 /index.php/voddetail/...。
     *
     *   maccms 的 mac_url()  它靠 switch($model) 匹配 29 个固定模型名
     *                    （index/index、vod/detail、art/show …，见 common.php:2897），
     *                    里面【没有 rep/index】。传进去会穿过整个 switch 返回空串，
     *                    途中还会用到 ENTRANCE 常量 —— 该常量只有 web 入口文件
     *                    （index.php:18 等）才定义，CLI 下会直接抛
     *                    "Undefined constant ENTRANCE"。给它传一个它不认识的模型名，
     *                    本身就是误用。
     *
     * 所以这里就诚实地返回这个部署下唯一能打开的形式。哪天补了伪静态，
     * 改这一处即可（并把上面这段实测记录一起更新）。
     */
    function mac_rep_url(): string {
        return '/index.php/macrep.html';
    }
}
if (!function_exists('mac_rep_last_update')) {
    function mac_rep_last_update(): string {
        $t = \think\facade\Db::name('rep')
            ->where('rep_applied', 1)
            ->max('rep_applied_time');
        if (!$t) return '';
        return ' ' . date('Y/m/d', (int)$t);
    }
}
if (!function_exists('mac_rep_notice')) {
    /**
     * 给主题用的「最近替换提醒」整句文案。
     *
     * mac_rep_last_update() 只给日期，主题想显示
     *     26-08-26，播放器替换，请站长替换
     * 这类带类型的提示还得自己再查一次库。这里一次给全。
     *
     * 取的是【最近一条对外可见(rep_status=1)的记录】，不要求 rep_applied ——
     * 因为这个提示的受众是【下游采集站的站长】：本站刚改了播放域名、图片域名之后，
     * 他们需要在自己库里同步替换，所以刚发布就该提醒，而不是等本站执行完。
     *
     * @param string $fmt 日期格式，默认 y-m-d（26-08-26 这种两位年份）
     * @return string 无记录时返回空串，主题里可直接 {if} 判空
     */
    function mac_rep_notice(string $fmt = 'y-m-d'): string {
        $row = \think\facade\Db::name('rep')
            ->where('rep_status', 1)
            ->order('rep_create_time', 'desc')
            ->find();
        if (!$row) {
            return '';
        }
        $type = trim((string)($row['rep_type'] ?? ''));
        $date = date($fmt, (int)($row['rep_create_time'] ?? 0));
        return $type === '' ? $date : ($date . '，' . $type . '，请站长替换');
    }
}
if (!function_exists('mac_rep_count')) {
    /** 对外可见的替换记录条数。主题里用来决定要不要显示入口/红点。 */
    function mac_rep_count(): int {
        return (int)\think\facade\Db::name('rep')->where('rep_status', 1)->count();
    }
}
// ========= /TP8 global helpers =========

if (!function_exists('mac_ppvod_category_map')) {
    /**
     * 解析 PPVOD 分类映射配置。
     *
     * 后台里以每行 "转码机分类=栏目ID" 的形式维护，例如：
     *     01wumazhuanqu=1
     *     02madouchuanmei=2
     * 解析为 ['01wumazhuanqu'=>1, '02madouchuanmei'=>2]。
     * 兼容中英文等号与全角逗号分隔，容忍空行与注释行(# 或 //)。
     */
    function mac_ppvod_category_map(): array
    {
        $raw = $GLOBALS['config']['ppvod']['category_map'] ?? '';
        if (is_array($raw)) {
            return array_map('intval', $raw);
        }
        $raw = (string)$raw;
        if (trim($raw) === '') {
            return [];
        }
        $map = [];
        foreach (preg_split('/[\r\n]+/', $raw) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#' || strpos($line, '//') === 0) {
                continue;
            }
            $line = str_replace(['＝', '：', ':'], '=', $line);
            $pos = strpos($line, '=');
            if ($pos === false) {
                continue;
            }
            $k = trim(substr($line, 0, $pos));
            $v = (int)trim(substr($line, $pos + 1));
            if ($k !== '' && $v > 0) {
                $map[$k] = $v;
            }
        }

        return $map;
    }
}
if (!function_exists('mac_where_ids')) {
    /**
     * 把「勾选的主键 id 集合」归一化成整数数组，供 where(['xxx_id' => ...]) 用。
     *
     * 背景（TP5.1 → TP8 迁移遗留的一类系统性 bug）：
     *   后台列表页有两条提交勾选 id 的路径，形态不同：
     *     - 删除按钮 .j-page-btns：走 AJAX，form.serialize() 把 name="ids[]" 的复选框
     *       序列化成 ids[]=1&ids[]=2 —— PHP 收到的是【数组】；
     *     - 批量设置字段 .j-select（审核/锁定/等级…→ xxx/field）：把勾选 id 以
     *       ids.join(',') 拼成 "1,2,3" 塞进 URL 与 iframe 隐藏字段 —— PHP 收到的是
     *       【逗号串】。
     *   原始 maccms 用 TP5.1 的 $where['xxx_id'] = ['in',$ids] 同时兼容两者；迁移时被
     *   简化成 $where['xxx_id'] = $ids。数组那条照常生成 IN(...)，没事；但逗号串那条
     *   生成 WHERE xxx_id = '1,2,3'，MySQL 拿字符串跟整数列比较会隐式截断成 1，
     *   于是【只命中第一个 id】—— 表现为「批量审核每次只成功一个视频」。
     *
     *   不能照抄 ['in',$ids] 回来：TP8 已删除这种关联式条件语法，实测
     *   where(['id'=>['in','1,2,3']]) 会生成 IN (in,1,2,3)（把 'in' 也当成值）。
     *   正确做法是把值统一成整数数组，框架自动按 IN 处理；单个 id 也没问题（IN (5)）。
     *
     * 传数组或逗号串都接受，返回去重后的正整数数组；无有效 id 时返回 []（调用方
     * 的 !empty($ids) 早已挡在前面，这里再兜一层）。
     */
    function mac_where_ids($ids): array {
        if (!is_array($ids)) {
            $ids = explode(',', (string)$ids);
        }
        $ids = array_map('intval', $ids);
        $ids = array_filter($ids, function ($v) { return $v > 0; });
        return array_values(array_unique($ids));
    }
}
