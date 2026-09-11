<?php

namespace app\admin\controller;

use think\facade\Cache;
use think\facade\Db;
use Exception;
use ip_limit\IpLocationQuery;
class Index extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    public function login()
    {
        if (Request()->isPost()) {
            $data = \think\facade\Request::post();
            $res = (new \app\common\model\Admin())->login($data);
            if ($res['code'] > 1) {
                return $this->error($res['msg']);
            }
            // AJAX 登录由前端跳转，非 AJAX 表单返回 HTTP 重定向。
            // 两者均交给框架中间件完成会话 Cookie 和响应收尾。
            if (\think\facade\Request::isAjax()) {
                return $this->success($res['msg']);
            }
            return redirect((string) url('index/index'));
        }
        event('admin_login_init', $this->request);
        return $this->fetch('admin@index/login');
    }

    public function logout()
    {
        $res = (new \app\common\model\Admin())->logout();
        return redirect((string) url('index/login'));
    }

    public function index()
    {
        $menus = @include MAC_ADMIN_COMM . 'auth.php';
        $version = config('version');

        foreach ($menus as $k1 => $v1) {
            foreach ($v1['sub'] as $k2 => $v2) {
                if ($v2['show'] == 1) {
                    if (strpos($v2['action'], 'javascript') !== false) {
                        $url = $v2['action'];
                    } else {
                        $url = url('admin/' . $v2['controller'] . '/' . $v2['action']);
                    }
                    if (!empty($v2['param'])) {
                        $url .= '?' . $v2['param'];
                    }
                    if ($this->check_auth($v2['controller'], $v2['action'])) {
                        $menus[$k1]['sub'][$k2]['url'] = $url;
                    } else {
                        unset($menus[$k1]['sub'][$k2]);
                    }
                } else {
                    unset($menus[$k1]['sub'][$k2]);
                }
            }

            if (empty($menus[$k1]['sub'])) {
                unset($menus[$k1]);
            }
        }

        $quickmenu = config('quickmenu');
        if (empty($quickmenu)) {
            $quickmenu = mac_read_file(APP_PATH . 'data/config/quickmenu.txt');
            $quickmenu = explode(chr(13), $quickmenu);
        }
        if (!empty($quickmenu)) {
            $menus[1]['sub'][13] = ['name' => lang('admin/index/quick_tit'), 'url' => 'javascript:void(0);return false;', 'controller' => '', 'action' => ''];

            foreach ($quickmenu as $k => $v) {
                if (empty($v)) {
                    continue;
                }
                $one = explode(',', trim($v));
                if (substr($one[1], 0, 4) == 'http' || substr($one[1], 0, 2) == '//') {
                } elseif (substr($one[1], 0, 1) == '/') {
                } elseif (strpos($one[1], '###') !== false || strpos($one[1], 'javascript:') !== false) {
                } else {
                    $one[1] = url($one[1]);
                }
                $menus[1]['sub'][14 + $k] = ['name' => $one[0], 'url' => $one[1], 'controller' => '', 'action' => ''];
            }
        }
        $langs = glob('./application/lang/*.php');
        foreach ($langs as $k => &$v) {
            $v = str_replace(['./application/lang/','.php'],['',''],$v);
        }
        $config = config('maccms');
        $this->assign('config', $config);
        $this->assign('langs', $langs);
        $this->assign('version', $version);
        $this->assign('menus', $menus);
        $this->assign('title', lang('admin/index/title'));
        $ipQuery = new IpLocationQuery();
        $country_code = $ipQuery->queryProvince(mac_get_client_ip());
        if($country_code == ""){
            $country_code = "其它";
        }
        $this->assign('ip_location', $country_code);
        $this->assign('mac_lang', \think\facade\Lang::getLangSet());
        return $this->fetch('admin@index/index');
    }

    public function welcome()
    {
        $version = config('version');

        $this->assign('spider_data', $this->botListData());
        $os_data = $this->systemStatusData();
        $show_os_guide = false;
        if (empty($os_data['cpu_usage']) || empty($os_data['mem_total'])) {
            $show_os_guide = true;
        }
        if (empty($os_data['disk_datas'])) {
            $show_os_guide = true;
        } else {
            $disk_total = 0;
            foreach($os_data['disk_datas'] as $disk) {
                $disk_total += $disk[1];
            }
            if ($disk_total == 0) {
                $show_os_guide = true;
            }
        }
        $this->assign('show_os_guide', $show_os_guide);
        $this->assign('os_data', $os_data);
        $this->assign('version', $version);
        $this->assign('mac_lang', \think\facade\Lang::getLangSet());
        $this->assign('dashboard_data', $this->getAdminDashboardData());

        $this->assign('admin', $this->_admin);
        $this->assign('perf_checks', mac_perf_env_checks());
        $this->assign('title', lang('admin/index/welcome/title'));
        return $this->fetch('admin@index/welcome');
    }

    public function quickmenu()
    {
        if (Request()->isPost()) {
            $param = \think\facade\Request::param();
            $validate = mac_validate('Token');
            if (!$validate->check($param)) {
                return $this->error($validate->getError());
            }
            $quickmenu = \think\facade\Request::post("quickmenu");
            $quickmenu = str_replace(chr(10), '', $quickmenu);
            $menu_arr = explode(chr(13), $quickmenu);
            $res = mac_arr2file(APP_PATH . 'extra/quickmenu.php', $menu_arr);
            if ($res === false) {
                return $this->error(lang('save_err'));
            }
            return $this->success(lang('save_ok'));
        } else {
            $config_menu = config('quickmenu');
            if (empty($config_menu)) {
                $quickmenu = mac_read_file(APP_PATH . 'data/config/quickmenu.txt');
            } else {
                $quickmenu = array_values($config_menu);
                $quickmenu = join(chr(13), $quickmenu);
            }
            $this->assign('quickmenu', $quickmenu);
            $this->assign('title', lang('admin/index/quickmenu/title'));
            return $this->fetch('admin@index/quickmenu');
        }
    }

    public function checkcache()
    {
        $res = 'no';
        $r = cache('cache_data');
        if ($r == '1') {
            $res = 'haved';
        }
        echo $res;
    }

    public function clear()
    {
        $res = $this->_cache_clear();
        //运行缓存
        if (!$res) {
            $this->error(lang('admin/index/clear_err'));
        }
        // 搜索缓存结果清理
        (new \app\common\model\VodSearch())->clearOldResult(true);
        return $this->success(lang('admin/index/clear_ok'));
    }

    public function iframe()
    {
        $val = \think\facade\Request::post('val', 0);
        if ($val != 0 && $val != 1) {
            return $this->error(lang('admin/index/clear_ok'));
        }
        if ($val == 1) {
            cookie('is_iframe', 'yes');
        } else {
            cookie('is_iframe', null);
        }
        return $this->success(lang('admin/index/iframe'));
    }

    public function unlocked()
    {
        $param = \think\facade\Request::param();
        $password = $param['password'];

        // 安全加固(V4):兼容 bcrypt/旧md5 的解锁校验
        if (!mac_password_verify($password, $this->_admin['admin_pwd'])) {
            return $this->error(lang('admin/index/pass_err'));
        }

        return $this->success(lang('admin/index/unlock_ok'));
    }

    public function check_back_link()
    {
        $param = \think\facade\Request::param();
        $res = mac_check_back_link($param['url']);
        return json($res);
    }

    public function select()
    {
        $param = \think\facade\Request::param();
        // 这些全是 URL 传参,缺任何一个都是合法调用形态(如 val 为空=清空该字段),
        // 不该每次都记一条 warning —— 生产上单 val 一项就刷了 46 条。
        $tpl = $param['tpl'] ?? '';
        $tab = $param['tab'] ?? '';
        $col = $param['col'] ?? '';
        $ids = $param['ids'] ?? '';
        $url = $param['url'] ?? '';
        $val = $param['val'] ?? '';

        $refresh = $param['refresh'] ?? '';

        if (empty($tpl) || empty($tab) || empty($col) || empty($ids) || empty($url)) {
            return $this->error(lang('param_err'));
        }
        // 安全加固(V14):限制模板名仅为字母数字下划线,杜绝 ../ 穿越与 @ 跨模块加载任意模板
        if (!preg_match('/^[a-z0-9_]+$/i', (string)$tpl)) {
            return $this->error(lang('param_err'));
        }

        if (is_array($ids)) {
            $ids = join(',', $ids);
        }

        if (empty($refresh)) {
            $refresh = 'yes';
        }

        $url = url($url);
    $mid = 1;
    if ($tab == 'art') {
        $mid = 2;
    } elseif ($tab == 'actor') {
        $mid = 8;
    } elseif ($tab == 'website') {
        $mid = 11;
    } elseif ($tab == 'manga') {
        $mid = 12;
    }
        $this->assign('mid', $mid);

        if ($tpl == 'select_type') {
            $type_tree = (new \app\common\model\Type())->getCache('type_tree');
            $this->assign('type_tree', $type_tree);
        } elseif ($tpl == 'select_level') {
            $level_list = [1, 2, 3, 4, 5, 6, 7, 8, 9];
            $this->assign('level_list', $level_list);
        }

        $this->assign('refresh', $refresh);
        $this->assign('url', $url);
        $this->assign('tab', $tab);
        $this->assign('col', $col);
        $this->assign('ids', $ids);
        $this->assign('val', $val);
        return $this->fetch('admin@public/' . $tpl);
    }

    /**
     * 动作入口：仅负责把数据包成 Response。
     * TP8 不会像 TP5 那样自动把返回的数组转成 JSON —— 返回裸数组会记
     * 「variable type error： array」并输出 0 字节。
     * 但本方法【同时被 welcome() 内部当数组用】，所以数据生产必须留在
     * 私有方法里：直接在这里 return json() 会让 welcome() 拿到 Response 对象，
     * 触发「Cannot use object of type think\response\Json as array」而 500。
     */
    public function get_system_status()
    {
        return json($this->systemStatusData());
    }

    /** 采集系统状态，返回数组。供动作与 welcome() 共用。 */
    private function systemStatusData(): array
    {
        return \app\common\util\SystemMetrics::snapshot(ROOT_PATH);
    }

    private function getAdminDashboardData()
    {
        // 今日数据（今日零点会变，TTL 短）
        $today_start = strtotime(date('Y-m-d 00:00:00'));
        $today_end = $today_start + 86399;
        $todayCacheKey  = 'admin_dashboard_today_' . date('Ymd');
        $weekCacheKey   = 'admin_dashboard_week_' . date('YmdH');  // 按小时粒度

        // 七日图表数据缓存 5 分钟（统计慢查询，5min 内无感知）
        $weekData = Cache::get($weekCacheKey);
        if ($weekData === null) {
            $prefix = config('database.connections.mysql.prefix');
            $sevenDaysAgo = strtotime(date('Y-m-d 00:00:00')) - 6 * 86400;

            // 原 SELECT * 子查询改为直接 GROUP BY，让 visit_time 索引生效
            $visitTable = '`' . str_replace('`', '``', $prefix . 'visit') . '`';
            $tmp_arr = Db::query(
                "SELECT FROM_UNIXTIME(visit_time, '%Y-%c-%d') days, COUNT(*) count
                 FROM {$visitTable}
                 WHERE visit_time >= ?
                 GROUP BY days
                 ORDER BY days ASC",
                [$sevenDaysAgo]
            );

            $userTable = '`' . str_replace('`', '``', $prefix . 'user') . '`';
            $reg_arr = Db::query(
                "SELECT FROM_UNIXTIME(user_reg_time, '%Y-%c-%d') days, COUNT(*) count
                 FROM {$userTable}
                 WHERE user_reg_time >= ?
                 GROUP BY days
                 ORDER BY days ASC",
                [$sevenDaysAgo]
            );

            $weekData = ['visit' => $tmp_arr, 'reg' => $reg_arr];
            Cache::set($weekCacheKey, $weekData, 300);
        }

        $tmp_arr = $weekData['visit'];
        $reg_arr = $weekData['reg'];

        // 今日实时数据缓存 2 分钟
        $todayData = Cache::get($todayCacheKey);
        if ($todayData === null) {
            $todayData = [
                'user_count'        => (new \app\common\model\User())->count(),
                'user_active_count' => (new \app\common\model\User())->where('user_status', 1)->count(),
                'today_visit_count' => (new \app\common\model\Visit())->where('visit_time', 'between', $today_start . ',' . $today_end)->count(),
                'today_money_get'   => (new \app\common\model\Order())->where('order_time', 'between', $today_start . ',' . $today_end)->where('order_status', 1)->sum('order_price'),
            ];
            Cache::set($todayCacheKey, $todayData, 120);
        }

        $result = [];
        $result['user_count']        = number_format($todayData['user_count'], 0, '.', ',');
        $result['user_active_count'] = number_format($todayData['user_active_count'], 0, '.', ',');
        $result['today_visit_count'] = number_format($todayData['today_visit_count'], 0, '.', ',');
        $result['today_money_get']   = number_format($todayData['today_money_get'], 2, '.', ',');

        // 七日访问图表
        $result['seven_day_visit_day']   = [];
        $result['seven_day_visit_count'] = [];
        $result['raise_visit_user_today'] = 0;
        if (is_array($tmp_arr) && count($tmp_arr) > 1 && (strtotime(end($tmp_arr)['days']) == strtotime(date('Y-m-d')))) {
            $yesterday_visit_count = $tmp_arr[count($tmp_arr) - 2]['count'];
            $lastday_visit_count   = end($tmp_arr)['count'];
            if ($yesterday_visit_count != 0) {
                $result['raise_visit_user_today'] = number_format((($lastday_visit_count - $yesterday_visit_count) / $yesterday_visit_count) * 100, 2, '.', ',');
            }
        }
        $result['seven_day_visit_total_count'] = 0;
        foreach ($tmp_arr as $data) {
            $result['seven_day_visit_day'][]   = $data['days'];
            $result['seven_day_visit_count'][] = $data['count'];
            $result['seven_day_visit_total_count'] += (int)$data['count'];
        }
        $result['seven_day_visit_total_count'] = number_format($result['seven_day_visit_total_count'], 0, '.', ',');

        // 七日注册图表
        $result['seven_day_reg_data']        = $reg_arr;
        $result['seven_day_reg_day']         = [];
        $result['seven_day_reg_count']       = [];
        $result['seven_day_reg_total_count'] = 0;
        $result['raise_reg_user_today']      = 0;
        foreach ($reg_arr as $value) {
            $result['seven_day_reg_day'][]   = $value['days'];
            $result['seven_day_reg_count'][] = $value['count'];
            $result['seven_day_reg_total_count'] += (int)$value['count'];
        }
        if (is_array($reg_arr) && count($reg_arr) > 1 && (strtotime(end($reg_arr)['days']) == strtotime(date('Y-m-d')))) {
            $yesterday_reg_count = $reg_arr[count($reg_arr) - 2]['count'];
            $lastday_reg_count   = end($reg_arr)['count'];
            if ($yesterday_reg_count != 0) {
                $result['raise_reg_user_today'] = number_format((($lastday_reg_count - $yesterday_reg_count) / $yesterday_reg_count) * 100, 2, '.', ',');
            }
        }
        $result['seven_day_reg_total_count'] = number_format($result['seven_day_reg_total_count'], 0, '.', ',');

        return $result;
    }

    public function rangeDateDailyVisit()
    {

        $startTs = strtotime(isset($_POST['startDate']) ? $_POST['startDate'] : '');
        $endTs = strtotime(isset($_POST['endDate']) ? $_POST['endDate'] : '');
        $startTs = ($startTs !== false) ? (int)$startTs : 0;
        $endTs = ($endTs !== false) ? (int)$endTs : 0;
        $visitTable = config('database.connections.mysql.prefix') . 'visit';
        $visitTable = '`' . str_replace('`', '``', $visitTable) . '`';
        // 去掉冗余子查询，直接 WHERE+GROUP BY 让 idx_visit_time 生效
        $range_daily_visit_data = Db::query(
            "SELECT FROM_UNIXTIME(visit_time, '%Y-%c-%d') days, COUNT(*) count
             FROM {$visitTable}
             WHERE visit_time >= ? AND visit_time <= ?
             GROUP BY days
             ORDER BY days ASC",
            [$startTs, $endTs]
        );
        $result = [];
        $range_visit_day = [];
        $range_visit_count = [];
        $range_visit_sum = 0;
        foreach ($range_daily_visit_data as $data) {
            $range_visit_sum = $range_visit_sum + $data['count'];
            array_push($range_visit_day, $data['days']);
            array_push($range_visit_count, $data['count']);
        }

        $result['days'] = $range_visit_day;
        $result['count'] = $range_visit_count;
        $result['sum'] = $range_visit_sum;
        return json_encode($result);
    }

    /** 动作入口：包 JSON。数据生产在 botListData()，因为 welcome() 也要用（见 get_system_status 的说明）。 */
    public function botlist()
    {
        $data = $this->botListData();
        $cat  = isset($_POST['category']) ? trim((string)$_POST['category']) : '';
        if ($cat === '') {
            // 前端首屏调用时下拉框还没选中，category 是空串。
            // 原来返回 $data[''] ?? [] —— 一个空数组，前端取 data.values 得到 undefined，
            // apexcharts 收到 series[0].data = undefined 就抛
            // 「t[c].data.map is not a function」，整个仪表盘脚本随之中断。
            // 这里回退到第一个有数据的蜘蛛，保证响应形状始终是 {key:[], values:[]}。
            foreach ($data as $one) {
                if (is_array($one) && isset($one['key'], $one['values'])) { return json($one); }
            }
            return json(['key' => [], 'values' => []]);
        }
        $hit = $data[$cat] ?? null;
        // 选了但该蜘蛛无记录时，同样返回形状完整的空结构，而不是空数组
        return json(is_array($hit) && isset($hit['key'], $hit['values'])
            ? $hit : ['key' => [], 'values' => []]);
    }

    /** 统计各搜索引擎蜘蛛最近 7 天的抓取，返回数组。供动作与 welcome() 共用。 */
    private function botListData()
    {
        $day_arr = [];
        //列出最近10天的日期
        for ($i = 0; $i < 7; $i++) {
            $day_arr[$i] = date('Y-m-d', time() - $i * 60 * 60 * 24);
        }
        $google_arr = [];
        $baidu_arr = [];
        $sogou_arr = [];
        $soso_arr = [];
        $yahoo_arr = [];
        $msn_arr = [];
        $msn_bot_arr = [];
        $sohu_arr = [];
        $yodao_arr = [];
        $twiceler_arr = [];
        $alexa_arr = [];
        $bot_list = [];
        foreach ($day_arr as $day_vo) {
            if (file_exists(ROOT_PATH . 'runtime/log/bot/' . $day_vo . '.txt')) {
                $bot_content = file_get_contents(ROOT_PATH . 'runtime/log/bot/' . $day_vo . '.txt');
            } else {
                $bot_content = '';
            }
            $google_arr[$day_vo] = substr_count($bot_content, 'Google');
            $baidu_arr[$day_vo] = substr_count($bot_content, 'Baidu');
            $sogou_arr[$day_vo] = substr_count($bot_content, 'Sogou');
            $soso_arr[$day_vo] = substr_count($bot_content, 'SOSO');
            $yahoo_arr[$day_vo] = substr_count($bot_content, 'Yahoo');
            $msn_arr[$day_vo] = substr_count($bot_content, 'MSN');
            $msn_bot_arr[$day_vo] = substr_count($bot_content, 'msnbot');
            $sohu_arr[$day_vo] = substr_count($bot_content, 'Sohu');
            $yodao_arr[$day_vo] = substr_count($bot_content, 'Yodao');
            $twiceler_arr[$day_vo] = substr_count($bot_content, 'Twiceler');
            $alexa_arr[$day_vo] = substr_count($bot_content, 'Alexa');
        }
        $bot_list['Google']['key'] = array_keys($google_arr);
        $bot_list['Google']['values'] = array_values($google_arr);
        $bot_list['Baidu']['keys'] = array_keys($baidu_arr);
        $bot_list['Baidu']['values'] = array_values($baidu_arr);
        $bot_list['Sogou']['keys'] = array_keys($sogou_arr);
        $bot_list['Sogou']['values'] = array_values($sogou_arr);
        $bot_list['SOSO']['keys'] = array_keys($soso_arr);
        $bot_list['SOSO']['values'] = array_values($soso_arr);
        $bot_list['Yahoo']['keys'] = array_keys($yahoo_arr);
        $bot_list['Yahoo']['values'] = array_values($yahoo_arr);
        $bot_list['MSN']['keys'] = array_keys($msn_arr);
        $bot_list['MSN']['values'] = array_values($msn_arr);
        $bot_list['msnbot']['keys'] = array_keys($msn_bot_arr);
        $bot_list['msnbot']['values'] = array_values($msn_bot_arr);
        $bot_list['Sohu']['keys'] = array_keys($sohu_arr);
        $bot_list['Sohu']['values'] = array_values($sohu_arr);
        $bot_list['Yodao']['keys'] = array_keys($yodao_arr);
        $bot_list['Yodao']['values'] = array_values($yodao_arr);
        $bot_list['Twiceler']['keys'] = array_keys($twiceler_arr);
        $bot_list['Twiceler']['values'] = array_values($twiceler_arr);
        $bot_list['Alexa']['keys'] = array_keys($alexa_arr);
        $bot_list['Alexa']['values'] = array_values($alexa_arr);

        if (!empty($_POST['category'])) {
            return $bot_list[$_POST['category']] ?? [];
        } else {
            return $bot_list;
        }
    }

    public function botlog()
    {
        $parm = \think\facade\Request::param();
        $data = (string)($parm['data'] ?? '');
        // 安全加固(V5):仅允许安全文件名,杜绝 ../ 路径穿越读取任意 .txt
        if ($data === '' || !preg_match('/^[A-Za-z0-9_\-]{1,64}$/', $data)) {
            return $this->error(lang('param_err'));
        }
        $bot_file = ROOT_PATH . 'runtime/log/bot/' . $data . '.txt';
        $bot_base = realpath(ROOT_PATH . 'runtime/log/bot/');
        $bot_real = realpath($bot_file);
        if ($bot_base === false || $bot_real === false || strpos($bot_real, $bot_base . DIRECTORY_SEPARATOR) !== 0) {
            return $this->error(lang('param_err'));
        }
        $bot_content = file_get_contents($bot_real);
        $bot_list = array_slice(array_reverse(explode("\r\n", trim($bot_content))), 0, 20);
        $this->assign('bot_list', $bot_list);
        return $this->fetch('admin@others/botlog');
    }
}