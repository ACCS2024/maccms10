<?php
namespace app\api\controller;

use think\facade\Db;
use app\common\util\Pinyin;

/**
 * 转码机内容入库接口（站点主要内容来源）
 *
 * 外部转码服务把成片信息以 JSON POST 到本接口，据此建 vod 记录。
 * 本站 mac_collect / mac_cj_node 均为空 —— 内容不是采集来的，是这条链路推进来的，
 * 所以这个控制器一旦缺失或报错，全站就不再有新内容。
 *
 *   POST /api.php/yzm/yzmauto?ac=yzm&pass=<interface.pass>
 *   body: 转码机产出的 JSON（orgfile/rpath/category/metadata/shareid/...）
 *
 * 从 TP5 移植到 TP8 的改动（行为保持不变，仅修正不兼容与安全问题）：
 *  1. use think\Db → think\facade\Db；移除无用且大小写错误的 use think\config
 *     （在大小写敏感的文件系统上，think\config 会解析失败）。
 *  2. 同名判重原本拼裸 SQL：
 *        $where = "vod_name='" . $info['vod_name'] . "'";
 *     vod_name 直接来自外部 JSON 的 orgfile，可注入。改为参数化 where。
 *  3. $info['type_name'] 不是 mac_vod 的列，TP8 严格字段模式下会导致 insert 失败，
 *     用完分类映射后必须剔除。
 *  4. $this->_param['ac'] / ['pass'] 未定义键防护（PHP 8 下未定义键会告警）。
 *  5. 日志目录改用应用根目录推导，不再依赖 $_SERVER['DOCUMENT_ROOT']
 *     （CLI 或部分 FPM 配置下该变量为空，会把日志写到文件系统根）。
 */
class Yzm extends Base
{
    private $_param;

    /** 播放器标识 */
    private $player = '155m3u8';

    /** 播放地址前缀名称 */
    private $playname = '第1集';

    /** share=分享地址 m3u8=m3u8地址 all=两个都入库 */
    private $addr = 'm3u8';

    /** 找不到分类时的默认栏目 ID */
    private $errorid = 11;

    /** 转码机 category → mac_type.type_id 映射 */
    private static $categoryMap = [
        '01wumazhuanqu'    => 1,
        '02madouchuanmei'  => 2,
        '03zhifuyouhuo'    => 3,
        '04sanjilunli'     => 4,
        '05aihuanlian'     => 5,
        '06zhongwenzimu'   => 6,
        '07katongdongman'  => 7,
        '08oumeixilie'     => 8,
        '09meinvzhubo'     => 9,
        '10guochanzipai'   => 10,
        '11shunvrenqi'     => 11,
        '12luolishaonv'    => 12,
        '13nvtongxingai'   => 13,
        '14duorenqunjiao'  => 14,
        '15meirujuru'      => 15,
        '16qiangjianluanlun' => 16,
        '33douyinshipin'   => 33,
        '34hanguozhubo'    => 34,
        '35wanghongtoutiao' => 35,
        '36wangbaoheiliao' => 36,
        '37oumeiwuma'      => 37,
        '38nvyoumingxing'  => 38,
        '39SMdiaojiao'     => 39,
        '40AVjieshuo'      => 40,
    ];

    public function __construct()
    {
        parent::__construct();
        $this->_param = input();

        if (($this->_param['ac'] ?? '') !== 'yzm') {
            $this->logError('非法使用此参数，只能是yzm，不可更改');
            exit;
        }
        if (($GLOBALS['config']['interface']['pass'] ?? '') !== ($this->_param['pass'] ?? '')) {
            $this->logError('入库密码不一致');
            exit;
        }
    }

    /**
     * 通知图床对远程图片做一次抓取缓存
     */
    private function fetchImageWithTryCatch($picUrl)
    {
        try {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, 'http://155pic.com/155pic_remoat.php?pic_url=' . $picUrl);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            curl_exec($ch);
            if (curl_errno($ch)) {
                $this->logError('图床抓取失败: ' . curl_error($ch));
            }
            curl_close($ch);
        } catch (\Throwable $e) {
            $this->logError('图床抓取异常: ' . $e->getMessage());
        }
    }

    public function yzmauto()
    {
        $config = config('maccms.collect');
        $config = $config['vod'] ?? [];
        if (empty($config)) {
            $this->logError('配置参数出错，无法使用');
            return;
        }

        $task = file_get_contents('php://input');
        if (!$task) {
            $this->logError('未获取到对应视频信息');
            return;
        }

        $arr = json_decode($task, true);
        $this->logError($task);
        if (!$arr) {
            return;
        }

        $info = [];
        $title_old = $arr['orgfile'] ?? '';
        $title_hz  = '.' . ($arr['suffix'] ?? '');
        $info['vod_name'] = str_replace($title_hz, '', $title_old);

        $videopath  = str_replace('\\', '/', $arr['rpath'] ?? '');
        $searchpath = $this->getCharpos2($videopath, '/');
        $videorpath = $searchpath >= 2 ? $videopath : '/' . $videopath;

        $pic = 'http://23.224.205.82:2100' . ($arr['rpath'] ?? '') . '/1.jpg';
        $this->fetchImageWithTryCatch($pic);
        $info['vod_pic'] = 'http://15260503.top' . ($arr['rpath'] ?? '') . '/1.jpg';

        if ($this->transgress_keyword($info['vod_name']) > 0) {
            $this->logError('内容含有非法词汇,无法入库 视频ID:' . $info['vod_name']);
            return;
        }

        $info['vod_en']        = Pinyin::get($info['vod_name']);
        $info['vod_letter']    = strtoupper(substr($info['vod_en'], 0, 1));
        $info['vod_pic_thumb'] = $info['vod_pic'];
        $info['vod_time_add']  = time();
        $info['vod_time']      = time();
        $info['vod_duration']  = $this->secondsToHour($arr['metadata']['time'] ?? 0);
        $info['vod_play_from'] = $this->player;

        $m3u8  = $this->playname . '$' . 'https://2607.v155p.com' . $videorpath . '/index.m3u8';
        $share = $this->playname . '$' . 'https://2607.v155p.com' . '/share/' . ($arr['shareid'] ?? '');
        // 原实现里 share 分支与 m3u8 分支等价，all 为两地址拼接，此处保持不变
        $info['vod_play_url'] = ($this->addr === 'all') ? ($m3u8 . '$$$' . $m3u8) : $m3u8;

        $info['vod_blurb']       = $info['vod_name'];
        $info['vod_content']     = $info['vod_name'];
        $info['vod_total']       = '1';
        $info['vod_serial']      = '1';
        $info['vod_isend']       = '1';
        $info['vod_pubdate']     = date('Y-m-d');
        $info['vod_year']        = date('Y');
        $info['vod_status']      = 0;
        $info['vod_down_url']    = $share;
        $info['vod_plot_name']   = 'null';
        $info['vod_plot_detail'] = 'null';

        $category            = $arr['category'] ?? '';
        $info['vod_class']   = mac_format_text(mac_txt_merge('', $category));

        if ($config['hits_start'] > 0 && $config['hits_end'] > 0) {
            $info['vod_hits']       = rand($config['hits_start'], $config['hits_end']);
            $info['vod_hits_day']   = rand($config['hits_start'], $config['hits_end']);
            $info['vod_hits_week']  = rand($config['hits_start'], $config['hits_end']);
            $info['vod_hits_month'] = rand($config['hits_start'], $config['hits_end']);
        }
        if (($config['tag'] ?? 0) == 1) {
            $info['vod_tag'] = mac_get_tag($info['vod_name'], $info['vod_content']);
        }
        if ($config['updown_start'] > 0 && $config['updown_end']) {
            $info['vod_up']   = rand($config['updown_start'], $config['updown_end']);
            $info['vod_down'] = rand($config['updown_start'], $config['updown_end']);
        }
        if (($config['score'] ?? 0) == 1) {
            $info['vod_score_num'] = rand(1, 1000);
            $info['vod_score_all'] = $info['vod_score_num'] * rand(1, 10);
            $info['vod_score']     = round($info['vod_score_all'] / $info['vod_score_num'], 1);
        }
        if (($config['psernd'] ?? 0) == 1) {
            $info['vod_content'] = mac_rep_pse_rnd($config['words'], $info['vod_content']);
        }
        if (($config['psesyn'] ?? 0) == 1) {
            $info['vod_content'] = mac_rep_pse_syn($config['thesaurus'], $info['vod_content']);
        }

        if (!isset(self::$categoryMap[$category])) {
            $this->logError('视频入库失败：未知分类 ' . $category);
            return;
        }
        $info['type_id'] = self::$categoryMap[$category];

        try {
            // 同名判重：原实现拼裸 SQL，vod_name 来自外部 JSON 可注入，改参数化
            $exists = Db::name('vod')->where('vod_name', $info['vod_name'])->find();
            if ($exists) {
                $this->logError('存在同名视频，并播放地址无改变 视频ID:' . $info['vod_name']);
                return;
            }
            $res = Db::name('vod')->insert($info);
            $this->logError($res
                ? '视频入库成功 视频ID:' . $info['vod_name'] . ' 分类:' . $info['vod_class']
                : '视频入库失败');
        } catch (\Throwable $e) {
            $this->logError($e->getMessage());
        }
    }

    private function secondsToHour($seconds)
    {
        $seconds = (int) $seconds;
        if ($seconds <= 0) {
            return '00:00:00';
        }
        $h = intdiv($seconds, 3600);
        $m = intdiv($seconds % 3600, 60);
        $s = $seconds % 60;
        return sprintf('%02d:%02d:%02d', $h, $m, $s);
    }

    /**
     * 入库日志。原实现取 $_SERVER['DOCUMENT_ROOT']，CLI 或部分 FPM 配置下为空，
     * 会把日志写到文件系统根目录；改为从应用根目录推导。
     */
    private function logError($content)
    {
        $root = defined('ROOT_PATH') ? ROOT_PATH : (($_SERVER['DOCUMENT_ROOT'] ?? '') ?: getcwd()) . DIRECTORY_SEPARATOR;
        $dir  = rtrim($root, '/\\') . DIRECTORY_SEPARATOR . 'log' . DIRECTORY_SEPARATOR;
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        @error_log(date('[Y-m-d H:i:s]') . ' - ' . $content . "\n", 3, $dir . date('Y-m-d') . '.txt');
    }

    private function transgress_keyword($content)
    {
        $keyword = [];
        $m = 0;
        foreach ($keyword as $kw) {
            if (substr_count($content, $kw) > 0) {
                $m++;
            }
        }
        return $m;
    }

    private function getCharpos2($str, $char)
    {
        return substr_count((string) $str, $char);
    }
}
