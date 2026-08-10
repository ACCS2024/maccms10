<?php
namespace app\api\controller;

use think\facade\Db;
use app\common\util\Pinyin;

/**
 * 转码机内容入库接口（站点侧对接组件）
 *
 *   POST /api.php/ppvod/ingest?ac=yzm&pass=<interface.pass>      （规范入口）
 *   POST /api.php/yzm/yzmauto?ac=yzm&pass=<interface.pass>       （历史入口，仍可用）
 *   body: 转码服务产出的 JSON（orgfile / suffix / rpath / category / shareid / metadata ...）
 *
 * 【本文件不包含任何站点或基础设施信息】
 * 转码机地址、图床域名、播放域名、播放器标识、分类映射等全部来自后台
 * 「PPVOD 转码入库」配置页（$config['ppvod']，保存在本站
 * application/extra/maccms.php；仓库里那份是占位空值）。
 * 未启用或配置不完整时接口直接拒绝服务并记日志，绝不使用内置默认值兜底，
 * 以免把某一个部署的地址变成所有部署的默认值。
 */
class Ppvod extends Base
{
    private $_param;

    /** @var array 站点私有配置（application/extra/yzm.php） */
    private $_cfg = [];

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

        // 配置来自后台「PPVOD 转码入库」页（$config['ppvod']，存于本站
        // application/extra/maccms.php —— 该文件在 Begin 中间件的 extra/ 白名单内）。
        $cfg = $GLOBALS['config']['ppvod'] ?? [];
        if (!is_array($cfg) || (string)($cfg['status'] ?? '0') !== '1') {
            $this->logError('PPVOD 入库接口未启用：请在后台「PPVOD 转码入库」中开启');
            exit;
        }
        $cfg['category_map'] = is_array($cfg['category_map'] ?? null)
            ? array_map('intval', $cfg['category_map'])
            : mac_ppvod_category_map();
        if (empty($cfg['play_domain']) || empty($cfg['pic_domain']) || empty($cfg['category_map'])) {
            $this->logError('PPVOD 配置不完整：播放域名 / 图床域名 / 分类映射均为必填');
            exit;
        }
        if (!is_array($cfg['keyword_blacklist'] ?? null)) {
            $cfg['keyword_blacklist'] = array_values(array_filter(array_map(
                'trim', preg_split('/[\r\n]+/', (string)($cfg['keyword_blacklist'] ?? ''))
            )));
        }
        $this->_cfg = $cfg;
    }

    /**
     * 通知图床对远程图片做一次抓取缓存（未配置该接口则跳过）
     */
    private function fetchImageWithTryCatch($picUrl)
    {
        $api = $this->_cfg['pic_fetch_api'] ?? '';
        if ($api === '') {
            return;
        }
        try {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $api . rawurlencode($picUrl));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, (int)($this->_cfg['pic_fetch_timeout'] ?? 15));
            curl_exec($ch);
            if (curl_errno($ch)) {
                $this->logError('图床抓取失败: ' . curl_error($ch));
            }
            curl_close($ch);
        } catch (\Throwable $e) {
            $this->logError('图床抓取异常: ' . $e->getMessage());
        }
    }

    /** 新的规范入口 */
    public function ingest()
    {
        return $this->yzmauto();
    }

    /**
     * 历史入口名。转码机侧配置的是 /api.php/yzm/yzmauto，
     * 在对方改配置之前不能改名，否则入库直接静默中断。
     */
    public function yzmauto()
    {
        $collect = config('maccms.collect');
        $collect = $collect['vod'] ?? [];
        if (empty($collect)) {
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

        $c = $this->_cfg;

        $info = [];
        $info['vod_name'] = str_replace('.' . ($arr['suffix'] ?? ''), '', (string)($arr['orgfile'] ?? ''));

        $rpath      = (string)($arr['rpath'] ?? '');
        $videopath  = str_replace('\\', '/', $rpath);
        $videorpath = substr_count($videopath, '/') >= 2 ? $videopath : '/' . $videopath;

        // 先让图床把源站的图抓过去，再把 vod_pic 指向图床
        if (!empty($c['transcoder_url'])) {
            $this->fetchImageWithTryCatch(rtrim($c['transcoder_url'], '/') . $rpath . '/1.jpg');
        }
        $info['vod_pic'] = rtrim($c['pic_domain'], '/') . $rpath . '/1.jpg';

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
        $info['vod_play_from'] = $c['player_flag'];

        $playname = $c['play_name'] ?? '第1集';
        $play     = rtrim($c['play_domain'], '/');
        $m3u8     = $playname . '$' . $play . $videorpath . '/index.m3u8';
        $share    = $playname . '$' . $play . '/share/' . ($arr['shareid'] ?? '');
        $info['vod_play_url'] = (($c['addr_mode'] ?? 'm3u8') === 'all') ? ($m3u8 . '$$$' . $m3u8) : $m3u8;

        $info['vod_blurb']       = $info['vod_name'];
        $info['vod_content']     = $info['vod_name'];
        $info['vod_total']       = '1';
        $info['vod_serial']      = '1';
        $info['vod_isend']       = '1';
        $info['vod_pubdate']     = date('Y-m-d');
        $info['vod_year']        = date('Y');
        $info['vod_status']      = (int)($c['default_status'] ?? 0);
        $info['vod_down_url']    = $share;
        $info['vod_plot_name']   = 'null';
        $info['vod_plot_detail'] = 'null';

        $category          = (string)($arr['category'] ?? '');
        $info['vod_class'] = mac_format_text(mac_txt_merge('', $category));

        if ($collect['hits_start'] > 0 && $collect['hits_end'] > 0) {
            $info['vod_hits']       = rand($collect['hits_start'], $collect['hits_end']);
            $info['vod_hits_day']   = rand($collect['hits_start'], $collect['hits_end']);
            $info['vod_hits_week']  = rand($collect['hits_start'], $collect['hits_end']);
            $info['vod_hits_month'] = rand($collect['hits_start'], $collect['hits_end']);
        }
        if (($collect['tag'] ?? 0) == 1) {
            $info['vod_tag'] = mac_get_tag($info['vod_name'], $info['vod_content']);
        }
        if ($collect['updown_start'] > 0 && $collect['updown_end']) {
            $info['vod_up']   = rand($collect['updown_start'], $collect['updown_end']);
            $info['vod_down'] = rand($collect['updown_start'], $collect['updown_end']);
        }
        if (($collect['score'] ?? 0) == 1) {
            $info['vod_score_num'] = rand(1, 1000);
            $info['vod_score_all'] = $info['vod_score_num'] * rand(1, 10);
            $info['vod_score']     = round($info['vod_score_all'] / $info['vod_score_num'], 1);
        }
        if (($collect['psernd'] ?? 0) == 1) {
            $info['vod_content'] = mac_rep_pse_rnd($collect['words'], $info['vod_content']);
        }
        if (($collect['psesyn'] ?? 0) == 1) {
            $info['vod_content'] = mac_rep_pse_syn($collect['thesaurus'], $info['vod_content']);
        }

        // category → type_id 映射来自站点配置，不内置任何业务分类
        if (!isset($c['category_map'][$category])) {
            $this->logError('视频入库失败：未知分类 ' . $category);
            return;
        }
        $info['type_id'] = (int)$c['category_map'][$category];

        try {
            // 同名判重。注意：不可拼裸 SQL —— vod_name 直接来自外部 JSON 的 orgfile
            $exists = Db::name('vod')->where('vod_name', $info['vod_name'])->find();
            if ($exists) {
                $this->logError('存在同名视频，并播放地址无改变 视频ID:' . $info['vod_name']);
                return;
            }
            $res = Db::name('vod')->insert($info);
            if ($res) {
                // 增量同步搜索索引。本控制器为了保持与老站一致的字段处理，
                // 是直接 Db::insert 而非走 Vod::saveData()，因此不会自动触发
                // MeilisearchSync —— 不显式调用的话，转码机推进来的内容要等到
                // 下一次全量重建才可被搜索到。
                // afterVodSave 内部会按 vod_status / vod_recycle_time 判断：
                // 未发布(默认 status=0 待审核)时会从索引移除，因此无论
                // default_status 配成 0 还是 1，这里调用都是正确的。
                try {
                    $newId = (int)Db::name('vod')->where('vod_name', $info['vod_name'])->value('vod_id');
                    if ($newId > 0) {
                        \app\common\util\MeilisearchSync::afterVodSave($newId);
                    }
                } catch (\Throwable $e) {
                    // 索引同步失败不应影响入库结果
                    $this->logError('Meili 同步失败: ' . $e->getMessage());
                }
            }
            $this->logError($res
                ? '视频入库成功 视频ID:' . $info['vod_name'] . ' 分类:' . $info['vod_class']
                : '视频入库失败');
        } catch (\Throwable $e) {
            $this->logError($e->getMessage());
        }
    }

    private function secondsToHour($seconds)
    {
        $seconds = (int)$seconds;
        if ($seconds <= 0) {
            return '00:00:00';
        }
        return sprintf('%02d:%02d:%02d', intdiv($seconds, 3600), intdiv($seconds % 3600, 60), $seconds % 60);
    }

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
        $m = 0;
        foreach (($this->_cfg['keyword_blacklist'] ?? []) as $kw) {
            if ($kw !== '' && substr_count($content, $kw) > 0) {
                $m++;
            }
        }
        return $m;
    }
}
