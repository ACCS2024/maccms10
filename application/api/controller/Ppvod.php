<?php
namespace app\api\controller;

use think\facade\Db;
use app\common\util\Pinyin;
use app\common\util\PpvodLegacyPayload;

/**
 * 转码机内容入库接口（站点侧对接组件）
 *
 *   POST /api.php/ppvod/ingest?ac=yzm&pass=<interface.pass>      （规范入口）
 *   POST /api.php/yzm/yzmauto?ac=yzm&pass=<interface.pass>       （历史入口，仍可用）
 *   body: 转码服务产出的 JSON（orgfile / suffix / rpath / category / shareid / metadata ...）
 *
 * 【本文件不包含任何站点或基础设施信息】
 * 默认模式下，转码机地址、图床域名、播放域名、播放器标识、分类映射等全部来自后台
 * 「PPVOD 转码入库」配置页（$config['ppvod']，保存在本站
 * application/extra/maccms.php；仓库里那份是占位空值）。
 * 只有显式开启旧 Yzm 兼容的站点会读取报文域名，并在入库前做严格校验。
 * 未启用或配置不完整时接口直接拒绝服务并记日志，绝不使用内置默认值兜底，
 * 以免把某一个部署的地址变成所有部署的默认值。
 */
class Ppvod extends Base
{
    private $_param;

    /** @var array 站点私有配置（application/extra/maccms.php） */
    private $_cfg = [];

    public function __construct()
    {
        parent::__construct();
        $this->_param = input();

        if (($this->_param['ac'] ?? '') !== 'yzm') {
            $this->logError('非法使用此参数，只能是yzm，不可更改');
            $this->jsonExit($this->env(0, 'bad_action'));
        }
        // 安全加固：常量时间比较，与 Receive 一致，杜绝时序侧信道逐字节爆破 interface.pass
        if (!hash_equals((string)($GLOBALS['config']['interface']['pass'] ?? ''), (string)($this->_param['pass'] ?? ''))) {
            $this->logError('入库密码不一致');
            $this->jsonExit($this->env(0, 'bad_pass'));
        }

        // 配置来自后台「PPVOD 转码入库」页（$config['ppvod']，存于本站
        // application/extra/maccms.php —— 该文件在 Begin 中间件的 extra/ 白名单内）。
        $cfg = $GLOBALS['config']['ppvod'] ?? [];
        if (!is_array($cfg) || (string)($cfg['status'] ?? '0') !== '1') {
            $this->logError('PPVOD 入库接口未启用：请在后台「PPVOD 转码入库」中开启');
            $this->jsonExit($this->env(0, 'disabled'));
        }
        $cfg['category_map'] = is_array($cfg['category_map'] ?? null)
            ? array_map('intval', $cfg['category_map'])
            : mac_ppvod_category_map();
        if (!PpvodLegacyPayload::enabled($cfg) && (empty($cfg['play_domain']) || empty($cfg['pic_domain']) || empty($cfg['category_map']))) {
            $this->logError('PPVOD 配置不完整：播放域名 / 图床域名 / 分类映射均为必填');
            $this->jsonExit($this->env(0, 'config_incomplete'));
        }
        if (!is_array($cfg['keyword_blacklist'] ?? null)) {
            $cfg['keyword_blacklist'] = array_values(array_filter(array_map(
                'trim', preg_split('/[\r\n]+/', (string)($cfg['keyword_blacklist'] ?? ''))
            )));
        }
        $this->_cfg = $cfg;
    }

    /**
     * 统一入库回执信封。
     *
     * 历史顽疾：yzmauto 的每一条路径都 `return;`（HTTP 200 + 0 字节），推送方
     * 无从区分「入库成功 / 同名已存在 / 分类未知 / 被安全闸拒绝 / 密码错」，只能靠
     * 猜——于是转码机侧把一整批推送全标「成功」，本站实际一条没进，日志上还看不出。
     *
     * 契约（HTTP 状态码一律 200，对接方只看 body.code）：
     *   code=1  内容此刻确实在本站库中且处于活跃态（本次插入，或同名已存在且未在回收站）
     *           → 推送方判「已送达」，不必重投。
     *   code=0  未入库/不可见，msg 为确定原因：
     *           bad_action/bad_pass/disabled/config_incomplete/config_error/empty_body/
     *           bad_json/blocked_keyword/bad_category/rejected/db_error/db_exception
     *   备注：同名判重只看活跃记录，回收站里的同名内容视同不存在 → 重推直接 inserted（见类注释）。
     *           → 推送方据 msg 告警或修配置。
     * 转码机旧版本忽略响应体，新增回执向后兼容。
     */
    private function env(int $code, string $msg, array $extra = []): array
    {
        return array_merge(['code' => $code, 'msg' => $msg], $extra);
    }

    /**
     * 构造函数阶段没有「返回响应」通道（其返回值不会被框架渲染），故手动输出 JSON 后 exit——
     * 与 action 内 `return json($this->env(...))` 产出完全同构的 body，
     * 保证无论在哪一道闸被拦下，对接方都拿到结构一致的回执。
     */
    private function jsonExit(array $env): void
    {
        if (!headers_sent()) {
            header('Content-Type: application/json; charset=utf-8');
        }
        echo json_encode($env, JSON_UNESCAPED_UNICODE);
        exit;
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
            return json($this->env(0, 'config_error'));
        }

        $task = file_get_contents('php://input');
        if (!$task) {
            $this->logError('未获取到对应视频信息');
            return json($this->env(0, 'empty_body'));
        }
        $arr = json_decode($task, true);
        $this->logError($task);
        if (!$arr) {
            return json($this->env(0, 'bad_json'));
        }

        $c = $this->_cfg;

        $info = [];
        $info['vod_name'] = str_replace('.' . ($arr['suffix'] ?? ''), '', (string)($arr['orgfile'] ?? ''));

        $rpath      = (string)($arr['rpath'] ?? '');
        $videopath  = str_replace('\\', '/', $rpath);
        $videorpath = substr_count($videopath, '/') >= 2 ? $videopath : '/' . $videopath;

        $legacy = null;
        if (PpvodLegacyPayload::enabled($c)) {
            try {
                $legacy = PpvodLegacyPayload::build($arr, $c, $collect, $c['category_map']);
                $videorpath = $legacy['video_path'];
            } catch (\InvalidArgumentException $e) {
                $field = $e->getMessage();
                $this->logError('旧版 Yzm 兼容报文校验失败，字段:' . $field);
                return json($this->env(0, 'rejected', ['field' => $field]));
            }
        }

        if ($legacy !== null) {
            $info['vod_pic'] = $legacy['vod_pic'];
        } else {
            // 先让图床把源站的图抓过去，再把 vod_pic 指向图床
            if (!empty($c['transcoder_url'])) {
                $this->fetchImageWithTryCatch(rtrim($c['transcoder_url'], '/') . $rpath . '/1.jpg');
            }
            $info['vod_pic'] = rtrim($c['pic_domain'], '/') . $rpath . '/1.jpg';
        }

        if ($this->transgress_keyword($info['vod_name']) > 0) {
            $this->logError('内容含有非法词汇,无法入库 视频ID:' . $info['vod_name']);
            return json($this->env(0, 'blocked_keyword'));
        }

        $info['vod_en']        = Pinyin::get($info['vod_name']);
        $info['vod_letter']    = strtoupper(substr($info['vod_en'], 0, 1));
        $info['vod_pic_thumb'] = $info['vod_pic'];
        $info['vod_time_add']  = time();
        $info['vod_time']      = time();
        $info['vod_duration']  = $this->secondsToHour($arr['metadata']['time'] ?? 0);
        $info['vod_play_from'] = $c['player_flag'];

        if ($legacy !== null) {
            $info['vod_play_url'] = $legacy['vod_play_url'];
        } else {
            $playname = $c['play_name'] ?? '第1集';
            $play     = rtrim($c['play_domain'], '/');
            $m3u8     = $playname . '$' . $play . $videorpath . '/index.m3u8';
            $share    = $playname . '$' . $play . '/share/' . ($arr['shareid'] ?? '');
            $info['vod_play_url'] = (($c['addr_mode'] ?? 'm3u8') === 'all') ? ($m3u8 . '$$$' . $m3u8) : $m3u8;
        }

        $info['vod_blurb']       = $info['vod_name'];
        $info['vod_content']     = $info['vod_name'];
        $info['vod_total']       = '1';
        $info['vod_serial']      = '1';
        $info['vod_isend']       = '1';
        $info['vod_pubdate']     = date('Y-m-d');
        $info['vod_year']        = date('Y');
        $info['vod_status']      = $legacy !== null ? $legacy['vod_status'] : (int)($c['default_status'] ?? 0);
        $info['vod_down_url']    = $legacy !== null ? $legacy['vod_down_url'] : $share;
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

        // 默认模式严格拒绝未知分类；旧版兼容模式复现 Yzm.php 的兜底栏目行为。
        if ($legacy !== null) {
            $info['type_id'] = $legacy['type_id'];
        } elseif (!isset($c['category_map'][$category])) {
            $this->logError('视频入库失败：未知分类 ' . $category);
            return json($this->env(0, 'bad_category', ['category' => $category]));
        } else {
            $info['type_id'] = (int)$c['category_map'][$category];
        }

        try {
            // 同名判重 —— 严格遵循全系统「回收站记录视同不存在」的约定（见
            // RecycleBinTrait::mergeRecycleWhere 默认 active 模式：正常操作只认
            // vod_recycle_time=0 的行）。老实现用裸 Db::name('vod') 且【未】排除回收站记录，
            // 于是「删进回收站的同名内容」把 vod_name 永久占住、重推被静默跳过 —— 内容既不可见
            // 又推不回（本次线上事故根因：最新 150 条被批量移进回收站后既看不到又推不回、后台
            // 又没有明显回收站入口，彻底卡死）。
            //
            // 这里显式 where('vod_recycle_time',0)：回收站里的同名记录一律【视为不存在】，
            // 重推直接落到下面的 insert，生成一条全新的活跃记录 —— 与采集入库应有行为、以及
            // WordPress「trash 掉再导入=生成新内容、旧的留在回收站」完全一致；旧的回收记录原样
            // 保留在回收站，尊重管理员对那一行的删除。vod_repeat 判重本身也带 recycle=0 过滤，
            // 故活跃行与回收行同名共存不会被误判为重复。
            // 注意：不可拼裸 SQL —— vod_name 直接来自外部 JSON 的 orgfile。
            $exists = Db::name('vod')->field('vod_id,vod_status')
                ->where('vod_name', $info['vod_name'])
                ->where('vod_recycle_time', 0)
                ->find();
            if ($exists) {
                $state = (int)($exists['vod_status'] ?? 0) === 1 ? 'published' : 'pending';
                $this->logError(sprintf(
                    '跳过：已存在同名【活跃】视频 vod_id=%d（%s）。视频名:%s',
                    (int)$exists['vod_id'], $state, $info['vod_name']
                ));
                return json($this->env(1, 'duplicate', ['vod_id' => (int)$exists['vod_id'], 'state' => $state]));
            }
            // 【安全闸】纵深防御：ingest 的 play_url/pic 虽多由服务端配置拼装，但 rpath、
            // 推送方给的字段理论上可夹带注入。与 receive/vod 同一道综合判据，命中即拒绝入库。
            if (($injField = mac_vod_has_injection($info)) !== '') {
                $this->logError("拒绝：字段 {$injField} 含注入特征，视频名:" . ($info['vod_name'] ?? ''));
                return json($this->env(0, 'rejected', ['field' => $injField]));
            }
            // insertGetId 直接取自增 id。【不可】再用 where('vod_name')->value('vod_id') 反查：
            // 判重已排除回收站记录、允许「回收站同名行(更早、id 更小) + 新活跃行」共存，按名反查
            // 会命中那条更早的回收站行 —— 返回错的 vod_id，且 afterVodSave 会把它当已回收从索引
            // 移除，结果新入库的活跃行反而没进搜索索引。
            $newId = (int)Db::name('vod')->insertGetId($info);
            if ($newId <= 0) {
                $this->logError('视频入库失败');
                return json($this->env(0, 'db_error'));
            }
            // 增量同步搜索索引。本控制器为保持与老站一致的字段处理，是直接 Db::insert 而非走
            // Vod::saveData()，因此不会自动触发 MeilisearchSync —— 不显式调用的话，转码机推进来的
            // 内容要等下一次全量重建才可被搜索到。afterVodSave 内部会按 vod_status / vod_recycle_time
            // 判断（未发布则从索引移除），故无论 default_status 是 0 还是 1，这里调用都正确。
            try {
                \app\common\util\MeilisearchSync::afterVodSave($newId);
            } catch (\Throwable $e) {
                // 索引同步失败不应影响入库结果
                $this->logError('Meili 同步失败: ' . $e->getMessage());
            }
            $this->logError('视频入库成功 视频ID:' . $info['vod_name'] . ' 分类:' . $info['vod_class']);
            return json($this->env(1, 'inserted', ['vod_id' => $newId]));
        } catch (\Throwable $e) {
            $this->logError($e->getMessage());
            return json($this->env(0, 'db_exception'));
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
        $runtime = defined('RUNTIME_PATH')
            ? RUNTIME_PATH
            : rtrim((defined('ROOT_PATH') ? ROOT_PATH : getcwd()), '/\\') . DIRECTORY_SEPARATOR . 'runtime' . DIRECTORY_SEPARATOR;
        $dir = rtrim($runtime, '/\\') . DIRECTORY_SEPARATOR . 'api' . DIRECTORY_SEPARATOR . 'ppvod' . DIRECTORY_SEPARATOR;
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        @error_log(date('[Y-m-d H:i:s]') . ' - ' . $content . "\n", 3, $dir . date('Y-m-d') . '.log');
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
