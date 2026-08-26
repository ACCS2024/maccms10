<?php
namespace app\api\controller;
use think\facade\Cache;

/**
 * SeaCMS 专用采集接口
 * 路由：api.php/Seacms/vod/
 *
 * XML 格式与 SeaCMS 采集器约定一致（episode URL 末尾追加 $flag 标识符）。
 * wd 搜索：优先 Meilisearch，无命中/未启用时自动回退 MySQL LIKE，与 Provide 策略相同。
 */
class Seacms extends Base
{
    /** @var array */
    private $_param;

    public function __construct()
    {
        parent::__construct();
        $this->_param = \think\facade\Request::param();
    }

    public function index() {}

    public function vod()
    {
        if ($GLOBALS['config']['api']['vod']['status'] != 1) {
            echo 'closed';
            exit;
        }

        if ($GLOBALS['config']['api']['vod']['charge'] == 1) {
            $h = $_SERVER['REMOTE_ADDR'] ?? '';
            if (!$h) {
                echo lang('api/auth_err');
                exit;
            }
            $this->checkDomainAuth($GLOBALS['config']['api']['vod']['auth']);
        }

        $cache_time = intval($GLOBALS['config']['api']['vod']['cachetime']);
        $cache_name = $GLOBALS['config']['app']['cache_flag'] . '_seacms_api_vod_' . md5(http_build_query($this->_param));
        $html = Cache::get($cache_name);

        if (empty($html) || $cache_time == 0) {

            $where = [];

            // ids 精确查
            if (!empty($this->_param['ids'] ?? null)) {
                $where['vod_id'] = $this->_param['ids'];
            }

            // 分类过滤（后台配置优先）
            if (!empty($GLOBALS['config']['api']['vod']['typefilter'])) {
                $where['type_id'] = $GLOBALS['config']['api']['vod']['typefilter'];
            }

            // t 参数：分类 id
            if (!empty($this->_param['t'] ?? null)) {
                if (
                    empty($GLOBALS['config']['api']['vod']['typefilter']) ||
                    strpos($GLOBALS['config']['api']['vod']['typefilter'], (string)($this->_param['t'])) !== false
                ) {
                    $where['type_id'] = $this->_param['t'];
                }
            }

            // h 参数：最近 N 小时
            if (!empty($this->_param['h'] ?? null)) {
                $todayunix = strtotime(date('Y-m-d', strtotime('+1 days')));
                $tommunix  = strtotime(date('Y-m-d H:i:s', strtotime('-' . intval($this->_param['h']) . ' hours')));
                $where[] = ['vod_time', '>', $tommunix];
                $where[] = ['vod_time', '<', $todayunix];
            }

            // wd 关键词：先加 LIKE 确保回退可用，再尝试 Meilisearch
            $wd = trim((string)($this->_param['wd'] ?? ''));
            if ($wd !== '') {
                $where[] = ['vod_name', 'like', '%' . $wd . '%'];
            }

            // from：播放源过滤
            if (empty($GLOBALS['config']['api']['vod']['from']) && !empty($this->_param['from'] ?? null)) {
                $GLOBALS['config']['api']['vod']['from'] = $this->_param['from'];
            }
            if (!empty($GLOBALS['config']['api']['vod']['from'])) {
                $from_list = array_filter(array_unique(
                    explode(',', trim($GLOBALS['config']['api']['vod']['from']))
                ));
                if (!empty($from_list)) {
                    $patterns = array_map(fn($f) => '%' . trim($f) . '%', $from_list);
                    $where[] = function ($q) use ($patterns) {
                        foreach ($patterns as $i => $p) {
                            $i === 0 ? $q->whereLike('vod_play_from', $p) : $q->whereLike('vod_play_from', $p, 'OR');
                        }
                    };
                }
            }

            // 后台额外 SQL 过滤
            if (!empty($GLOBALS['config']['api']['vod']['datafilter'])) {
                $where['_string'] = ($where['_string'] ?? '') . ' ' . $GLOBALS['config']['api']['vod']['datafilter'];
            }

            $pg       = max(1, intval($this->_param['pg'] ?? 1));
            $pagesize = intval($GLOBALS['config']['api']['vod']['pagesize']);
            if (!empty($this->_param['pagesize'] ?? null) && intval($this->_param['pagesize']) > 0) {
                $pagesize = min(intval($this->_param['pagesize']), 100);
            }

            $order = 'vod_time desc';
            $field = 'vod_id,vod_name,type_id,"" as type_name,vod_en,vod_time,vod_remarks,vod_play_from,vod_play_url,vod_time,vod_pic,vod_area,vod_lang,vod_year,vod_serial,vod_actor,vod_director,vod_content';

            if (($this->_param['ac'] ?? '') == 'videolist' || ($this->_param['ac'] ?? '') == 'detail') {
                $field = '*';
            }

            // Meilisearch 双轨：命中则替换 where+order+total；未命中/未启用自动用 LIKE 回退
            $meili = mac_meili_api_apply('vod', $where, $wd, $pg, $pagesize, $order, 0);

            if ($meili !== false) {
                $res           = (new \app\common\model\Vod())->listData($meili[0], $meili[1], 1, $pagesize, 0, $field, 0, 0);
                $res['page']   = $pg;
                if ($meili[2] !== null) {
                    $res['total']     = (int)$meili[2];
                    $res['pagecount'] = $pagesize > 0 ? (int)ceil($meili[2] / $pagesize) : 0;
                }
            } else {
                $res = (new \app\common\model\Vod())->listData($where, $order, $pg, $pagesize, 0, $field, 0);
            }

            $html = mac_filter_tags($this->build_xml($res));

            if ($cache_time > 0) {
                Cache::set($cache_name, $html, $cache_time);
            }
        }

        header('Content-Type: text/xml; charset=utf-8');
        echo $html;
        exit;
    }

    /**
     * 处理播放 URL，追加 $flag 标识（SeaCMS 格式要求）。
     * SeaCMS 解析器用 `episode_url$flag` 识别播放源，与标准 Provide 格式不同。
     */
    private function url_deal(string $urls, string $froms, string $from, string $flag): string
    {
        $res_xml = '';
        $arr_url  = explode('$$$', $urls);
        $arr_from = explode('$$$', $froms);
        $count    = count($arr_from);

        for ($i = 0; $i < $count; $i++) {
            if (!isset($arr_url[$i])) {
                continue;
            }
            $cur_from = $arr_from[$i];
            // 在每集 URL 内的 # 分隔符前追加 $flag，再在整段末尾追加 $flag
            $cur_url = str_replace('#', '$' . $cur_from . '#', $arr_url[$i]);

            if ($from !== '') {
                if ($cur_from !== $from && !str_contains($from, $cur_from)) {
                    continue;
                }
            }
            $res_xml .= '<dd flag="' . $cur_from . '"><![CDATA[' . $cur_url . '$' . $cur_from . ']]></dd>';
        }

        return $res_xml;
    }

    /**
     * 生成 SeaCMS 格式 XML 输出。
     */
    private function build_xml(array $res): string
    {
        $type_list = (new \app\common\model\Type())->getCache('type_list');
        $from_cfg  = (string)($GLOBALS['config']['api']['vod']['from'] ?? '');
        $imgurl    = (string)($GLOBALS['config']['api']['vod']['imgurl'] ?? '');
        $ac        = (string)($this->_param['ac'] ?? '');
        $is_detail = ($ac === 'videolist' || $ac === 'detail');

        $xml  = '<?xml version="1.0" encoding="utf-8"?>';
        $xml .= '<rss version="5.1">';
        $xml .= '<list'
            . ' page="'        . intval($res['page'])      . '"'
            . ' pagecount="'   . intval($res['pagecount']) . '"'
            . ' pagesize="'    . intval($res['limit'])     . '"'
            . ' recordcount="' . intval($res['total'])     . '"'
            . '>';

        foreach ($res['list'] as &$v) {
            $type_name = $type_list[$v['type_id']]['type_name'] ?? '';

            // 封面地址处理
            $pic = (string)($v['vod_pic'] ?? '');
            if (str_starts_with($pic, 'mac:')) {
                $pic = str_replace('mac:', self::imgUrlProtocol('vod'), $pic);
            } elseif ($pic !== '' && !str_starts_with($pic, 'http') && !str_starts_with($pic, '//')) {
                $pic = $imgurl . $pic;
            }

            $xml .= '<video>';
            $xml .= '<last>'  . date('Y-m-d H:i:s', intval($v['vod_time'])) . '</last>';
            $xml .= '<id>'    . intval($v['vod_id'])  . '</id>';
            $xml .= '<tid>'   . intval($v['type_id']) . '</tid>';
            $xml .= '<name><![CDATA[' . ($v['vod_name'] ?? '') . ']]></name>';
            $xml .= '<type>'  . htmlspecialchars($type_name) . '</type>';

            if ($is_detail) {
                $dl   = $this->url_deal(
                    (string)($v['vod_play_url']  ?? ''),
                    (string)($v['vod_play_from'] ?? ''),
                    $from_cfg,
                    'xml'
                );
                $xml .= '<pic>'    . $pic                             . '</pic>';
                $xml .= '<lang>'   . htmlspecialchars($v['vod_lang']     ?? '') . '</lang>';
                $xml .= '<area>'   . htmlspecialchars($v['vod_area']     ?? '') . '</area>';
                $xml .= '<year>'   . intval($v['vod_year'] ?? 0)               . '</year>';
                $xml .= '<state><![CDATA['  . ($v['vod_serial']   ?? '') . ']]></state>';
                $xml .= '<note><![CDATA['   . ($v['vod_remarks']  ?? '') . ']]></note>';
                $xml .= '<actor><![CDATA['  . ($v['vod_actor']    ?? '') . ']]></actor>';
                $xml .= '<director><![CDATA[' . ($v['vod_director'] ?? '') . ']]></director>';
                $xml .= '<dl>'     . $dl                                       . '</dl>';
                $xml .= '<des><![CDATA['    . ($v['vod_content']  ?? '') . ']]></des>';
            } else {
                $dt = $from_cfg !== ''
                    ? $from_cfg
                    : str_replace('$$$', ',', (string)($v['vod_play_from'] ?? ''));
                $xml .= '<dt>'    . htmlspecialchars($dt)               . '</dt>';
                $xml .= '<note><![CDATA[' . ($v['vod_remarks'] ?? '') . ']]></note>';
            }

            $xml .= '</video>';
        }
        unset($v);

        $xml .= '</list>';

        // 非 detail 模式附带分类列表
        if (!$is_detail) {
            $typefilter = array_filter(explode(',', (string)($GLOBALS['config']['api']['vod']['typefilter'] ?? '')));
            $xml .= '<class>';
            foreach ($type_list as &$t) {
                if (($t['type_mid'] ?? 0) != 1) {
                    continue;
                }
                if (!empty($typefilter) && !in_array($t['type_id'], $typefilter)) {
                    continue;
                }
                $xml .= '<ty id="' . intval($t['type_id']) . '">' . htmlspecialchars($t['type_name']) . '</ty>';
            }
            unset($t);
            $xml .= '</class>';
        }

        $xml .= '</rss>';
        return $xml;
    }
    /**
     * mac:// 前缀图片的协议还原。
     *
     * 原实现调用 $this->getImgUrlProtocol()，但那是 Provide 的 private 方法，
     * Seacms 继承的是 Base，运行时必然 Call to undefined method ——
     * 只有当结果集里出现 mac: 前缀的 vod_pic 时才触发，所以前几页正常、
     * 翻到含老数据的页面（如 ac=list&pg=9113）直接 500。
     * 这里补上同语义实现，避免再跨类依赖私有方法。
     */
    private static function imgUrlProtocol(string $key): string
    {
        $default = ($GLOBALS['config']['upload']['protocol'] ?? 'http') . ':';
        $imgurl  = $GLOBALS['config']['api'][$key]['imgurl'] ?? null;
        if ($imgurl === null) {
            return $default;
        }
        return substr($imgurl, 0, 5) === 'https' ? 'https:' : $default;
    }
}
