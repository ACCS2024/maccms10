<?php
namespace app\api\controller;

use think\facade\Cache;

/**
 * 非凡(feifei) 专用采集接口
 * 路由：api.php/Feifei/vod/
 *
 * 与 Zanpian 输出格式完全一致（老站上两个文件除类名与缓存键前缀外逐字节相同），
 * 之所以并存，是因为下游采集软件按固定的接口路径名请求。这里把实现收在本类，
 * Zanpian 直接继承并只覆盖缓存键前缀，避免两份代码各自漂移。
 *
 * TP5 → TP8 移植要点（输出保持逐字节不变）：
 *  - use think\Cache / think\Controller → think\facade\Cache
 *  - TP5 数组条件 ['in',$v] / ['like',$v] / [['gt',$a],['lt',$b]] → TP8 条件写法
 *  - $where['_string'] 累加前先初始化，避免 PHP 8 未定义索引
 *  - model('vod') / model('Type') 经 common.php 的 shim 仍可用，此处显式用模型类
 */
class Feifei extends Base
{
    /** @var array */
    protected $_param;

    /** 缓存键前缀，子类可覆盖 */
    protected $cachePrefix = 'feifei_api_vod_';

    public function __construct()
    {
        parent::__construct();
        $this->_param = input();
    }

    public function index()
    {
    }

    public function vod()
    {
        if ($GLOBALS['config']['api']['vod']['status'] != 1) {
            echo 'closed';
            exit;
        }

        // 收费模式下的来源授权校验（与老站行为一致）
        if ($GLOBALS['config']['api']['vod']['charge'] == 1) {
            $h = $_SERVER['REMOTE_ADDR'] ?? '';
            if (!$h) {
                echo '域名未授权！';
                exit;
            }
            $auth  = $GLOBALS['config']['api']['vod']['auth'] ?? '';
            $auths = [];
            if (!empty($auth)) {
                $auths = explode('#', $auth);
                foreach ($auths as $k => $v) {
                    $auths[$k] = gethostbyname(trim($v));
                }
            }
            if ($h != 'localhost' && $h != '127.0.0.1' && !in_array($h, $auths)) {
                echo '域名未授权！';
                exit;
            }
        }

        $cache_time = intval($GLOBALS['config']['api']['vod']['cachetime'] ?? 0);
        $cach_name  = $this->cachePrefix . md5(http_build_query($this->_param));
        $html       = Cache::get($cach_name);

        if (empty($html) || $cache_time == 0) {
            $where = [];

            if (!empty($this->_param['ids'] ?? null)) {
                $where['vod_id'] = $this->_param['ids'];
            }
            if (!empty($GLOBALS['config']['api']['vod']['typefilter'])) {
                $where['type_id'] = $GLOBALS['config']['api']['vod']['typefilter'];
            }
            if (!empty($this->_param['t'] ?? null)) {
                if (empty($GLOBALS['config']['api']['vod']['typefilter'])
                    || strpos($GLOBALS['config']['api']['vod']['typefilter'], (string)$this->_param['t']) !== false) {
                    $where['type_id'] = $this->_param['t'];
                }
            }
            if (!empty($this->_param['h'] ?? null)) {
                $todayunix = strtotime(date('Y-m-d', strtotime('+1 days')));
                $tommunix  = strtotime(date('Y-m-d', strtotime('-' . intval($this->_param['h']) . ' hours')));
                $where[]   = ['vod_time', '>', $tommunix];
                $where[]   = ['vod_time', '<', $todayunix];
            }
            if (!empty($this->_param['wd'] ?? null)) {
                $where[] = ['vod_name', 'like', '%' . $this->_param['wd'] . '%'];
            }

            if (empty($GLOBALS['config']['api']['vod']['from']) && !empty($this->_param['from'] ?? null)) {
                $GLOBALS['config']['api']['vod']['from'] = $this->_param['from'];
            }
            if (!empty($GLOBALS['config']['api']['vod']['from'])) {
                $where[] = ['vod_play_from', 'like', '%' . $GLOBALS['config']['api']['vod']['from'] . '%'];
            }
            if (!empty($GLOBALS['config']['api']['vod']['datafilter'])) {
                $where['_string'] = ($where['_string'] ?? '') . ' ' . $GLOBALS['config']['api']['vod']['datafilter'];
            }

            $pg       = max(1, intval($this->_param['pg'] ?? 1));
            $pagesize = intval($GLOBALS['config']['api']['vod']['pagesize']);
            $order    = 'vod_time desc';
            $field    = 'vod_id,vod_name,type_id,"" as type_name,vod_en,vod_time,vod_remarks,vod_play_from,vod_time';

            if (($this->_param['ac'] ?? '') == 'videolist' || ($this->_param['ac'] ?? '') == 'detail') {
                $field = '*';
            }

            // 关键词检索优先走 Meilisearch，未启用/无命中时自动回退上面已构造的 LIKE 条件。
            // 与 Provide / Seacms 保持同一策略：MySQL LIKE 只能匹配连续子串，
            // 而 Meili 索引了拼音、首字母与繁简互换字段，召回明显更全
            // （实测 wd=JKSR：LIKE 142 条，Meili 220 条），且耗时从 ~1.3s 降到 ~50ms。
            $wd    = trim((string)($this->_param['wd'] ?? ''));
            $meili = $wd !== '' ? mac_meili_api_apply('vod', $where, $wd, $pg, $pagesize, $order, 0) : false;

            if ($meili !== false) {
                $res = (new \app\common\model\Vod())->listData($meili[0], $meili[1], 1, $pagesize, 0, $field, 0, 0);
                $res['page'] = $pg;
                if ($meili[2] !== null) {
                    $res['total']     = (int)$meili[2];
                    $res['pagecount'] = $pagesize > 0 ? (int)ceil($meili[2] / $pagesize) : 0;
                }
            } else {
                $res = (new \app\common\model\Vod())->listData($where, $order, $pg, $pagesize, 0, $field, 0);
            }

            if ($res['code'] > 1) {
                echo $res['msg'];
                exit;
            }

            $html = $this->vod_xml($res);
            if ($cache_time > 0) {
                Cache::set($cach_name, $html, $cache_time);
            }
        }

        echo $html;
        exit;
    }

    public function vod_url_deal($urls, $froms, $from, $flag)
    {
        $res_xml  = '';
        $res_json = [];
        $arr1 = explode('$$$', (string)$urls);
        $arr2 = explode('$$$', (string)$froms);
        $arr1count = count($arr1);
        $arr2count = count($arr2);
        for ($i = 0; $i < $arr2count; $i++) {
            if ($arr1count >= $i && isset($arr1[$i])) {
                $arr1[$i] = str_replace('#', '$' . $arr2[$i] . '#', $arr1[$i]);
                if ($from != '') {
                    if ($arr2[$i] == $from) {
                        $res_xml .= '<dd flag="' . $arr2[$i] . '"><![CDATA[' . $arr1[$i] . '$' . $arr2[$i] . ']]></dd>';
                        $res_json[$arr2[$i]] = $arr1[$i];
                    }
                } else {
                    $res_xml .= '<dd flag="' . $arr2[$i] . '"><![CDATA[' . $arr1[$i] . '$' . $arr2[$i] . ']]></dd>';
                    $res_json[$arr2[$i]] = $arr1[$i];
                }
            }
        }
        return $flag == 'xml' ? $res_xml : $res_json;
    }

    public function vod_xml($res)
    {
        $xml  = '<?xml version="1.0" encoding="utf-8"?>';
        $xml .= '<rss version="5.1">';
        $type_list = (new \app\common\model\Type())->getCache('type_list');

        $xml .= '<list page="' . $res['page'] . '" pagecount="' . $res['pagecount']
              . '" pagesize="' . $res['limit'] . '" recordcount="' . $res['total'] . '">';

        foreach ($res['list'] as $k => &$v) {
            $type_info = $type_list[$v['type_id']] ?? ['type_name' => ''];
            $xml .= '<video>';
            $xml .= '<last>' . date('Y-m-d H:i:s', $v['vod_time']) . '</last>';
            $xml .= '<id>' . $v['vod_id'] . '</id>';
            $xml .= '<tid>' . $v['type_id'] . '</tid>';
            $xml .= '<name><![CDATA[' . $v['vod_name'] . ']]></name>';
            $xml .= '<type>' . ($type_info['type_name'] ?? '') . '</type>';

            $pic = (string)($v['vod_pic'] ?? '');
            if (substr($pic, 0, 4) == 'mac:') {
                $v['vod_pic'] = str_replace('mac:', 'http:', $pic);
            } elseif (!empty($pic) && substr($pic, 0, 4) != 'http' && substr($pic, 0, 2) != '//') {
                $v['vod_pic'] = $GLOBALS['config']['api']['vod']['imgurl'] . $pic;
            }

            if (($this->_param['ac'] ?? '') == 'videolist' || ($this->_param['ac'] ?? '') == 'detail') {
                $tempurl = $this->vod_url_deal(
                    $v['vod_play_url'] ?? '', $v['vod_play_from'] ?? '',
                    $GLOBALS['config']['api']['vod']['from'] ?? '', 'xml'
                );
                $xml .= '<keywords>' . ($v['vod_class'] ?? '') . '</keywords>';
                $xml .= '<mcid></mcid>';
                $xml .= '<pic>' . ($v['vod_pic'] ?? '') . '</pic>';
                $xml .= '<lang>' . ($v['vod_lang'] ?? '') . '</lang>';
                $xml .= '<area>' . ($v['vod_area'] ?? '') . '</area>';
                $xml .= '<year>' . ($v['vod_year'] ?? '') . '</year>';
                $xml .= '<state>' . ($v['vod_serial'] ?? '') . '</state>';
                $xml .= '<note><![CDATA[' . ($v['vod_remarks'] ?? '') . ']]></note>';
                $xml .= '<actor><![CDATA[' . ($v['vod_actor'] ?? '') . ']]></actor>';
                $xml .= '<director><![CDATA[' . ($v['vod_director'] ?? '') . ']]></director>';
                $xml .= '<dl>' . $tempurl . '</dl>';
                $xml .= '<des><![CDATA[' . ($v['vod_content'] ?? '') . ']]></des>';
            } else {
                if (!empty($GLOBALS['config']['api']['vod']['from'])) {
                    $xml .= '<dt>' . $GLOBALS['config']['api']['vod']['from'] . '</dt>';
                } else {
                    $xml .= '<dt>' . str_replace('$$$', ',', (string)($v['vod_play_from'] ?? '')) . '</dt>';
                }
                $xml .= '<note><![CDATA[' . ($v['vod_remarks'] ?? '') . ']]></note>';
            }
            $xml .= '</video>';
        }
        unset($v);
        $xml .= '</list>';

        if (($this->_param['ac'] ?? '') != 'videolist' && ($this->_param['ac'] ?? '') != 'detail') {
            $xml .= '<class>';
            $typefilter = explode(',', (string)($GLOBALS['config']['api']['vod']['typefilter'] ?? ''));
            foreach ($type_list as $k => $t) {
                if (($t['type_mid'] ?? 0) == 1) {
                    if (!empty($GLOBALS['config']['api']['vod']['typefilter'])) {
                        if (in_array($t['type_id'], $typefilter)) {
                            $xml .= '<ty id="' . $t['type_id'] . '">' . $t['type_name'] . '</ty>';
                        }
                    } else {
                        $xml .= '<ty id="' . $t['type_id'] . '">' . $t['type_name'] . '</ty>';
                    }
                }
            }
            $xml .= '</class>';
        }

        $xml .= '</rss>';
        return $xml;
    }
}
