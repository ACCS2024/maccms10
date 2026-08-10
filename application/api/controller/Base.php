<?php
namespace app\api\controller;
use think\facade\Request;
use app\common\controller\All;
use app\common\util\ApiMeilisearchSuggest;

class Base extends All
{
    public function __construct()
    {
        parent::__construct();
        $this->label_user();
        $config = $GLOBALS['config']['site'];
        $this->assign($config);

        //站点关闭中
        if($config['site_status'] == 0){

        }
    }

    /**
     * 统一搜索建议：Meilisearch + 与列表一致的已发布/回收过滤；无命中时 MySQL LIKE 回退。
     *
     * @param string      $kind    vod|art|actor|topic|role|website|manga
     * @param string|null $urlFlag mac_url_search 第二参数，默认与 $kind 相同
     *
     * @return \think\response\Json
     */
    protected function jsonSuggestByKind(Request $request, $kind, $urlFlag = null)
    {
        if ($GLOBALS['config']['app']['search'] != '1') {
            return json(['code' => 999, 'msg' => lang('suggest_close')]);
        }
        $urlFlag = ($urlFlag !== null && $urlFlag !== '') ? (string)$urlFlag : (string)$kind;
        $param = $request->param();
        $param = mac_search_len_check(array_merge(['wd' => '', 'tag' => '', 'class' => '', 'letter' => '', 'name' => '', 'state' => '', 'level' => '', 'area' => '', 'lang' => '', 'version' => '', 'actor' => '', 'director' => '', 'starsign' => '', 'blood' => ''], $param));
        $wd = mac_filter_xss(trim((string)($param['wd'] ?? '')));
        if ($wd === '') {
            return json(['code' => 1001, 'msg' => '参数错误']);
        }
        $limit = max(1, min(20, intval($param['limit'] ?? 10)));
        $res = ApiMeilisearchSuggest::suggestListDataRes($kind, $wd, $limit);
        // 不要在这里预编码:mac_url() 现在会对落到路径段的变量统一 rawurlencode,
        // 这里再 urlencode 一次会变成双重编码(% → %25),而且 urlencode 把空格编成 +,
        // 在路径段里是字面量加号而不是空格。
        $res['url'] = mac_url_search(['wd' => $wd], $urlFlag);

        return json($res);
    }

}
