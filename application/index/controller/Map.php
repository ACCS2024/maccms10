<?php
namespace app\index\controller;

class Map extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    public function index()
    {
        // 主题没有 map/index.html 就直接回首页。
        //
        // 站点地图模板是第三方主题的可选项(本仓库自带的 vozy 主题就没有),缺了的话
        // label_fetch 抛 TemplateNotFoundException,而 /map.html 与 /map.xml 恰恰是
        // 搜索引擎会反复来抓的地址 —— 让它 500 比什么都糟。302 回首页,爬虫顺着
        // 首页继续爬,不产生错误页。
        $tplRoot = $GLOBALS['MAC_ROOT_TEMPLATE'] ?? '';
        $suffix  = '.' . ltrim((string)config('view.view_suffix') ?: 'html', '.');
        if ($tplRoot === '' || !is_file($tplRoot . 'map' . DIRECTORY_SEPARATOR . 'index' . $suffix)) {
            return redirect((string)(defined('MAC_PATH') ? MAC_PATH : '/') ?: '/');
        }

        // 站点地图无单一分类上下文,提供安全默认 $obj 供模板「筛选」链接使用
        // (PHP8 下模板引用未定义变量会被 TP8 升级为异常 → 500)
        $this->assign('obj', ['type_id' => 1, 'type_mid' => 1, 'type_name' => '']);
        return $this->label_fetch('map/index');
    }

}
