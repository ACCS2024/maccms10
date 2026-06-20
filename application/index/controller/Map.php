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
        // 站点地图无单一分类上下文,提供安全默认 $obj 供模板「筛选」链接使用
        // (PHP8 下模板引用未定义变量会被 TP8 升级为异常 → 500)
        $this->assign('obj', ['type_id' => 1, 'type_mid' => 1, 'type_name' => '']);
        return $this->label_fetch('map/index');
    }

}
