<?php
namespace app\index\controller;

use app\common\model\Rep as RepModel;

class Rep extends Base
{
    public function __construct()
    {
        parent::__construct();
        $cfg = $GLOBALS['config']['rep'] ?? [];
        if (($cfg['enabled'] ?? '1') === '0') {
            throw new \think\exception\HttpException(404, 'Not Found');
        }
    }

    public function index()
    {
        $list = RepModel::activeList();
        $this->assign('list', $list);
        $this->assign('site_name', $GLOBALS['config']['site']['site_name'] ?? 'MacCMS');
        return $this->label_fetch('rep/index');
    }
}
