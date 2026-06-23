<?php
namespace app\index\controller;

use app\common\model\HelpCfg;

class Help extends Base
{
    public function __construct()
    {
        parent::__construct();

        if (HelpCfg::get('enabled', '1') === '0') {
            throw new \think\exception\HttpException(404, 'Not Found');
        }
    }

    public function index()
    {
        $cfg = HelpCfg::getAll();

        $this->assign('cfg', $cfg);
        $this->assign('site_name', $cfg['site_name'] ?? ($GLOBALS['config']['site']['site_name'] ?? ''));

        $keys = ['mac10', 'maccms', 'seacms', 'seacms87', 'ff50player', 'player'];
        $files = [];
        foreach ($keys as $key) {
            $files[$key] = is_file(ROOT_PATH . 'upload/help/' . $key . '.zip');
        }
        $this->assign('files', $files);

        return $this->label_fetch('help/index');
    }
}
