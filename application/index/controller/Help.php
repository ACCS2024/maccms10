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

        // M3U8 parse URL shown to visitors: parse_host overrides player_host if set
        $this->assign('parse_host_eff', !empty($cfg['parse_host']) ? $cfg['parse_host'] : ($cfg['player_host'] ?? ''));

        // Newart (news/actor) section
        $this->assign('newart_show', ($cfg['newart_enabled'] ?? '1') !== '0');
        $this->assign('newart_api_host_eff', !empty($cfg['newart_api_host']) ? $cfg['newart_api_host'] : ($cfg['api_host'] ?? ''));

        $keys = ['mac10', 'maccms', 'seacms', 'seacms87', 'ff50player'];
        $files = [];
        foreach ($keys as $key) {
            $files[$key] = is_file(ROOT_PATH . 'upload/help/' . $key . '.zip');
        }
        $this->assign('files', $files);

        return $this->label_fetch('help/index');
    }
}
