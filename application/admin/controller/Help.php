<?php
namespace app\admin\controller;

use think\facade\Config;
use think\facade\Request;
use app\common\model\HelpCfg;

/**
 * 帮助中心控制器
 * 管理播放器资源文件配置及 ZIP 生成
 */
class Help extends Base
{
    public function __construct()
    {
        parent::__construct();
        Config::set(['view_path' => APP_PATH . 'admin/view/'], 'template');
    }

    /**
     * 帮助中心配置首页
     */
    public function index()
    {
        $cfg = HelpCfg::getAll();

        // 扫描已生成的 ZIP 文件列表
        $fileList = [];
        $helpDir = ROOT_PATH . 'upload/help/';
        $knownFiles = ['mac10.zip', 'maccms.zip', 'seacms.zip', 'seacms87.zip', 'ff50player.zip', 'player.zip'];
        foreach ($knownFiles as $fname) {
            $fpath = $helpDir . $fname;
            if (is_file($fpath)) {
                $fileList[$fname] = filemtime($fpath);
            }
        }

        $this->assign('cfg', $cfg);
        $this->assign('file_list', $fileList);
        return $this->fetch('help/index');
    }

    /**
     * 保存配置（POST）
     */
    public function save()
    {
        if (!Request::isPost()) {
            return json(['code' => 0, 'msg' => '非法请求']);
        }

        $fields = ['site_name', 'player_flag', 'site_host', 'site_back_tip', 'api_host',
                   'player_host', 'tg_url', 'player_code', 'notice'];
        $optionalFields = ['player_code', 'notice'];

        $data = [];
        foreach ($fields as $field) {
            $val = (string)Request::post($field, '');
            if (!in_array($field, $optionalFields, true) && $val === '') {
                return json(['code' => 0, 'msg' => '字段 ' . $field . ' 不能为空']);
            }
            $data[$field] = $val;
        }

        HelpCfg::setMulti($data);

        // 若勾选了"保存后自动重新生成"，则立即生成
        $autoRegen = Request::post('auto_regen', '');
        if (!empty($autoRegen)) {
            HelpCfg::generateFiles();
        }

        return json(['code' => 1, 'msg' => '保存成功']);
    }

    /**
     * 立即重新生成所有资源文件（POST）
     */
    public function regen()
    {
        if (!Request::isPost()) {
            return json(['code' => 0, 'msg' => '非法请求']);
        }

        $generated = HelpCfg::generateFiles();

        if (empty($generated)) {
            return json(['code' => 0, 'msg' => '生成失败，请检查目录写入权限']);
        }

        return json(['code' => 1, 'msg' => '已生成：' . implode(', ', $generated), 'data' => $generated]);
    }

    /**
     * 切换启用/禁用状态（POST）
     */
    public function toggleEnabled()
    {
        if (!Request::isPost()) {
            return json(['code' => 0, 'msg' => '非法请求']);
        }

        $current = HelpCfg::get('enabled', '0');
        $newVal  = ($current === '1') ? '0' : '1';
        HelpCfg::set('enabled', $newVal);

        return json([
            'code' => 1,
            'msg'  => $newVal === '1' ? '已开启' : '已关闭',
            'data' => ['enabled' => $newVal],
        ]);
    }
}
