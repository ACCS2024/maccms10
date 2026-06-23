<?php
namespace app\admin\controller;

use app\common\model\Rep as RepModel;
use think\facade\Config;
use think\facade\Db;
use think\facade\Request;

class Rep extends Base
{
    private static $typeMap = [
        '文章图片替换' => ['art'  => ['art_pic', 'art_content']],
        '视频封面替换' => ['vod'  => ['vod_pic']],
        '视频播放地址' => ['vod'  => ['vod_play_url']],
        '播放器替换'   => ['vod'  => ['vod_play_from', 'vod_play_server']],
        '域名替换'     => ['vod'  => ['vod_play_url', 'vod_pic'], 'art' => ['art_content', 'art_pic']],
    ];

    public function __construct()
    {
        parent::__construct();
        Config::set(['view_path' => APP_PATH . 'admin/view/'], 'template');
    }

    public function index()
    {
        $list    = RepModel::allList();
        $enabled = $GLOBALS['config']['rep']['enabled'] ?? '1';
        $this->assign('list', $list);
        $this->assign('rep_enabled', $enabled);
        $this->assign('types', array_keys(self::$typeMap));
        return $this->fetch('rep/index');
    }

    public function add()
    {
        $param = Request::post();
        $type  = trim($param['rep_type'] ?? '');
        $orig  = trim($param['rep_original'] ?? '');
        $rep   = trim($param['rep_replacement'] ?? '');
        $note  = trim($param['rep_note'] ?? '');

        if (empty($type) || empty($orig) || empty($rep)) {
            return json(['code' => 0, 'msg' => '参数不完整']);
        }

        RepModel::create([
            'rep_type'        => $type,
            'rep_original'    => $orig,
            'rep_replacement' => $rep,
            'rep_note'        => $note,
            'rep_status'      => 1,
            'rep_applied'     => 0,
            'rep_applied_time'=> 0,
            'rep_create_time' => time(),
        ]);

        return json(['code' => 1, 'msg' => '添加成功']);
    }

    public function del()
    {
        $ids = Request::post('ids');
        if (empty($ids)) {
            return json(['code' => 0, 'msg' => '参数错误']);
        }
        if (!is_array($ids)) {
            $ids = explode(',', $ids);
        }
        $ids = array_filter(array_map('intval', $ids));
        if (empty($ids)) {
            return json(['code' => 0, 'msg' => '参数错误']);
        }
        RepModel::destroy($ids);
        return json(['code' => 1, 'msg' => '删除成功']);
    }

    public function toggle()
    {
        $id = intval(Request::post('id'));
        if (!$id) {
            return json(['code' => 0, 'msg' => '参数错误']);
        }
        $row = RepModel::find($id);
        if (!$row) {
            return json(['code' => 0, 'msg' => '记录不存在']);
        }
        $row->rep_status = $row->rep_status ? 0 : 1;
        $row->save();
        return json(['code' => 1, 'status' => $row->rep_status, 'msg' => $row->rep_status ? '已显示' : '已隐藏']);
    }

    public function toggleEnabled()
    {
        $configFile = APP_PATH . 'extra/maccms.php';
        $config     = include $configFile;
        $current    = $config['rep']['enabled'] ?? '1';
        $config['rep']['enabled'] = ($current === '1') ? '0' : '1';
        file_put_contents($configFile, '<?php' . "\nreturn " . var_export($config, true) . ";\n");
        $GLOBALS['config']['rep'] = $config['rep'];
        return json(['code' => 1, 'enabled' => $config['rep']['enabled'], 'msg' => $config['rep']['enabled'] === '1' ? '已开启' : '已关闭']);
    }

    public function execute()
    {
        $id = intval(Request::post('id'));
        if (!$id) {
            return json(['code' => 0, 'msg' => '参数错误']);
        }
        $row = RepModel::find($id);
        if (!$row) {
            return json(['code' => 0, 'msg' => '记录不存在']);
        }

        $type  = $row->rep_type;
        $orig  = $row->rep_original;
        $repl  = $row->rep_replacement;
        $map   = self::$typeMap[$type] ?? null;

        if (!$map) {
            return json(['code' => 0, 'msg' => "类型「{$type}」不支持自动执行，请手动处理"]);
        }

        $prefix  = config('database.connections.mysql.prefix');
        $results = [];
        try {
            foreach ($map as $table => $fields) {
                foreach ($fields as $field) {
                    $count = Db::name($table)->where($field, 'like', '%' . $orig . '%')->count();
                    if ($count > 0) {
                        Db::execute(
                            "UPDATE `{$prefix}{$table}` SET `{$field}` = REPLACE(`{$field}`, ?, ?) WHERE `{$field}` LIKE ?",
                            [$orig, $repl, '%' . $orig . '%']
                        );
                        $results[] = "mac_{$table}.{$field}: 替换 {$count} 条";
                    } else {
                        $results[] = "mac_{$table}.{$field}: 未找到匹配";
                    }
                }
            }
            $row->rep_applied      = 1;
            $row->rep_applied_time = time();
            $row->save();
            return json(['code' => 1, 'msg' => implode('；', $results)]);
        } catch (\Exception $e) {
            return json(['code' => 0, 'msg' => '执行失败：' . $e->getMessage()]);
        }
    }
}
