<?php
namespace app\admin\controller;

use app\common\model\Rep as RepModel;
use think\facade\Config;
use think\facade\Db;
use think\facade\Request;

class Rep extends Base
{
    public function __construct()
    {
        parent::__construct();
        // TP8 的视图配置组名是 'view';'template' 是 TP5 的旧组名,全仓没有任何读取点,
        // 写进去等于空操作。这五处今天之所以没出事,只是因为 AppInit 对
        // ENTRANCE==='admin' 无条件把 view.view_path 置空,think-view 恰好回落到
        // application/admin/view/ —— 与这行想指定的目录相同。一旦 AppInit 那个
        // 分支改成有条件的(债务方案 S5 正打算这么做),这五个页面会静默改渲染前台
        // 主题模板。把组名修正为 'view',让这行真正承担它声称的职责。
        Config::set(['view_path' => APP_PATH . 'admin/view/'], 'view');
    }

    public function index()
    {
        $list    = RepModel::allList();
        $enabled = $GLOBALS['config']['rep']['enabled'] ?? '1';
        $this->assign('list', $list);
        $this->assign('rep_enabled', $enabled);
        $this->assign('types', array_keys(RepModel::$typeMap));
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
        if (!array_key_exists($type, RepModel::$typeMap)) {
            return json(['code' => 0, 'msg' => '不支持的替换类型']);
        }

        RepModel::create([
            'rep_type'         => $type,
            'rep_original'     => $orig,
            'rep_replacement'  => $rep,
            'rep_note'         => $note,
            'rep_status'       => 1,
            'rep_applied'      => 0,
            'rep_applied_time' => 0,
            'rep_create_time'  => time(),
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
        $ids = array_values(array_filter(array_map('intval', $ids)));
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

        // Atomic read-modify-write with exclusive lock
        $fp = fopen($configFile, 'r+');
        if (!$fp) {
            return json(['code' => 0, 'msg' => '配置文件不可写']);
        }
        flock($fp, LOCK_EX);
        $config  = include $configFile;
        $current = $config['rep']['enabled'] ?? '1';
        $config['rep']['enabled'] = ($current === '1') ? '0' : '1';
        $content = '<?php' . "\nreturn " . var_export($config, true) . ";\n";
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, $content);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);

        $GLOBALS['config']['rep'] = $config['rep'];
        $newState = $config['rep']['enabled'];
        return json(['code' => 1, 'enabled' => $newState, 'msg' => $newState === '1' ? '已开启' : '已关闭']);
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

        $type = $row->rep_type;
        $orig = $row->rep_original;
        $repl = $row->rep_replacement;
        $map  = RepModel::$typeMap[$type] ?? null;

        if (!$map) {
            return json(['code' => 0, 'msg' => "类型「{$type}」不支持自动执行，请手动处理"]);
        }

        $prefix  = config('database.connections.mysql.prefix');
        $results = [];
        try {
            foreach ($map as $table => $fields) {
                foreach ($fields as $field) {
                    $affected = Db::execute(
                        "UPDATE `{$prefix}{$table}` SET `{$field}` = REPLACE(`{$field}`, ?, ?) WHERE `{$field}` LIKE ?",
                        [$orig, $repl, '%' . $orig . '%']
                    );
                    $results[] = "{$prefix}{$table}.{$field}: 替换 {$affected} 条";
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
