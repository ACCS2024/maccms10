<?php
namespace app\admin\controller;
use app\common\controller\All;
use app\common\util\BulkTableIo;
use think\facade\Cache;
use app\common\util\Dir;
use think\facade\Db;

class Base extends All
{
    var $_admin;
    var $_pagesize;
    var $_makesize;

    public function __construct()
    {
        parent::__construct();

        // 校验Update.php文件完整性；放行 Update 控制器自身，避免 hash 失配时升级 UI 也被锁死
        if ($this->_cl != 'Update') {
            $update_file = APP_PATH . 'admin/controller/Update.php';
            $expected_hash = config('version.update_hash');
            if (!empty($expected_hash) && is_file($update_file) && md5_file($update_file) !== $expected_hash) {
                throw new \think\exception\HttpResponseException(\think\Response::create(lang('admin/update/core_file_error')));
            }
        }

        // 安全加固:本地库结构自动迁移(幂等、标记守卫)。必须在登录/口令rehash之前执行,
        // 否则旧库 char(32) 列无法容纳 bcrypt 哈希导致首次登录写入失败。
        mac_security_auto_migrate();
        // 性能:Meili 索引设置自动同步(仅 Meili 启用时;按 payload 哈希版本一次性应用,不阻断、不联网)
        mac_meili_settings_auto_sync();

        //判断用户登录状态
        // 定时任务放行:授权由【真正做过校验的代码路径】显式授予 ——
        // app\api\controller\Timming::index() 在通过「本机 CLI 或 token 正确」的闸门之后
        // 才 define(MAC_TIMMING_AUTHORIZED)。
        //
        // 上游版本这里比对的是 $this->_cl=='Timming',即从 URL 里的控制器名反推身份;
        // 之后为堵这个洞改成比对真实类名 $real_class=='Timming',但 cron 实例化的是
        // Collect/Make/Cj/Index/Urlsend,真实类名永远不是 Timming —— 该分支从此不可达,
        // 定时任务全部落进 else 分支被判「未登录」。改为显式常量后两个问题一起消失:
        // 不可伪造(常量只由过闸后的那段代码定义),也不再误伤 cron。
        if(in_array($this->_cl,['Index']) && in_array($this->_ac,['login'])) {

        }
        elseif(ENTRANCE=='api' && defined('MAC_TIMMING_AUTHORIZED') && MAC_TIMMING_AUTHORIZED === true){

        }
        else {
            $res = (new \app\common\model\Admin())->checkLogin();
            if ($res['code'] > 1) {
                // TP8:构造函数的返回值会被忽略,必须 throw HttpResponseException 才能真正
                // 中断请求。否则 `return redirect()` 仅退出构造、动作仍会执行 → 鉴权被绕过。
                if(ENTRANCE=='api'){
                    throw new \think\exception\HttpResponseException(json(['code'=>1009,'msg'=>'not login']));
                }
                throw new \think\exception\HttpResponseException(redirect((string) url('index/login')));
            }
            $this->_admin = $res['info'];
            $this->_pagesize = $GLOBALS['config']['app']['pagesize'];
            $this->_makesize = $GLOBALS['config']['app']['makesize'];

            if(!$this->check_auth($this->_cl,$this->_ac)){
                // 同理:error() 在非 AJAX 下已 throw;AJAX 下返回 json,需显式 throw 才能中断,
                // 避免无权限的 AJAX 请求继续执行动作。
                throw new \think\exception\HttpResponseException($this->error(lang('permission_denied')));
            }
        }
        $this->assign('cl',$this->_cl);
        $this->assign('MAC_VERSION',config('version.code') ?? '');
    }

    /**
     * 后台模板渲染:在渲染前重新注入后台公共变量。
     * TP8 下构造函数期的 View::assign 未能稳定保留到 fetch(动作期 assign 正常),
     * 故在此统一兜底,确保 public/head.html 等公共模板所需变量始终存在。
     */
    protected function fetch(string $template = '', array $vars = []): string
    {
        $this->assign('MAC_VERSION', config('version.code') ?? '');
        $this->assign('cl', $this->_cl);
        return parent::fetch($template, $vars);
    }

    /**
     * 后台模板的筛选参数 param 包成 SafeParam:{$param.xxx} 缺键回显时返回空串,
     * 避免 PHP8 未定义键 → 500(控制器内 $where 仍用原始数组,不受影响)。
     */
    protected function assign($name, $value = ''): void
    {
        if (($name === 'param' || $name === 'info') && is_array($value)) {
            $value = new \app\common\util\SafeParam($value);
        } elseif ($name === 'config' && is_array($value)) {
            // 设置页 {$config.section.key} 嵌套访问:用递归容器兜底未配置的段
            $value = new \app\common\util\SafeConfig($value);
        }
        parent::assign($name, $value);
    }

    public function check_auth($c,$a)
    {
        $c = strtolower($c);
        $a = strtolower($a);

        // UEditor AI proxy: logged-in admin only; API key never sent to browser.
        if ($c === 'upload' && ($a === 'ueditor_ai' || $a === 'ueditorai')) {
            return true;
        }

        if ($c === 'assistant' && in_array($a, ['chat', 'ping'], true)) {
            $assistantCfg = config('maccms.admin_assistant');
            $scope = is_array($assistantCfg) && isset($assistantCfg['access_scope'])
                ? strtolower(trim((string)$assistantCfg['access_scope']))
                : 'all';
            if ($scope === 'super' && (string)$this->_admin['admin_id'] !== '1') {
                return false;
            }
            return true;
        }

        if(($this->_admin['admin_id'] ?? '') =='1'){
            return true;
        }

        // 权限比对必须两侧归一,不能拿运行期的值直接去权限串里 strpos。
        //
        // 运行期拿到的是 TP8 的形态:request()->controller() 返回 Str::studly 后的
        // 类名(ResourceHub)、action() 返回 URL 里的原始动作名(multiCollect);
        // 而 admin_auth 里存的是权限树 auth.php 的原始写法(resource_hub/multiCollect)。
        // 下划线与大小写两个维度都对不上,于是**所有多词控制器与驼峰动作对子管理员
        // 一律被拒**,且超管(admin_id==1)在上面就 return true 了,从超管视角永远看不见。
        // 老写法还有个隐患:strpos 是子串匹配,'vod/del' 会被 'newvod/del' 误命中。
        // 统一走 authKey() 归一 + 全等比较。
        $want = self::authKey($c, $a);

        $auths = ($this->_admin['admin_auth'] ?? '') . ',index/index,index/welcome,index/logout,';
        foreach (explode(',', $auths) as $one) {
            $one = trim($one);
            if ($one === '' || strpos($one, '/') === false) {
                continue;
            }
            [$oc, $oa] = explode('/', $one, 2);
            if (self::authKey($oc, $oa) === $want) {
                return true;
            }
        }
        return false;
    }

    /**
     * 权限项的规范形:控制器去下划线转小写 + 动作转小写。
     * resource_hub/multiCollect 与 ResourceHub/multicollect 归一后都是
     * resourcehub/multicollect,两侧才能比得上。
     */
    public static function authKey($c, $a): string
    {
        $c = strtolower(str_replace('_', '', (string)$c));
        // 权限树里存在 'index?ac2=wap' 这种带参写法,比对时只取动作名
        $a = strtolower((string)strtok((string)$a, '?'));
        return $c . '/' . $a;
    }

    /** Resolve a managed file or directory without allowing sibling roots or symlink escapes. */
    protected static function resolveManagedPath($path, string $root, bool $allowNew = false): ?string
    {
        if (!is_string($path) || $path === '' || preg_match('/[\x00-\x1f\x7f]/', $path)) {
            return null;
        }
        $path = str_replace('\\', '/', $path);
        $relative = str_starts_with($path, './') ? substr($path, 2) : $path;
        if ($relative !== $root && !str_starts_with($relative, $root . '/')) {
            return null;
        }
        if (in_array('..', explode('/', $relative), true)) {
            return null;
        }
        $rootPath = realpath(ROOT_PATH . $root);
        if ($rootPath === false) {
            return null;
        }
        $candidate = ROOT_PATH . $relative;
        // Unlinking a canonicalized file symlink would delete its target, not the link.
        if (is_link($candidate) && !is_dir($candidate)) {
            return null;
        }
        $resolved = realpath($candidate);
        if ($resolved === false && $allowNew && !file_exists($candidate) && !is_link($candidate)) {
            $parent = realpath(dirname($candidate));
            if ($parent !== false) {
                $resolved = $parent . DIRECTORY_SEPARATOR . basename($candidate);
            }
        }
        if ($resolved === false || ($resolved !== $rootPath
            && !str_starts_with($resolved, $rootPath . DIRECTORY_SEPARATOR))) {
            return null;
        }
        return $resolved;
    }

    protected function _cache_clear(): bool
    {
        try {
            if (ENTRANCE === 'admin' && !\app\common\util\PlayerConfigCache::refresh(
                ROOT_PATH, config('vodplayer'), config('voddowner'), config('vodserver')
            )) { return false; }
        } catch (\Throwable $error) { return false; }
        $complete = true;
        foreach (['cache','temp'] as $name) {
            try { $removed = Dir::clearDirectory(RUNTIME_PATH . $name . '/'); }
            catch (\Throwable $error) { $removed = false; }
            $complete = $removed && $complete;
        }
        try { $cleared = Cache::clear() === true; }
        catch (\Throwable $error) { $cleared = false; }
        return $complete && $cleared;
    }

    public function batch_replace($field,$model,$search,$replace,$type='vod')
    {
        $replaceres = [];
        if(isset($model[$field]) && $search !== ''){
            if(empty($replace)) $replace = '';
            
            $original_value = $model[$field];
            $new_value = mac_filter_xss(str_replace($search, $replace, $original_value));

            if($original_value !== $new_value){
                $replaceres[$field] = $new_value;
                $replaceres['des'] = '&nbsp;'.lang('admin/batch/replace').'['.lang('admin/batch/field_'.str_replace($type.'_','',$field)).']：'.mac_filter_xss($search).'→'.mac_filter_xss($replace).'；';
            }
            else{
                $replaceres['des'] = '&nbsp;'.lang('admin/batch/no_match').'；';
            }
        }
        return $replaceres;
    }

    public function base_export($param,$table,$where)
    {
        $max = min(BulkTableIo::MAX_EXPORT_ROWS, max(1, intval($param['max'] ?? 5000)));
        $format = (isset($param['format']) && $param['format'] === 'xlsx') ? 'xlsx' : 'csv';
        if ($format === 'xlsx' && !class_exists('ZipArchive')) {
            return $this->error(lang('admin/batch/io_need_zip'));
        }
        $fields = Db::name(ucfirst($table))->getTableFields();
        $list = Db::name(ucfirst($table))->where($where)->order("{$table}_id desc")->limit($max)->select()->toArray();
        $base = $table.'_export_' . date('Ymd_His');
        if ($format === 'xlsx') {
            BulkTableIo::exportXlsxDownload($base, $fields, $list);
        } else {
            BulkTableIo::exportCsvDownload($base, $fields, $list);
        }
        exit;
    }

    public function base_import($table)
    {
        if (!is_string($table) || !in_array($table, ['art', 'manga', 'vod'], true)
            || !$this->request->isPost()) {
            return $this->error(lang('illegal_request'));
        }
        $param = $this->request->post();
        $validate = mac_validate('Token');
        $validate->setRequest($this->request);
        if (!$validate->check($param)) {
            return $this->error(lang('token_err'));
        }
        try {
            $upload = \app\common\util\ImportUpload::inspect($this->request->file('file'),
                ['csv', 'txt', 'xlsx'], BulkTableIo::MAX_IMPORT_BYTES);
            $parsed = BulkTableIo::parseFile($upload['path'], $upload['extension'], true);
        } catch (\app\common\util\ImportColumnException $error) {
            return $this->importColumnError($error->row, $error->column);
        } catch (\app\common\util\ImportTextException $error) {
            return $this->error(lang('admin/batch/io_text'), null, ['status' => 'invalid_text']);
        } catch (\Throwable $error) {
            return $this->error(lang('import_err'));
        }
        // PHP owns and removes its temporary upload. Never unlink a caller-provided pathname.
        if ($parsed['rows'] === []) { return $this->error(lang('import_err')); }
        try {
            $fields = $this->importFields($table);
        } catch (\Throwable $error) {
            return $this->error(lang('save_err'));
        }
        // An unknown ID/content header must not silently turn an update into an insert or lose a column.
        foreach ($parsed['headers'] as $index => $header) {
            if ($header !== '' && !in_array($header, $fields, true)) { return $this->importColumnError(1, $index + 1); }
        }
        if (!in_array($table . '_name', $parsed['headers'], true) || !in_array('type_id', $parsed['headers'], true)) {
            return $this->importColumnError(1, count($parsed['headers']) + 1);
        }
        $summary = ['total' => count($parsed['rows']), 'saved' => 0, 'failed' => 0,
            'unknown' => 0, 'unprocessed' => 0, 'repeat_index_pending' => 0, 'errors' => []];
        $unknownRow = null;
        foreach ($parsed['rows'] as $idx => $row) {
            $sourceRow = $parsed['row_numbers'][$idx];
            try {
                $data = BulkTableIo::filterRowKeys($row, $fields);
                if (!is_string($data[$table . '_name'] ?? null) || trim($data[$table . '_name']) === '') {
                    throw new \InvalidArgumentException('Missing content name');
                }
                $data = BulkTableIo::prepareGenericForSave($data, $table);
            } catch (\InvalidArgumentException $error) {
                $summary['failed']++;
                if (count($summary['errors']) < 15) {
                    $summary['errors'][] = ['row' => $sourceRow, 'reason' => 'param_err'];
                }
                continue;
            }
            try {
                $res = model(ucfirst($table))->saveData($data);
                if (!is_array($res) || !isset($res['code']) || !in_array($res['code'], [1, 1001, 1002], true)) {
                    throw new \UnexpectedValueException('Unconfirmed content save result');
                }
            } catch (\Throwable $error) {
                // saveData may have committed before a cache/search/connection failure. Do not retry or continue.
                try {
                    \think\facade\Log::error('Content import save unconfirmed: ' . json_encode([
                        'module' => $table, 'row' => $sourceRow, 'exception' => get_class($error),
                    ]));
                } catch (\Throwable $loggingError) { /* Diagnostics must not replace the unknown-outcome response. */ }
                $summary['unknown'] = 1;
                $unknownRow = $sourceRow;
                $summary['unprocessed'] = $summary['total'] - $idx - 1;
                break;
            }
            if ($res['code'] !== 1) {
                $summary['failed']++;
                if (count($summary['errors']) < 15) {
                    $summary['errors'][] = ['row' => $sourceRow, 'reason' => $res['code'] === 1001 ? 'param_err' : 'save_err'];
                }
                continue;
            }
            $summary['saved']++;
            if ($table === 'vod') {
                $pending = !is_array($res['info'] ?? null) || !empty($res['info']['repeat_index_pending']);
                try { Cache::delete('vod_repeat_table_created_time'); }
                catch (\Throwable $cacheError) { $pending = true; }
                if ($pending) { $summary['repeat_index_pending']++; }
            }
        }
        $summary['unknown_row'] = $unknownRow;
        $summary['status'] = $unknownRow !== null ? 'unknown'
            : ($summary['saved'] === 0 ? 'failed' : ($summary['failed'] > 0 ? 'partial' : 'completed'));
        $msg = lang('admin/batch/io_ok', [$summary['saved']]);
        if ($summary['failed'] > 0) {
            $msg .= ' ' . lang('admin/batch/io_fail', [$summary['failed']]);
            foreach ($summary['errors'] as $error) {
                $msg .= '；' . lang('admin/batch/io_row', [$error['row']]) . ' ' . lang($error['reason']);
            }
        }
        if ($summary['repeat_index_pending'] > 0) {
            $msg .= '；' . lang('admin/batch/io_pending', [$summary['repeat_index_pending']]);
        }
        if ($unknownRow !== null) {
            $msg .= '；' . lang('admin/batch/io_unknown', [$unknownRow]);
            return $this->error($msg, null, $summary);
        }
        return $summary['saved'] > 0 ? $this->success($msg, null, $summary) : $this->error($msg, null, $summary);
    }

    private function importColumnError(int $row, int $column)
    {
        return $this->error(lang('admin/batch/io_columns', [$row, $column]), null,
            ['status' => 'invalid_columns', 'row' => $row, 'column' => $column]);
    }

    /** Read current writer metadata; a query's master option does not cover getTableFields(). */
    private function importFields(string $module): array
    {
        $query = Db::name(ucfirst($module));
        $connection = $query->getConnection();
        if (!$connection instanceof \think\db\PDOConnection) {
            throw new \RuntimeException('Content import requires PDO storage');
        }
        $table = $query->getTable();
        if ($connection->getConfig('type') === 'mysql') {
            $rows = $connection->query('SELECT COLUMN_NAME AS name FROM information_schema.COLUMNS '
                . 'WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY ORDINAL_POSITION', [$table], true);
        } elseif ($connection->getConfig('type') === 'sqlite') {
            $rows = $connection->query('PRAGMA table_info("' . str_replace('"', '""', $table) . '")', [], true);
        } else {
            throw new \RuntimeException('Unsupported content import storage');
        }
        $fields = array_column($rows, 'name');
        foreach ([$module . '_id', $module . '_name', 'type_id'] as $required) {
            if (!in_array($required, $fields, true)) { throw new \RuntimeException('Missing import schema'); }
        }
        return $fields;
    }

}
