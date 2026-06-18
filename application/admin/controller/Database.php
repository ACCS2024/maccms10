<?php
namespace app\admin\controller;
use think\facade\Db;
use app\common\util\Dir;
use app\common\util\Database as dbOper;

class Database extends Base
{
    var $_db_config;
    public function __construct()
    {
        parent::__construct();
    }

    public function index()
    {
        $group = \think\facadeRequest::param("group");
        if($group=='import'){
            //列出备份文件列表
            $path = trim( $GLOBALS['config']['db']['backup_path'], '/').DS;
            if (!is_dir($path)) {
                Dir::create($path);
            }
            $flag = \FilesystemIterator::KEY_AS_FILENAME;
            $glob = new \FilesystemIterator($path,  $flag);

            $list = [];
            foreach ($glob as $name => $file) {
                if(preg_match('/^\d{8,8}-\d{6,6}-\d+\.sql(?:\.gz)?$/', $name)){
                    $name = sscanf($name, '%4s%2s%2s-%2s%2s%2s-%d');
                    $date = "{$name[0]}-{$name[1]}-{$name[2]}";
                    $time = "{$name[3]}:{$name[4]}:{$name[5]}";
                    $part = $name[6];

                    if(isset($list["{$date} {$time}"])){
                        $info = $list["{$date} {$time}"];
                        $info['part'] = max($info['part'], $part);
                        $info['size'] = $info['size'] + $file->getSize();
                    } else {
                        $info['part'] = $part;
                        $info['size'] = $file->getSize();
                    }

                    $extension        = strtoupper($file->getExtension());
                    $info['compress'] = ($extension === 'SQL') ? '无' : $extension;
                    $info['time']     = strtotime("{$date} {$time}");

                    $list["{$date} {$time}"] = $info;
                }
            }
        }
        else{
            $group='export';
            $list = Db::query("SHOW TABLE STATUS");
        }

        $this->assign('list',$list);
        $this->assign('title',lang('admin/database/title'));
        return $this->fetch('admin@database/'.$group);
    }

    public function export($ids = '', $start = 0)
    {
        if ($this->request->isPost()) {
            if (empty($ids)) {
                return $this->error(lang('admin/database/select_export_table'));
            }

            if (!is_array($ids)) {
                $tables[] = $ids;
            } else {
                $tables = $ids;
            }
            $have_admin = false;
            $admin_table='';
            foreach($tables as $k=>$v){
                if(strpos($v,'_admin')!==false){
                    $have_admin=true;
                    $admin_table = $v;
                    unset($tables[$k]);
                }
            }
            if($have_admin){
                $tables[] = $admin_table;
            }

            //读取备份配置
            $config = array(
                'path'     => $GLOBALS['config']['db']['backup_path'] .DS,
                'part'     => $GLOBALS['config']['db']['part_size'] ,
                'compress' => $GLOBALS['config']['db']['compress'] ,
                'level'    => $GLOBALS['config']['db']['compress_level'] ,
            );

            //检查是否有正在执行的任务
            $lock = "{$config['path']}backup.lock";
            if(is_file($lock)){
                return $this->error(lang('admin/database/lock_check'));
            } else {
                if (!is_dir($config['path'])) {
                    Dir::create($config['path'], 0755, true);
                }
                //创建锁文件
                file_put_contents($lock, $this->request->time());
            }

            //生成备份文件信息
            $file = [
                'name' => date('Ymd-His', $this->request->time()),
                'part' => 1,
            ];

            // 创建备份文件
            $database = new dbOper($file, $config);
            if($database->create() !== false) {
                // 备份指定表
                foreach ($tables as $table) {
                    $start = $database->backup($table, $start);
                    while (0 !== $start) {
                        if (false === $start) {
                            return $this->error(lang('admin/database/backup_err'));
                        }
                        $start = $database->backup($table, $start[0]);
                    }
                }
                // 备份完成，删除锁定文件
                unlink($lock);
            }
            return $this->success(lang('admin/database/backup_ok'));
        }
        return $this->error(lang('admin/database/backup_err'));
    }

    /**
     * 恢复数据库 [参考原作者 麦当苗儿 <zuojiazi@vip.qq.com>]
     * @param string|array $ids 表名
     * @param integer $start 起始行数
     * @author 橘子俊 <364666827@qq.com>
     * @return mixed
     */
    public function import($id = '')
    {
        if (empty($id)) {
            return $this->error(lang('admin/database/select_file'));
        }

        $name  = date('Ymd-His', $id) . '-*.sql*';
        $path  = trim( $GLOBALS['config']['db']['backup_path'] , '/').DS.$name;
        $files = glob($path);
        $list  = array();
        foreach($files as $name){
            $basename = basename($name);
            $match    = sscanf($basename, '%4s%2s%2s-%2s%2s%2s-%d');
            $gz       = preg_match('/^\d{8,8}-\d{6,6}-\d+\.sql.gz$/', $basename);
            $list[$match[6]] = array($match[6], $name, $gz);
        }
        ksort($list);

        // 检测文件正确性
        $last = end($list);
        if(count($list) === $last[0]){
            foreach ($list as $item) {
                $config = [
                    'path'     => trim($GLOBALS['config']['db']['backup_path'], '/').DS,
                    'compress' => $item[2]
                ];
                $database = new dbOper($item, $config);
                $start = $database->import(0);
                // 导入所有数据
                while (0 !== $start) {
                    if (false === $start) {
                        return $this->error(lang('admin/database/import_err'));
                    }
                    $start = $database->import($start[0]);
                }
            }
            return $this->success(lang('admin/database/import_ok'));
        }
        return $this->error(lang('admin/database/file_damage'));
    }

    public function optimize($ids = '')
    {
        if (empty($ids)) {
            return $this->error(lang('admin/database/select_optimize_table'));
        }

        if (!is_array($ids)) {
            $table[] = $ids;
        } else {
            $table = $ids;
        }

        foreach ($table as $t) {
            if (!$this->isValidTable($t)) {
                return $this->error('Table is invalid.');
            }
        }

        $tables = implode('`,`', $table);
        $res = Db::query("OPTIMIZE TABLE `{$tables}`");
        if ($res) {
            return $this->success(lang('admin/database/optimize_ok'));
        }
        return $this->error(lang('admin/database/optimize_err'));
    }

    public function repair($ids = '')
    {
        if (empty($ids)) {
            return $this->error(lang('admin/database/select_repair_table'));
        }

        if (!is_array($ids)) {
            $table[] = $ids;
        } else {
            $table = $ids;
        }

        foreach ($table as $t) {
            if (!$this->isValidTable($t)) {
                return $this->error('Table is invalid.');
            }
        }

        $tables = implode('`,`', $table);
        $res = Db::query("REPAIR TABLE `{$tables}`");
        if ($res) {
            return $this->success(lang('admin/database/repair_ok'));
        }
        return $this->error(lang('admin/database/repair_ok'));
    }

    /**
     * 将所选表存储引擎转换为 InnoDB(MyISAM 表级锁 → 行级锁/MVCC,
     * 根治采集与高并发下的锁表、"卡死/故障多",并支持事务与崩溃恢复)。
     * 仅管理员手动、低峰触发:大表 ALTER 会重建表、耗时且占用磁盘,故不放入登录自动迁移。
     * 已是 InnoDB 的表自动跳过;逐表执行,单表失败(如旧版 MySQL 的 FULLTEXT 限制)不影响其余。
     */
    public function convert_engine($ids = '')
    {
        if (empty($ids)) {
            return $this->error(lang('admin/database/select_optimize_table'));
        }
        $table = is_array($ids) ? $ids : [$ids];
        foreach ($table as $t) {
            if (!$this->isValidTable($t)) {
                return $this->error('Table is invalid.');
            }
        }
        // 读取当前引擎,已 InnoDB 的跳过
        $engineMap = [];
        foreach (Db::query("SHOW TABLE STATUS") as $row) {
            $engineMap[$row['Name']] = strtoupper((string)($row['Engine'] ?? ''));
        }
        $converted = [];
        $skipped   = [];
        $failed    = [];
        foreach ($table as $t) {
            if (($engineMap[$t] ?? '') === 'INNODB') {
                $skipped[] = $t;
                continue;
            }
            try {
                Db::execute("ALTER TABLE `" . str_replace('`', '', $t) . "` ENGINE=InnoDB");
                $converted[] = $t;
            } catch (\Throwable $e) {
                $failed[] = $t . ' (' . $e->getMessage() . ')';
            }
        }
        $msg = 'InnoDB 转换完成 — 成功:' . count($converted)
             . ',跳过(已是InnoDB):' . count($skipped)
             . ',失败:' . count($failed);
        if (!empty($failed)) {
            return $this->error($msg . ' | 失败:' . implode('; ', $failed));
        }
        return $this->success($msg);
    }

    /**
     * 清理「冗余单列索引」:仅删除可证明多余的索引——
     * 单列、非唯一、非主键,且该列恰是某复合索引的「首列」(最左前缀)。
     * 此类单列索引的全部查找都能由复合索引最左前缀承担,删之不影响任何查询,纯减写放大。
     * 例:补了 (type_id,vod_status,vod_time) 后,单列 type_id 索引即冗余。
     *
     * 安全边界(经核实 maccms 查询模式后刻意从严):
     *  - 唯一索引(NON_UNIQUE=0)一律保留(承载唯一约束,非纯加速);
     *  - 仅"首列重复"才删;vod_name/vod_director(采集去重等值查)、vod_up/down/level/hits*(排序白名单)
     *    等虽是单列但被实际查询使用,不属"首列重复",不会被本方法删除。
     * 幂等:已清理过再次执行不再删除。
     */
    public function drop_redundant_index($ids = '')
    {
        if (empty($ids)) {
            return $this->error(lang('admin/database/select_optimize_table'));
        }
        $table = is_array($ids) ? $ids : [$ids];
        foreach ($table as $t) {
            if (!$this->isValidTable($t)) {
                return $this->error('Table is invalid.');
            }
        }
        $dropped = [];
        $failed  = [];
        foreach ($table as $t) {
            $rows = Db::query(
                "SELECT INDEX_NAME, SEQ_IN_INDEX, COLUMN_NAME, NON_UNIQUE
                 FROM information_schema.STATISTICS
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
                 ORDER BY INDEX_NAME, SEQ_IN_INDEX",
                [$t]
            );
            // 聚合:每个索引的列序列 + 是否唯一
            $idx = [];
            foreach ($rows as $r) {
                $n = $r['INDEX_NAME'];
                $idx[$n]['cols'][(int)$r['SEQ_IN_INDEX']] = $r['COLUMN_NAME'];
                $idx[$n]['nonuniq'] = (int)$r['NON_UNIQUE'];
            }
            // 复合索引(>1 列)的首列集合
            $leadingCols = [];
            foreach ($idx as $meta) {
                if (count($meta['cols']) > 1) {
                    ksort($meta['cols']);
                    $leadingCols[reset($meta['cols'])] = true;
                }
            }
            // 单列 + 非唯一 + 非主键 + 列是某复合索引首列 → 冗余
            foreach ($idx as $name => $meta) {
                if ($name === 'PRIMARY' || count($meta['cols']) !== 1 || $meta['nonuniq'] !== 1) {
                    continue;
                }
                $col = reset($meta['cols']);
                if (empty($leadingCols[$col])) {
                    continue;
                }
                try {
                    Db::execute("ALTER TABLE `" . str_replace('`', '', $t) . "` DROP INDEX `" . str_replace('`', '', $name) . "`");
                    $dropped[] = $t . '.' . $name;
                } catch (\Throwable $e) {
                    $failed[] = $t . '.' . $name . ' (' . $e->getMessage() . ')';
                }
            }
        }
        $msg = '冗余索引清理完成 — 删除:' . count($dropped) . ',失败:' . count($failed)
             . (empty($dropped) ? '(无可删冗余索引)' : ' | ' . implode(', ', $dropped));
        if (!empty($failed)) {
            return $this->error($msg . ' | 失败:' . implode('; ', $failed));
        }
        return $this->success($msg);
    }

    public function del($id = '')
    {
        if (empty($id)) {
            return $this->error(lang('admin/database/select_del_file'));
        }

        $name  = date('Ymd-His', $id) . '-*.sql*';
        $path = trim($GLOBALS['config']['db']['backup_path']).DS.$name;
        array_map("unlink", glob($path));
        if(count(glob($path)) && glob($path)){
            return $this->error(lang('del_err'));
        }
        return $this->success(lang('del_ok'));
    }

    public function sql()
    {
        if($this->request->isPost()){
            $param=\think\facadeRequest::param();
            $validate = \think\Loader::validate('Token');
            if(!$validate->check($param)){
                return $this->error($validate->getError());
            }

            $sql = trim($param['sql']);

            if(!empty($sql)){
                $forbidden_keywords = ['into dumpfile', 'into outfile', 'char(', 'load_file'];
                foreach ($forbidden_keywords as $keyword) {
                    if (stripos($sql, $keyword) !== false) {
                        return $this->error(lang('format_err'));
                    }
                }
                $sql = str_replace('{pre}',config('database.prefix'),$sql);
                // 高危操作留痕:SQL 控制台无论全局审计开关如何,始终记录 执行人/IP/SQL,便于事后追溯
                @file_put_contents(
                    RUNTIME_PATH . 'sql_console.log',
                    date('Y-m-d H:i:s') . "\t" . (isset($this->_admin['admin_name']) ? $this->_admin['admin_name'] : '?')
                        . '(#' . (isset($this->_admin['admin_id']) ? $this->_admin['admin_id'] : '?') . ')'
                        . "\t" . (function_exists('mac_get_client_ip') ? mac_get_client_ip() : '') . "\t"
                        . str_replace(["\r", "\n"], ' ', $sql) . "\n",
                    FILE_APPEND | LOCK_EX
                );
                //查询语句返回结果集
                if(
                    strtolower(substr($sql,0,6))=="select" || 
                    stripos($sql, ' outfile') !== false
                ){

                }
                else{
                    Db::execute($sql);
                }
            }
            $this->success(lang('run_ok'));
        }
        return $this->fetch('admin@database/sql');
    }

    public function columns()
    {
        $param = \think\facadeRequest::param();
        $table = $param['table'];
        if (!empty($table) && !$this->isValidTable($table)) {
            return $this->error('Table is invalid.');
        }
        if (!empty($table)) {
            $list = Db::query('SHOW COLUMNS FROM `' . str_replace('`', '``', $table) . '`');
            $this->success(lang('obtain_ok'),null, $list);
        }
        $this->error(lang('param_err'));
    }

    public function rep()
    {
        if($this->request->isPost()){
            $param = \think\facadeRequest::param();
            $table = isset($param['table']) ? $param['table'] : '';
            $field = isset($param['field']) ? $param['field'] : '';
            $findstr = isset($param['findstr']) ? $param['findstr'] : '';
            $tostr = isset($param['tostr']) ? $param['tostr'] : '';
            $where = isset($param['where']) ? $param['where'] : '';

            $validate = \think\Loader::validate('Token');
            if(!$validate->check($param)){
                return $this->error($validate->getError());
            }
            if ($table === '' || !$this->isValidTable($table)) {
                return $this->error('Table is invalid.');
            }
            if ($field === '' || $findstr === '' || $tostr === '') {
                return $this->error(lang('param_err'));
            }
            if (!$this->isValidField($table, $field)) {
                return $this->error('Column is invalid.');
            }
            $whereSql = $this->sanitizeRepWhereClause($where);
            if ($whereSql === false) {
                return $this->error('WHERE clause is invalid.');
            }
            $tq = '`' . str_replace('`', '``', $table) . '`';
            $fq = '`' . str_replace('`', '``', $field) . '`';
            $sql = 'UPDATE ' . $tq . ' SET ' . $fq . '=REPLACE(' . $fq . ', ?, ?) WHERE 1=1' . $whereSql;
            Db::execute($sql, [$findstr, $tostr]);
            return $this->success(lang('run_ok'));
        }
        $list = Db::query("SHOW TABLE STATUS");
        $this->assign('list',$list);
        return $this->fetch('admin@database/rep');
    }

    private function isValidTable($table) {
        $list = Db::query("SHOW TABLE STATUS");
        foreach ($list as $table_raw) {
            if ($table_raw['Name'] == $table) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $table 已通过 isValidTable 校验的表名
     */
    private function isValidField($table, $field)
    {
        if (!is_string($field) || !preg_match('/^[a-zA-Z0-9_]+$/', $field)) {
            return false;
        }
        $list = Db::query('SHOW COLUMNS FROM `' . str_replace('`', '``', $table) . '`');
        if (!is_array($list)) {
            return false;
        }
        foreach ($list as $row) {
            if (!empty($row['Field']) && $row['Field'] === $field) {
                return true;
            }
        }
        return false;
    }

    /**
     * 附加 WHERE 仅允许 AND 开头的简单片段；无法安全绑定的表达式一律拒绝。
     *
     * @param string $where
     * @return string|false 返回可拼接到 SQL 的片段（含前导空格），或 false
     */
    private function sanitizeRepWhereClause($where)
    {
        $where = trim((string)$where);
        if ($where === '') {
            return '';
        }
        if (strlen($where) > 500) {
            return false;
        }
        $norm = preg_replace('/\s+/', ' ', strtolower($where));
        $blocked = [
            ';', '--', '/*', '*/', ' union ', ' select ', ' insert ', ' update ', ' delete ',
            ' drop ', ' create ', ' alter ', ' grant ', ' revoke ', ' exec ', ' execute ',
            'sleep(', 'benchmark(', 'load_file', 'outfile', 'dumpfile', ' information_schema',
            ' xor ', ' or 1', ' or true',
        ];
        foreach ($blocked as $b) {
            if (strpos($norm, $b) !== false) {
                return false;
            }
        }
        if (strncmp($norm, 'and ', 4) !== 0) {
            return false;
        }

        return ' ' . $where;
    }
}
