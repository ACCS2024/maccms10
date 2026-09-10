<?php
namespace app\admin\controller;
use think\facade\Db;
use app\common\util\Database as dbOper;

class Database extends Base
{
    var $_db_config;
    public function __construct()
    {
        parent::__construct();
    }

    private function backupConfig(): array
    {
        $settings = $GLOBALS['config']['db'] ?? null;
        $path = is_array($settings) ? ($settings['backup_path'] ?? null) : null;
        if (!is_string($path) || trim($path) === '' || preg_match('/[\x00-\x1f\x7f]/', $path)
            || str_contains($path, '://')) {
            throw new \RuntimeException('Invalid backup directory');
        }
        $path = str_replace('\\', '/', trim($path));
        if (in_array('..', explode('/', $path), true)) { throw new \RuntimeException('Invalid backup directory'); }
        if (!str_starts_with($path, '/') && !preg_match('/^[a-zA-Z]:\//', $path)) { $path = ROOT_PATH.$path; }
        if (!is_dir($path) && !@mkdir($path, 0700, true) && !is_dir($path)) {
            throw new \RuntimeException('Cannot create backup directory');
        }
        $path = realpath($path);
        if ($path === false) { throw new \RuntimeException('Invalid backup directory'); }
        return ['path'=>rtrim($path, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR,
            'part'=>$settings['part_size'] ?? 20971520, 'compress'=>$settings['compress'] ?? 0,
            'level'=>$settings['compress_level'] ?? 6];
    }

    /** The inode stays in place: existence is not ownership, flock is. */
    private function backupLock(string $path)
    {
        $filename = $path.'backup.lock';
        $mask = umask(0077);
        try { $stream = @fopen($filename, 'x+b'); }
        finally { umask($mask); }
        if ($stream === false) {
            if (is_link($filename) || !is_file($filename)) { throw new \RuntimeException('Invalid backup lock'); }
            $stream = @fopen($filename, 'r+b');
        }
        if ($stream === false) { throw new \RuntimeException('Cannot open backup lock'); }
        if (!@flock($stream, LOCK_EX | LOCK_NB)) { fclose($stream); return null; }
        clearstatcache(true, $filename);
        $stat = @lstat($filename); $opened = fstat($stream);
        if (!$stat || !$opened || ($stat['mode'] & 0170000) !== 0100000 || $stat['nlink'] !== 1
            || $stat['dev'] !== $opened['dev'] || $stat['ino'] !== $opened['ino']) {
            fclose($stream); throw new \RuntimeException('Backup lock changed');
        }
        $owner = getmypid().' '.time()."\n";
        if (!@ftruncate($stream, 0) || @fwrite($stream, $owner) !== strlen($owner) || !@fflush($stream)) {
            fclose($stream); throw new \RuntimeException('Cannot write backup lock');
        }
        return $stream;
    }

    private function backupName($id): ?string
    {
        if ((!is_int($id) && !is_string($id)) || !preg_match('/^[1-9][0-9]*$/D', (string)$id)) { return null; }
        $time = filter_var($id, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1,'max_range'=>253402214399]]);
        return $time === false ? null : date('Ymd-His', $time);
    }

    /** Exact filenames only; a new archive is usable after its manifest is published. */
    private function backupParts(string $path, string $name, bool $verifyHashes = false): array
    {
        if (file_exists($path.'.'.$name.'.pending') || is_link($path.'.'.$name.'.pending')) {
            throw new \RuntimeException('Backup is incomplete');
        }
        $parts = []; $compression = null;
        foreach (glob($path.$name.'-*.sql*') ?: [] as $filename) {
            if (!preg_match('/^'.preg_quote($name, '/').'-([1-9][0-9]*)\.sql(\.gz)?$/D', basename($filename), $match)) { continue; }
            $part = filter_var($match[1], FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
            $gzip = !empty($match[2]) ? 1 : 0;
            if ($part === false || !is_file($filename) || is_link($filename) || isset($parts[$part])
                || ($compression !== null && $compression !== $gzip)) { throw new \RuntimeException('Invalid backup part'); }
            $compression = $gzip; $parts[$part] = [$part, $filename, $gzip];
        }
        ksort($parts);
        if (!$parts || array_keys($parts) !== range(1, count($parts))) { throw new \RuntimeException('Missing backup part'); }
        $manifest = $path.'.'.$name.'.json';
        if (file_exists($manifest) || is_link($manifest)) {
            if (!is_file($manifest) || is_link($manifest) || filesize($manifest) > 1048576) { throw new \RuntimeException('Invalid backup manifest'); }
            $data = json_decode((string)file_get_contents($manifest), true);
            if (!is_array($data) || ($data['version'] ?? null) !== 1 || !is_array($data['parts'] ?? null)
                || count($data['parts']) !== count($parts)) { throw new \RuntimeException('Invalid backup manifest'); }
            foreach (array_values($parts) as $index=>$part) {
                $expected = $data['parts'][$index] ?? null;
                if (!is_array($expected) || ($expected['name'] ?? null) !== basename($part[1])
                    || ($expected['size'] ?? null) !== filesize($part[1]) || !is_string($expected['sha256'] ?? null)
                    || !preg_match('/^[a-f0-9]{64}$/D', $expected['sha256'])
                    || ($verifyHashes && !hash_equals($expected['sha256'], hash_file('sha256', $part[1])))) {
                    throw new \RuntimeException('Backup integrity check failed');
                }
            }
        } else {
            // Old MacCMS archives had no manifest. New codec archives require theirs.
            $first = reset($parts);
            $stream = $first[2] ? @gzopen($first[1], 'rb') : @fopen($first[1], 'rb');
            if (!is_resource($stream)) { throw new \RuntimeException('Cannot read backup'); }
            try { $header = $first[2] ? gzgets($stream, 80) : fgets($stream, 80); }
            finally { $first[2] ? gzclose($stream) : fclose($stream); }
            if (trim((string)$header) === '-- MySQL backup') { throw new \RuntimeException('Missing backup manifest'); }
        }
        return $parts;
    }

    private function writeBackupMetadata(string $filename, string $bytes): void
    {
        $mask = umask(0077);
        try { $stream = @fopen($filename, 'xb'); }
        finally { umask($mask); }
        if ($stream === false) { throw new \RuntimeException('Cannot create backup metadata'); }
        try {
            for ($offset = 0, $length = strlen($bytes); $offset < $length;) {
                $written = @fwrite($stream, substr($bytes, $offset));
                if ($written === false || $written === 0) { throw new \RuntimeException('Cannot write backup metadata'); }
                $offset += $written;
            }
            if (!@fflush($stream)) { throw new \RuntimeException('Cannot flush backup metadata'); }
        } finally { fclose($stream); }
    }

    public function index()
    {
        $group = $this->request->param('group');
        $list = [];
        if ($group === 'import') {
            try {
                $path = $this->backupConfig()['path'];
                $names = [];
                foreach (new \FilesystemIterator($path, \FilesystemIterator::SKIP_DOTS) as $file) {
                    if (preg_match('/^(\d{8}-\d{6})-[1-9][0-9]*\.sql(?:\.gz)?$/D', $file->getFilename(), $match)) {
                        $names[$match[1]] = true;
                    }
                }
                foreach (array_keys($names) as $name) {
                    try { $parts = $this->backupParts($path, $name); }
                    catch (\Throwable $error) { continue; }
                    $date = \DateTimeImmutable::createFromFormat('!Ymd-His', $name);
                    if (!$date || $date->format('Ymd-His') !== $name) { continue; }
                    $first = reset($parts);
                    $list[$date->format('Y-m-d H:i:s')] = ['part'=>count($parts),
                        'size'=>array_sum(array_map(static fn($part)=>filesize($part[1]), $parts)),
                        'compress'=>$first[2] ? 'GZ' : '无', 'time'=>$date->getTimestamp()];
                }
            } catch (\Throwable $error) { return $this->error(lang('admin/database/file_damage')); }
        } else {
            $group = 'export';
            $list = Db::query('SHOW TABLE STATUS');
        }
        $this->assign('list', $list);
        $this->assign('title', lang('admin/database/title'));
        return $this->fetch('admin@database/'.$group);
    }

    public function export($ids = '', $start = 0)
    {
        if (!$this->request->isPost()) { return $this->error(lang('admin/database/backup_err')); }
        $tables = is_array($ids) ? $ids : [$ids];
        if (!$tables) { return $this->error(lang('admin/database/select_export_table')); }
        foreach ($tables as $table) {
            if (!is_string($table) || $table === '' || str_contains($table, "\0")) {
                return $this->error(lang('admin/database/select_export_table'));
            }
        }
        // This endpoint has always completed one synchronous job; no cross-request offset is safe.
        if (!in_array($start, [0, '0'], true)) { return $this->error(lang('admin/database/backup_err')); }
        $lock = null; $database = null; $staging = null; $marker = null; $manifest = null;
        $published = []; $complete = false; $message = 'admin/database/backup_err';
        try {
            $known = array_column(Db::query('SHOW TABLE STATUS'), 'Name');
            $tables = array_values(array_unique($tables));
            foreach ($tables as $table) {
                if (!in_array($table, $known, true)) { throw new \RuntimeException('Invalid backup table'); }
            }
            // Keep administrator tables last, without dropping multiple selected matching tables.
            usort($tables, static fn($a,$b)=>(int)str_contains($a,'_admin') <=> (int)str_contains($b,'_admin'));
            $config = $this->backupConfig(); $path = $config['path'];
            $lock = $this->backupLock($path);
            if ($lock === null) { $message = 'admin/database/lock_check'; throw new \RuntimeException('Backup is busy'); }
            $name = $this->backupName($this->request->time());
            if ($name === null || (glob($path.$name.'-*.sql*') ?: [])
                || file_exists($path.'.'.$name.'.json') || is_link($path.'.'.$name.'.json')
                || file_exists($path.'.'.$name.'.pending') || is_link($path.'.'.$name.'.pending')) {
                throw new \RuntimeException('Backup name already exists');
            }
            $marker = $path.'.'.$name.'.pending';
            $this->writeBackupMetadata($marker, "Backup has not completed.\n");
            $staging = $path.'.backup-'.bin2hex(random_bytes(12));
            if (!@mkdir($staging, 0700)) { throw new \RuntimeException('Cannot create backup staging directory'); }
            $config['path'] = $staging.DIRECTORY_SEPARATOR;
            $database = new dbOper(['name'=>$name, 'part'=>1], $config);
            if (!$database->create()) { throw new \RuntimeException('Cannot create backup'); }
            foreach ($tables as $table) {
                $next = $database->backup($table, 0);
                while (is_array($next)) { $next = $database->backup($table, $next[0]); }
                if ($next !== 0) { throw new \RuntimeException('Cannot complete backup'); }
            }
            if (!$database->close()) { throw new \RuntimeException('Cannot close backup'); }
            $metadata = ['version'=>1, 'parts'=>[]];
            foreach ($database->createdFiles() as $source) {
                $destination = $path.basename($source);
                // Hard-link publication is exclusive and stays on the same filesystem.
                if (!@link($source, $destination)) { throw new \RuntimeException('Cannot publish backup'); }
                $published[] = $destination;
                $metadata['parts'][] = ['name'=>basename($source), 'size'=>filesize($source), 'sha256'=>hash_file('sha256', $source)];
            }
            $manifest = $path.'.'.$name.'.json';
            $encoded = json_encode($metadata, JSON_THROW_ON_ERROR);
            if (strlen($encoded) > 1048576) { throw new \RuntimeException('Backup manifest is too large'); }
            $this->writeBackupMetadata($manifest, $encoded);
            if (!@unlink($marker)) { throw new \RuntimeException('Cannot complete backup publication'); }
            $complete = true;
        } catch (\Throwable $error) {
            // Only resources owned by this attempt may be removed; an old archive is never overwritten.
        } finally {
            if ($database !== null) { $database->close(); }
            $cleaned = true;
            if (!$complete) {
                foreach ($published as $filename) { $cleaned = @unlink($filename) && $cleaned; }
                if ($manifest !== null && is_file($manifest)) { $cleaned = @unlink($manifest) && $cleaned; }
            }
            if ($staging !== null && is_dir($staging)) {
                foreach ($database !== null ? $database->createdFiles() : [] as $filename) { @unlink($filename); }
                @rmdir($staging);
            }
            if (!$complete && $cleaned && $marker !== null && is_file($marker)) { @unlink($marker); }
            if (is_resource($lock)) { flock($lock, LOCK_UN); fclose($lock); }
        }
        return $complete ? $this->success(lang('admin/database/backup_ok')) : $this->error(lang($message));
    }

    public function import($id = '')
    {
        $name = $this->backupName($id);
        if (!$this->request->isPost() || $name === null) { return $this->error(lang('admin/database/select_file')); }
        $lock = null; $complete = false; $message = 'admin/database/file_damage';
        try {
            $config = $this->backupConfig();
            $lock = $this->backupLock($config['path']);
            if ($lock === null) { $message = 'admin/database/lock_check'; throw new \RuntimeException('Backup is busy'); }
            $parts = $this->backupParts($config['path'], $name, true);
            $message = 'admin/database/import_err';
            foreach ($parts as $part) {
                $config['compress'] = $part[2];
                $database = new dbOper($part, $config, 'import');
                $next = $database->import(0);
                while (is_array($next)) { $next = $database->import($next[0]); }
                if ($next !== 0) { throw new \RuntimeException('Cannot restore backup'); }
            }
            $complete = true;
        } catch (\Throwable $error) {
        } finally { if (is_resource($lock)) { flock($lock, LOCK_UN); fclose($lock); } }
        return $complete ? $this->success(lang('admin/database/import_ok')) : $this->error(lang($message));
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

    /**
     * 补充性能索引
     *
     * 幂等：已存在的索引跳过，不存在的创建。
     * 设计原则：每条索引只针对已知高频查询，覆盖列按「等值列在前、范围/排序列在后」原则排序。
     * 可安全多次执行：重复运行不产生副作用。
     */
    public function add_perf_indexes()
    {
        $prefix = (string)config('database.connections.mysql.prefix');
        $q = function (string $sql, array $bind = []) {
            return Db::query($sql, $bind);
        };
        $e = function (string $sql) {
            Db::execute($sql);
        };

        // 检查索引是否存在
        $indexExists = function (string $table, string $indexName) use ($q) {
            $rows = $q(
                "SELECT COUNT(*) AS c FROM information_schema.STATISTICS
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?",
                [$table, $indexName]
            );
            return (int)($rows[0]['c'] ?? 0) > 0;
        };

        // 检查表是否存在
        $tableExists = function (string $table) use ($q) {
            $rows = $q(
                "SELECT COUNT(*) AS c FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
                [$table]
            );
            return (int)($rows[0]['c'] ?? 0) > 0;
        };

        /*
         * 待补充的索引清单：
         * [table, index_name, create_sql]
         * create_sql 中表名用 {T} 占位（已含 prefix）。
         *
         * 覆盖索引选择依据：
         *   mac_type.type_pid      — 分类树查询 WHERE type_pid=? ORDER BY type_sort
         *   mac_vod.idx_type_status_time — 视频列表 WHERE type_id=? AND vod_status=1 ORDER BY vod_time
         *   mac_vod.idx_type1_status_time — 视频列表 WHERE type_id_1=? AND vod_status=1 ORDER BY vod_time
         *   mac_vod.idx_status_time  — 全局时间线 WHERE vod_status=1 ORDER BY vod_time
         *   mac_visit.visit_time   — 后台统计 WHERE visit_time BETWEEN ? AND ?
         *   mac_user.user_reg_time — 后台注册统计 WHERE user_reg_time BETWEEN ? AND ?
         *   mac_comment.idx_comment_lookup — 评论列表 WHERE comment_rid=? AND comment_mid=? AND comment_pid=0 AND comment_status=1
         *   mac_comment.idx_comment_sub    — 子评论 WHERE comment_pid IN(...)  AND comment_status=1
         */
        $plan = [
            [
                'table' => $prefix . 'type',
                'name'  => 'idx_type_pid_sort',
                'sql'   => "ALTER TABLE `{T}` ADD INDEX `idx_type_pid_sort` (`type_pid`, `type_sort`)",
            ],
            [
                'table' => $prefix . 'vod',
                'name'  => 'idx_vod_type_status_time',
                'sql'   => "ALTER TABLE `{T}` ADD INDEX `idx_vod_type_status_time` (`type_id`, `vod_status`, `vod_time`)",
            ],
            [
                'table' => $prefix . 'vod',
                'name'  => 'idx_vod_type1_status_time',
                'sql'   => "ALTER TABLE `{T}` ADD INDEX `idx_vod_type1_status_time` (`type_id_1`, `vod_status`, `vod_time`)",
            ],
            [
                'table' => $prefix . 'vod',
                'name'  => 'idx_vod_status_time',
                'sql'   => "ALTER TABLE `{T}` ADD INDEX `idx_vod_status_time` (`vod_status`, `vod_time`)",
            ],
            [
                'table' => $prefix . 'visit',
                'name'  => 'idx_visit_time',
                'sql'   => "ALTER TABLE `{T}` ADD INDEX `idx_visit_time` (`visit_time`)",
            ],
            [
                'table' => $prefix . 'user',
                'name'  => 'idx_user_reg_time',
                'sql'   => "ALTER TABLE `{T}` ADD INDEX `idx_user_reg_time` (`user_reg_time`)",
            ],
            [
                'table' => $prefix . 'comment',
                'name'  => 'idx_comment_lookup',
                'sql'   => "ALTER TABLE `{T}` ADD INDEX `idx_comment_lookup` (`comment_rid`, `comment_mid`, `comment_pid`, `comment_status`, `comment_time`)",
            ],
            [
                'table' => $prefix . 'comment',
                'name'  => 'idx_comment_sub',
                'sql'   => "ALTER TABLE `{T}` ADD INDEX `idx_comment_sub` (`comment_pid`, `comment_status`)",
            ],
        ];

        $created = [];
        $skipped = [];
        $failed  = [];

        foreach ($plan as $item) {
            $table = $item['table'];
            $name  = $item['name'];

            if (!$tableExists($table)) {
                $skipped[] = $table . '.' . $name . '(表不存在)';
                continue;
            }

            if ($indexExists($table, $name)) {
                $skipped[] = $table . '.' . $name . '(已存在)';
                continue;
            }

            try {
                $sql = str_replace('{T}', str_replace('`', '``', $table), $item['sql']);
                $e($sql);
                $created[] = $table . '.' . $name;
            } catch (\Throwable $ex) {
                $failed[] = $table . '.' . $name . ': ' . $ex->getMessage();
            }
        }

        $msg = '性能索引补充完成 — 新建:' . count($created) . '，跳过:' . count($skipped) . '，失败:' . count($failed);
        if (!empty($created)) {
            $msg .= ' | 新建:' . implode(', ', $created);
        }
        if (!empty($failed)) {
            return $this->error($msg . ' | 错误:' . implode('; ', $failed));
        }
        return $this->success($msg);
    }

    /**
     * 返回当前性能索引状态（JSON，供 welcome 页和 AJAX 使用）
     */
    public function perf_index_status()
    {
        $prefix = (string)config('database.connections.mysql.prefix');
        $q = function (string $sql, array $bind = []) {
            return Db::query($sql, $bind);
        };
        $tableExists = function (string $table) use ($q) {
            $rows = $q(
                "SELECT COUNT(*) AS c FROM information_schema.TABLES
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
                [$table]
            );
            return (int)($rows[0]['c'] ?? 0) > 0;
        };
        $indexExists = function (string $table, string $indexName) use ($q) {
            $rows = $q(
                "SELECT COUNT(*) AS c FROM information_schema.STATISTICS
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?",
                [$table, $indexName]
            );
            return (int)($rows[0]['c'] ?? 0) > 0;
        };

        $plan = [
            ['table' => $prefix . 'type',    'name' => 'idx_type_pid_sort',          'label' => 'type: type_pid+sort'],
            ['table' => $prefix . 'vod',     'name' => 'idx_vod_type_status_time',   'label' => 'vod: type_id+status+time'],
            ['table' => $prefix . 'vod',     'name' => 'idx_vod_type1_status_time',  'label' => 'vod: type_id_1+status+time'],
            ['table' => $prefix . 'vod',     'name' => 'idx_vod_status_time',        'label' => 'vod: status+time'],
            ['table' => $prefix . 'visit',   'name' => 'idx_visit_time',             'label' => 'visit: visit_time'],
            ['table' => $prefix . 'user',    'name' => 'idx_user_reg_time',          'label' => 'user: reg_time'],
            ['table' => $prefix . 'comment', 'name' => 'idx_comment_lookup',         'label' => 'comment: 列表查询'],
            ['table' => $prefix . 'comment', 'name' => 'idx_comment_sub',            'label' => 'comment: 子评论'],
        ];

        $result = [];
        foreach ($plan as $item) {
            $exists = $tableExists($item['table']) && $indexExists($item['table'], $item['name']);
            $result[] = ['label' => $item['label'], 'exists' => $exists];
        }
        $missing = count(array_filter($result, function ($r) { return !$r['exists']; }));
        return json(['code' => 1, 'missing' => $missing, 'items' => $result]);
    }

    public function del($id = '')
    {
        $name = $this->backupName($id);
        if (!$this->request->isPost() || $name === null) { return $this->error(lang('admin/database/select_del_file')); }
        $lock = null; $complete = false; $message = 'del_err';
        try {
            $path = $this->backupConfig()['path'];
            $lock = $this->backupLock($path);
            if ($lock === null) { $message = 'admin/database/lock_check'; throw new \RuntimeException('Backup is busy'); }
            $files = [];
            foreach (glob($path.$name.'-*.sql*') ?: [] as $filename) {
                if (preg_match('/^'.preg_quote($name, '/').'-[1-9][0-9]*\.sql(?:\.gz)?$/D', basename($filename))) { $files[] = $filename; }
            }
            foreach (['json','pending'] as $suffix) {
                $filename = $path.'.'.$name.'.'.$suffix;
                if (file_exists($filename) || is_link($filename)) { $files[] = $filename; }
            }
            if (!$files) { throw new \RuntimeException('No backup files selected'); }
            // Deletion also works for incomplete archives, but never follows links or loose suffixes.
            foreach ($files as $filename) {
                if (!is_file($filename) || is_link($filename)) { throw new \RuntimeException('Invalid backup file'); }
            }
            foreach ($files as $filename) {
                if (!@unlink($filename)) { throw new \RuntimeException('Cannot delete backup file'); }
            }
            $complete = true;
        } catch (\Throwable $error) {
        } finally { if (is_resource($lock)) { flock($lock, LOCK_UN); fclose($lock); } }
        return $complete ? $this->success(lang('del_ok')) : $this->error(lang($message));
    }

    public function sql()
    {
        if($this->request->isPost()){
            $param=\think\facade\Request::param();
            $validate = mac_validate('Token');
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
                $sql = str_replace('{pre}',config('database.connections.mysql.prefix'),$sql);
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
        $param = \think\facade\Request::param();
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
            $param = \think\facade\Request::param();
            $table = isset($param['table']) ? $param['table'] : '';
            $field = isset($param['field']) ? $param['field'] : '';
            $findstr = isset($param['findstr']) ? $param['findstr'] : '';
            $tostr = isset($param['tostr']) ? $param['tostr'] : '';
            $where = isset($param['where']) ? $param['where'] : '';

            $validate = mac_validate('Token');
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
