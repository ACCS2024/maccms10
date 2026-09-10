<?php
namespace app\common\util;

use think\facade\Db;

/**
 * 轻量数据库备份/恢复服务(PDO 实现,不依赖 mysqldump,供 CLI db:export / db:import 复用)。
 *
 * 设计取舍:面向开发/测试站点(数据量小)。导出为标准 .sql(DROP+CREATE+INSERT),
 * 恢复复用 mac_parse_sql(与安装器同一套 SQL 解析,支持表前缀替换)。
 * 大表请用 mysqldump;本服务以"零依赖、可移植、可被 reinstall/clone 复用"为目标。
 */
class DbBackup
{
    /** 列出当前库的表(可按前缀过滤) */
    public function listTables($prefix = '')
    {
        if (!is_string($prefix)) { throw new \InvalidArgumentException('无效表前缀'); }
        $tables = [];
        foreach (Db::query('SHOW FULL TABLES') as $row) {
            if (end($row) !== 'BASE TABLE') { continue; }
            $name = reset($row);
            if ($prefix === '' || strpos($name, $prefix) === 0) {
                $tables[] = $name;
            }
        }
        return $tables;
    }

    /**
     * Export selected base tables, publishing the complete file only after checked close.
     * InnoDB rows share one repeatable-read snapshot; other engines require a maintenance window.
     * @return array ['tables'=>int,'rows'=>int,'consistent_snapshot'=>bool]
     */
    public function export(array $tables, $file)
    {
        if (!is_string($file) || $file === '' || preg_match('/[\x00-\x1f\x7f]/', $file) || str_contains($file, '://')) {
            throw new \RuntimeException('无效输出文件');
        }
        $parent = realpath(dirname($file));
        if ($parent === false || !is_dir($parent) || basename($file) === '.' || basename($file) === '..') {
            throw new \RuntimeException('输出目录不存在');
        }
        $file = $parent.DIRECTORY_SEPARATOR.basename($file);
        if (is_link($file) || (file_exists($file) && !is_file($file))) { throw new \RuntimeException('输出必须为普通文件'); }
        if (!$tables) { throw new \RuntimeException('没有可导出的表'); }
        foreach ($tables as $table) {
            if (!is_string($table) || $table === '' || str_contains($table, "\0")) { throw new \RuntimeException('无效表名'); }
        }
        $tables = array_values(array_unique($tables));
        $metadata = array_column(Db::query('SHOW TABLE STATUS', [], true), null, 'Name');
        $consistent = true;
        foreach ($tables as $table) {
            if (!isset($metadata[$table]) || empty($metadata[$table]['Engine'])) { throw new \RuntimeException('表不存在或不是普通表'); }
            $consistent = $consistent && strtoupper($metadata[$table]['Engine']) === 'INNODB';
        }
        $pdo = Db::connect()->getPdo();
        if (!$pdo || $pdo->inTransaction()) { throw new \RuntimeException('导出需要独立数据库连接事务'); }
        $directory = null; $codec = null; $input = null; $output = null; $transaction = false;
        try {
            // Use the ORM transaction counter too: routing/reconnect must not silently lose the snapshot.
            Db::execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY');
            Db::startTrans(); $transaction = true;
            $directory = $parent.DIRECTORY_SEPARATOR.'.db-export-'.bin2hex(random_bytes(12));
            if (!@mkdir($directory, 0700)) { throw new \RuntimeException('无法创建导出临时目录'); }
            $codec = new Database(['name'=>date('Ymd-His'),'part'=>1], ['path'=>$directory,'part'=>PHP_INT_MAX,'compress'=>0]);
            if (!$codec->create()) { throw new \RuntimeException('无法创建导出文件'); }
            $rows = 0;
            foreach ($tables as $table) {
                // The first table SELECT establishes the snapshot shared by counts and all row pages.
                $rows += (int)Db::query('SELECT COUNT(*) AS total FROM '.$this->q($table))[0]['total'];
                $next = $codec->backup($table, 0);
                while (is_array($next)) { $next = $codec->backup($table, $next[0]); }
                if ($next !== 0) { throw new \RuntimeException('表导出失败'); }
            }
            if (!$codec->close()) { throw new \RuntimeException('无法关闭导出文件'); }
            Db::rollback(); $transaction = false;
            $parts = $codec->createdFiles();
            if (count($parts) !== 1) { throw new \RuntimeException('导出文件分卷异常'); }
            $complete = $directory.DIRECTORY_SEPARATOR.'complete.sql';
            $mask = umask(0077);
            try { $output = @fopen($complete, 'xb'); }
            finally { umask($mask); }
            if ($output === false) { throw new \RuntimeException('无法写入导出文件'); }
            $this->writeExport($output, "-- maccms-cli db:export\nSET @MACCMS_OLD_SQL_MODE=@@SESSION.SQL_MODE;\nSET @MACCMS_OLD_FOREIGN_KEY_CHECKS=@@SESSION.FOREIGN_KEY_CHECKS;\nSET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n");
            $input = @fopen($parts[0], 'rb');
            if ($input === false || @stream_copy_to_stream($input, $output) !== filesize($parts[0])) { throw new \RuntimeException('无法完整复制导出数据'); }
            fclose($input); $input = null;
            $this->writeExport($output, "\nSET FOREIGN_KEY_CHECKS=@MACCMS_OLD_FOREIGN_KEY_CHECKS;\nSET SQL_MODE=@MACCMS_OLD_SQL_MODE;\n");
            if (!@fflush($output) || (function_exists('fsync') && !@fsync($output))) { throw new \RuntimeException('无法刷新导出文件'); }
            $closed = @fclose($output); $output = null;
            if (!$closed || is_link($file) || (file_exists($file) && !is_file($file)) || !@rename($complete, $file)) {
                throw new \RuntimeException('无法发布完整导出文件');
            }
            return ['tables'=>count($tables), 'rows'=>$rows, 'consistent_snapshot'=>$consistent];
        } catch (\Throwable $error) {
            throw new \RuntimeException('数据库导出失败: '.$error->getMessage(), 0, $error);
        } finally {
            if (is_resource($input)) { fclose($input); }
            if (is_resource($output)) { fclose($output); }
            if ($codec !== null) { $codec->close(); }
            if ($directory !== null && is_dir($directory)) {
                foreach ($codec !== null ? $codec->createdFiles() : [] as $part) { @unlink($part); }
                if (is_file($directory.DIRECTORY_SEPARATOR.'complete.sql')) { @unlink($directory.DIRECTORY_SEPARATOR.'complete.sql'); }
                @rmdir($directory);
            }
            if ($transaction) { Db::rollback(); }
        }
    }

    private function writeExport($stream, string $bytes): void
    {
        for ($offset = 0, $length = strlen($bytes); $offset < $length;) {
            $written = @fwrite($stream, substr($bytes, $offset));
            if ($written === false || $written === 0) { throw new \RuntimeException('无法完整写入导出文件'); }
            $offset += $written;
        }
    }

    /**
     * 从 .sql 文件恢复(复用 mac_parse_sql,可选表前缀替换 ['old_'=>'new_'])。
     * @return int 执行语句数
     * @throws \RuntimeException
     */
    public function import($file, array $prefixMap = [])
    {
        if (!is_file($file)) {
            throw new \RuntimeException("文件不存在:{$file}");
        }
        $list = array_filter(mac_parse_sql(file_get_contents($file), 0, $prefixMap));
        $n = 0;
        foreach ($list as $stmt) {
            try {
                Db::execute($stmt);
                $n++;
            } catch (\Exception $e) {
                throw new \RuntimeException('第 ' . ($n + 1) . ' 条语句执行失败:' . $e->getMessage());
            }
        }
        return $n;
    }

    /** 反引号包裹(标识符来自本库 SHOW TABLES,可信;仍做转义) */
    private function q($ident)
    {
        return '`' . str_replace('`', '``', (string)$ident) . '`';
    }
}
