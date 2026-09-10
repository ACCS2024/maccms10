<?php
namespace app\common\util;

use think\facade\Db;

/**
 * 轻量数据库备份/恢复服务(PDO 实现,不依赖 mysqldump,供 CLI db:export / db:import 复用)。
 *
 * 设计取舍:面向开发/测试站点(数据量小)。导出为标准 .sql(DROP+CREATE+INSERT),
 * 恢复流式扫描 SQL 语句,仅对带反引号表名进行前缀替换。
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

    /** Import a trusted local table dump without buffering the whole file or changing quoted data. */
    public function import($file, array $prefixMap = [])
    {
        if (!is_string($file) || $file === '' || str_contains($file, "\0") || str_contains($file, '://')
            || !is_file($file) || is_link($file)) { throw new \RuntimeException('导入文件必须是可读普通文件'); }
        $stream = null; $settings = null; $count = 0;
        try {
            $stream = @fopen($file, 'rb');
            if ($stream === false || !@flock($stream, LOCK_SH | LOCK_NB)) { throw new \RuntimeException('无法打开或锁定导入文件'); }
            $reader = new SqlDumpStream($stream, $prefixMap);
            // Capture the write connection: DDL in a dump must never commit a caller-owned transaction.
            $saved = Db::query('SELECT @@SESSION.sql_mode AS mode, @@SESSION.foreign_key_checks AS fk, @@SESSION.autocommit AS autocommit, @@SESSION.character_set_client AS client, @@SESSION.character_set_results AS results, @@SESSION.collation_connection AS collation', [], true)[0];
            if (Db::connect()->getPdo()->inTransaction()) { throw new \RuntimeException('导入需要独立数据库连接事务'); }
            $settings = $saved;
            Db::execute('SET SESSION AUTOCOMMIT=1');
            Db::execute("SET SESSION SQL_MODE='NO_AUTO_VALUE_ON_ZERO'");
            Db::execute('SET SESSION FOREIGN_KEY_CHECKS=0');
            $statements = 0;
            foreach ($reader->statements() as $statement) { $statements++; }
            if ($statements === 0) { throw new \RuntimeException('导入文件没有 SQL 语句'); }
            if (!rewind($stream)) { throw new \RuntimeException('无法重新读取导入文件'); }
            // A lexical preflight catches unterminated quotes/comments before the first DROP executes.
            $reader = new SqlDumpStream($stream, $prefixMap);
            foreach ($reader->statements() as $statement) {
                Db::execute($statement); $count++;
            }
            if (Db::connect()->getPdo()->inTransaction()) { throw new \RuntimeException('导入文件中的事务未结束'); }
            return $count;
        } catch (\Throwable $error) {
            throw new \RuntimeException('第 '.($count+1).' 条语句前后导入失败: '.$error->getMessage(), 0, $error);
        } finally {
            if (is_resource($stream)) { flock($stream, LOCK_UN); fclose($stream); }
            if ($settings !== null) {
                $pdo = Db::connect()->getPdo();
                if ($pdo && $pdo->inTransaction()) { Db::rollback(); }
                Db::execute('SET SESSION FOREIGN_KEY_CHECKS='.(int)$settings['fk'].', AUTOCOMMIT='.(int)$settings['autocommit']);
                Db::execute('SET SESSION SQL_MODE=?', [$settings['mode']]);
                Db::execute('SET SESSION character_set_client=?, character_set_results=?, collation_connection=?', [$settings['client'],$settings['results'],$settings['collation']]);
            }
        }
    }

    /** 反引号包裹(标识符来自本库 SHOW TABLES,可信;仍做转义) */
    private function q($ident)
    {
        return '`' . str_replace('`', '``', (string)$ident) . '`';
    }
}
