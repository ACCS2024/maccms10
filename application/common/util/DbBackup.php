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
        $tables = [];
        foreach (Db::query('SHOW TABLES') as $row) {
            $name = current($row);
            if ($prefix === '' || strpos($name, $prefix) === 0) {
                $tables[] = $name;
            }
        }
        return $tables;
    }

    /**
     * 导出指定表到 .sql 文件。
     * @return array ['tables'=>int,'rows'=>int]
     * @throws \RuntimeException
     */
    public function export(array $tables, $file)
    {
        $fh = @fopen($file, 'w');
        if (!$fh) {
            throw new \RuntimeException("无法写入文件:{$file}");
        }
        // 预热连接后取 PDO 用于安全转义
        Db::query('SELECT 1');
        $pdo = Db::connect()->getPdo();
        if (!$pdo) {
            fclose($fh);
            throw new \RuntimeException('无法获取数据库连接');
        }

        fwrite($fh, "-- maccms-cli db:export " . date('Y-m-d H:i:s') . "\n");
        fwrite($fh, "SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n\n");

        $rowCount = 0;
        foreach ($tables as $t) {
            $create = Db::query('SHOW CREATE TABLE ' . $this->q($t));
            $ddl = $create[0]['Create Table'] ?? ($create[0]['Create View'] ?? '');
            if ($ddl === '') {
                continue;
            }
            fwrite($fh, "DROP TABLE IF EXISTS " . $this->q($t) . ";\n" . $ddl . ";\n\n");

            // 分页读取,避免一次性吃满内存
            $page = 1;
            $size = 2000;
            while (true) {
                $rows = Db::table($t)->page($page, $size)->select();
                if (empty($rows)) {
                    break;
                }
                $cols = array_keys($rows[0]);
                $colParts = [];
                foreach ($cols as $c) {
                    $colParts[] = $this->q($c);
                }
                $colList = implode(',', $colParts);
                foreach ($rows as $row) {
                    $vals = [];
                    foreach ($row as $v) {
                        $vals[] = ($v === null) ? 'NULL' : $pdo->quote((string)$v);
                    }
                    fwrite($fh, "INSERT INTO " . $this->q($t) . " ({$colList}) VALUES (" . implode(',', $vals) . ");\n");
                    $rowCount++;
                }
                if (count($rows) < $size) {
                    break;
                }
                $page++;
            }
            fwrite($fh, "\n");
        }
        fwrite($fh, "SET FOREIGN_KEY_CHECKS=1;\n");
        fclose($fh);
        return ['tables' => count($tables), 'rows' => $rowCount];
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
