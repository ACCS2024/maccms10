<?php
declare(strict_types=1);

/** Add explicit thumbnail backup state without guessing or rewriting historical image pointers. */
final class VodCoverBackupMigration
{
    private string $database;
    public function __construct(private PDO $pdo, private string $prefix = 'mac_')
    {
        if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) !== 'mysql'
            || !preg_match('/^[A-Za-z0-9_]{0,50}$/D', $prefix)) {
            throw new InvalidArgumentException('MySQL and a valid table prefix are required');
        }
        $this->database = (string)$pdo->query('SELECT DATABASE()')->fetchColumn();
        if ($this->database === '') { throw new InvalidArgumentException('Select the target database explicitly'); }
    }

    private function rows(string $sql, array $values): array
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($values);
        return $statement->fetchAll(PDO::FETCH_ASSOC);
    }

    public function preflight(): array
    {
        $report = ['database'=>$this->database, 'prefix'=>$this->prefix, 'blockers'=>[], 'changes'=>[], 'rewrites_existing_data'=>false];
        $parameters = [$this->database, $this->prefix . 'vod'];
        $tables = $this->rows('SELECT ENGINE AS engine FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME=?', $parameters);
        if (count($tables) !== 1 || strtoupper((string)$tables[0]['engine']) !== 'INNODB') {
            $report['blockers'][] = 'vod_table_missing_or_not_innodb';
            return $report;
        }
        $columns = [];
        foreach ($this->rows('SELECT COLUMN_NAME AS name, DATA_TYPE AS type, IS_NULLABLE AS nullable, '
            . 'CHARACTER_MAXIMUM_LENGTH AS capacity, COLUMN_DEFAULT AS default_value FROM information_schema.COLUMNS '
            . 'WHERE TABLE_SCHEMA=? AND TABLE_NAME=?', $parameters) as $column) { $columns[$column['name']] = $column; }
        foreach (['vod_pic', 'vod_pic_thumb', 'vod_pic_original'] as $name) {
            if (!isset($columns[$name]) || $columns[$name]['type'] !== 'varchar' || (int)$columns[$name]['capacity'] < 1024) {
                $report['blockers'][] = $name . '_requires_review';
            }
        }
        $column = $columns['vod_pic_thumb_original'] ?? null;
        if ($column === null) {
            $report['changes'][] = ['id'=>'original_thumbnail', 'sql'=>'ALTER TABLE `' . $this->prefix
                . 'vod` ADD COLUMN `vod_pic_thumb_original` VARCHAR(1024) NULL DEFAULT NULL'];
        } elseif ($column['type'] !== 'varchar' || (int)$column['capacity'] !== 1024
            || $column['nullable'] !== 'YES' || $column['default_value'] !== null) {
            $report['blockers'][] = 'original_thumbnail_definition_requires_review';
        }
        return $report;
    }

    public function apply(): array
    {
        if ($this->pdo->inTransaction()) { throw new RuntimeException('Schema changes must not commit a caller transaction'); }
        $lock = 'vod-cover-schema:' . substr(hash('sha256', $this->database . '/' . $this->prefix), 0, 40);
        if ((int)$this->rows('SELECT GET_LOCK(?, 0) AS acquired', [$lock])[0]['acquired'] !== 1) {
            throw new RuntimeException('Another cover schema migration is running');
        }
        try {
            $report = $this->preflight();
            if ($report['blockers']) { throw new RuntimeException('Cover schema preflight blocked'); }
            foreach ($report['changes'] as $change) { $this->pdo->exec($change['sql']); }
            return $this->preflight();
        } finally { $this->rows('SELECT RELEASE_LOCK(?) AS released', [$lock]); }
    }
}
