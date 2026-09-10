<?php
declare(strict_types=1);

/** Explicit MySQL-only migration; preflight performs SELECTs and never changes ledger rows. */
final class LedgerVisibilityMigration
{
    private string $database;
    public function __construct(private PDO $pdo, private string $prefix = 'mac_')
    {
        if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) !== 'mysql' || !preg_match('/^[A-Za-z0-9_]{0,58}$/D', $prefix)) {
            throw new InvalidArgumentException('MySQL and a valid table prefix are required');
        }
        $this->database = (string)$pdo->query('SELECT DATABASE()')->fetchColumn();
        if ($this->database === '') { throw new InvalidArgumentException('Select the target database explicitly'); }
    }
    private function rows(string $sql, array $params): array
    {
        $statement = $this->pdo->prepare($sql); $statement->execute($params);
        return $statement->fetchAll(PDO::FETCH_ASSOC);
    }
    public function preflight(): array
    {
        $params = [$this->database, $this->prefix.'plog'];
        $report = ['database'=>$this->database, 'prefix'=>$this->prefix, 'blockers'=>[], 'changes'=>[]];
        $engine = $this->rows('SELECT ENGINE AS engine FROM information_schema.tables WHERE table_schema=? AND table_name=?', $params);
        if (!$engine || strtoupper((string)$engine[0]['engine']) !== 'INNODB') {
            $report['blockers'][] = 'ledger_table_missing_or_not_innodb'; return $report;
        }
        $columns = array_column($this->rows('SELECT COLUMN_NAME AS name, COLUMN_TYPE AS type, IS_NULLABLE AS nullable, COLUMN_DEFAULT AS default_value FROM information_schema.columns WHERE table_schema=? AND table_name=?', $params), null, 'name');
        foreach (['plog_id','user_id','plog_points'] as $name) {
            if (!isset($columns[$name])) { $report['blockers'][] = $name.'_missing'; }
        }
        $changes = [];
        if (!isset($columns['plog_user_hidden'])) {
            $changes[] = 'ADD COLUMN `plog_user_hidden` TINYINT UNSIGNED NOT NULL DEFAULT 0';
        } else {
            $column = $columns['plog_user_hidden'];
            if (!preg_match('/^tinyint(?:\(\d+\))? unsigned$/D', $column['type']) || $column['nullable'] !== 'NO' || (string)$column['default_value'] !== '0') {
                $report['blockers'][] = 'visibility_column_requires_manual_review';
            }
            $invalid = (int)$this->pdo->query('SELECT COUNT(*) FROM `'.$this->prefix.'plog` WHERE plog_user_hidden IS NULL OR plog_user_hidden NOT IN (0,1)')->fetchColumn();
            if ($invalid > 0) { $report['blockers'][] = 'invalid_visibility_values_require_manual_review'; }
        }
        $indexes = [];
        foreach ($this->rows('SELECT INDEX_NAME AS name, COLUMN_NAME AS column_name, SUB_PART AS sub_part, NON_UNIQUE AS non_unique FROM information_schema.statistics WHERE table_schema=? AND table_name=? ORDER BY INDEX_NAME,SEQ_IN_INDEX', $params) as $row) {
            $indexes[$row['name']][] = $row;
        }
        $hasIndex = false;
        foreach ($indexes as $parts) {
            if (array_column($parts,'column_name') === ['user_id','plog_user_hidden','plog_id']
                && count(array_filter($parts, static fn($part)=>$part['sub_part'] !== null)) === 0) { $hasIndex = true; }
        }
        if (!$hasIndex) {
            if (isset($indexes['user_visibility'])) { $report['blockers'][] = 'visibility_index_name_requires_manual_review'; }
            else { $changes[] = 'ADD INDEX `user_visibility` (`user_id`,`plog_user_hidden`,`plog_id`)'; }
        }
        if ($changes) { $report['changes'][] = ['id'=>'ledger_user_visibility','sql'=>'ALTER TABLE `'.$this->prefix.'plog` '.implode(', ', $changes)]; }
        return $report;
    }
    public function apply(): array
    {
        // Revalidate immediately before DDL; never reuse an operator's stale preflight output.
        $report = $this->preflight();
        if ($report['blockers']) { throw new RuntimeException('Ledger visibility preflight has blockers'); }
        foreach ($report['changes'] as $change) { $this->pdo->exec($change['sql']); }
        return $this->preflight();
    }
}
