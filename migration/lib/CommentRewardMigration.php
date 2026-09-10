<?php
declare(strict_types=1);

/** Establishes a forward-only comment provenance boundary; old rows are never promoted. */
final class CommentRewardMigration
{
    private string $database;
    public function __construct(private PDO $pdo, private string $prefix = 'mac_')
    {
        if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) !== 'mysql' || !preg_match('/^[A-Za-z0-9_]{0,57}$/D', $prefix)) {
            throw new InvalidArgumentException('MySQL and a valid table prefix are required');
        }
        $this->database = (string)$pdo->query('SELECT DATABASE()')->fetchColumn();
        if ($this->database === '') { throw new InvalidArgumentException('Select the target database explicitly'); }
    }
    private function rows(string $sql, array $params): array
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        return $statement->fetchAll(PDO::FETCH_ASSOC);
    }
    public function preflight(): array
    {
        $params = [$this->database, $this->prefix . 'comment'];
        $table = '`' . $this->prefix . 'comment`';
        $report = ['database'=>$this->database, 'prefix'=>$this->prefix, 'blockers'=>[], 'changes'=>[],
            'existing_rows'=>0, 'verified_rows'=>0, 'backfill_verified'=>false];
        $engine = $this->rows('SELECT ENGINE AS engine FROM information_schema.tables WHERE table_schema=? AND table_name=?', $params);
        if (!$engine || strtoupper((string)$engine[0]['engine']) !== 'INNODB') {
            $report['blockers'][] = 'comment_table_missing_or_not_innodb';
            return $report;
        }
        $columns = array_column($this->rows('SELECT COLUMN_NAME AS name, COLUMN_TYPE AS type, IS_NULLABLE AS nullable, COLUMN_DEFAULT AS default_value, EXTRA AS extra FROM information_schema.columns WHERE table_schema=? AND table_name=?', $params), null, 'name');
        foreach (['comment_id','user_id','comment_status','comment_time','comment_content'] as $column) {
            if (!isset($columns[$column])) { $report['blockers'][] = $column . '_missing'; }
        }
        $report['existing_rows'] = (int)$this->pdo->query('SELECT COUNT(*) FROM ' . $table)->fetchColumn();
        $changes = [];
        if (!isset($columns['comment_reward_verified'])) {
            $changes[] = 'ADD COLUMN `comment_reward_verified` TINYINT UNSIGNED NOT NULL DEFAULT 0';
        } else {
            $column = $columns['comment_reward_verified'];
            if (!preg_match('/^tinyint(?:\(\d+\))? unsigned$/D', $column['type']) || $column['nullable'] !== 'NO'
                || (string)$column['default_value'] !== '0' || stripos($column['extra'], 'generated') !== false) {
                $report['blockers'][] = 'provenance_column_requires_manual_review';
            }
            $invalid = (int)$this->pdo->query('SELECT COUNT(*) FROM ' . $table . ' WHERE comment_reward_verified IS NULL OR comment_reward_verified NOT IN (0,1)')->fetchColumn();
            if ($invalid > 0) { $report['blockers'][] = 'invalid_provenance_values_require_manual_review'; }
            $report['verified_rows'] = (int)$this->pdo->query('SELECT COUNT(*) FROM ' . $table . ' WHERE comment_reward_verified=1')->fetchColumn();
        }
        $indexes = [];
        foreach ($this->rows('SELECT INDEX_NAME AS name, COLUMN_NAME AS column_name, SUB_PART AS sub_part FROM information_schema.statistics WHERE table_schema=? AND table_name=? ORDER BY INDEX_NAME,SEQ_IN_INDEX', $params) as $row) {
            $indexes[$row['name']][] = $row;
        }
        $hasIndex = false;
        foreach ($indexes as $parts) {
            $parts = array_slice($parts, 0, 4);
            if (array_column($parts, 'column_name') === ['user_id','comment_reward_verified','comment_status','comment_time']
                && count(array_filter($parts, static fn($part) => $part['sub_part'] !== null)) === 0) { $hasIndex = true; }
        }
        if (!$hasIndex) {
            if (isset($indexes['comment_reward_user'])) { $report['blockers'][] = 'provenance_index_name_requires_manual_review'; }
            else { $changes[] = 'ADD INDEX `comment_reward_user` (`user_id`,`comment_reward_verified`,`comment_status`,`comment_time`)'; }
        }
        if ($changes) { $report['changes'][] = ['id'=>'comment_reward_provenance', 'sql'=>'ALTER TABLE ' . $table . ' ' . implode(', ', $changes)]; }
        return $report;
    }
    public function apply(): array
    {
        $report = $this->preflight();
        if ($report['blockers']) { throw new RuntimeException('Comment reward preflight has blockers'); }
        foreach ($report['changes'] as $change) { $this->pdo->exec($change['sql']); }
        return $this->preflight();
    }
}
