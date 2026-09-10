<?php
declare(strict_types=1);

/** MySQL payment schema migration. Preflight only issues SELECT statements. */
final class PaymentSchemaMigration
{
    private string $database;

    public function __construct(private PDO $pdo, private string $prefix = 'mac_')
    {
        if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME) !== 'mysql'
            || !preg_match('/^[a-zA-Z0-9_]{0,58}$/D', $prefix)) {
            throw new InvalidArgumentException('MySQL and a valid table prefix are required');
        }
        $this->database = (string)$pdo->query('SELECT DATABASE()')->fetchColumn();
        if ($this->database === '') {
            throw new InvalidArgumentException('Select the target database explicitly');
        }
    }

    private function rows(string $sql, array $parameters = []): array
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($parameters);
        return $statement->fetchAll(PDO::FETCH_ASSOC);
    }

    public function preflight(): array
    {
        $report = ['database'=>$this->database, 'prefix'=>$this->prefix, 'blockers'=>[], 'changes'=>[]];
        $columns = [];
        foreach (['user', 'order', 'plog'] as $name) {
            $table = $this->prefix . $name;
            $metadata = $this->rows('SELECT ENGINE AS engine FROM information_schema.tables WHERE table_schema=? AND table_name=?',
                [$this->database, $table]);
            if (!$metadata || strtoupper((string)$metadata[0]['engine']) !== 'INNODB') {
                $report['blockers'][] = $name . '_table_missing_or_not_innodb';
                continue;
            }
            foreach ($this->rows('SELECT COLUMN_NAME AS name, DATA_TYPE AS type, COLUMN_TYPE AS declaration,
                IS_NULLABLE AS nullable, CHARACTER_MAXIMUM_LENGTH AS max_length
                FROM information_schema.columns WHERE table_schema=? AND table_name=?', [$this->database, $table]) as $column) {
                $columns[$name][$column['name']] = $column;
            }
        }
        foreach (['user'=>['user_points'], 'order'=>['order_id','order_code','order_points'], 'plog'=>['plog_points']] as $table=>$required) {
            foreach ($required as $column) {
                if (!isset($columns[$table][$column])) { $report['blockers'][] = $table . '_' . $column . '_missing'; }
            }
        }
        if ($report['blockers']) { return $report; }

        $code = $columns['order']['order_code'];
        if (!in_array($code['type'], ['char','varchar'], true) || $code['nullable'] !== 'NO'
            || (int)$code['max_length'] > 191) {
            $report['blockers'][] = 'order_code_definition_requires_manual_review';
        }
        $orderTable = '`' . $this->prefix . 'order`';
        $report['blank_order_codes'] = (int)$this->pdo->query('SELECT COUNT(*) FROM ' . $orderTable
            . " WHERE order_code IS NULL OR TRIM(order_code) = ''")->fetchColumn();
        if ($report['blank_order_codes'] > 0) { $report['blockers'][] = 'blank_order_codes_require_manual_reconciliation'; }
        $duplicates = $this->rows('SELECT COUNT(*) AS groups_count, COALESCE(SUM(n - 1), 0) AS excess_rows FROM
            (SELECT COUNT(*) AS n FROM ' . $orderTable . ' GROUP BY order_code HAVING COUNT(*) > 1) AS duplicate_codes')[0];
        $report['duplicate_groups'] = (int)$duplicates['groups_count'];
        $report['duplicate_excess_rows'] = (int)$duplicates['excess_rows'];
        if ($report['duplicate_groups'] > 0) {
            $report['blockers'][] = 'duplicate_order_codes_require_manual_reconciliation';
            // IDs locate the rows for an operator; never dump raw order codes or user records.
            $report['duplicate_samples'] = $this->rows('SELECT MIN(order_id) AS first_order_id, MAX(order_id) AS last_order_id,
                COUNT(*) AS row_count FROM ' . $orderTable . ' GROUP BY order_code HAVING COUNT(*) > 1 LIMIT 20');
        }

        $indexes = [];
        foreach ($this->rows('SELECT INDEX_NAME AS name, NON_UNIQUE AS non_unique, COLUMN_NAME AS column_name,
            SUB_PART AS sub_part FROM information_schema.statistics
            WHERE table_schema=? AND table_name=? ORDER BY INDEX_NAME, SEQ_IN_INDEX', [$this->database, $this->prefix . 'order']) as $index) {
            $indexes[$index['name']][] = $index;
        }
        $hasUnique = false;
        foreach ($indexes as $parts) {
            if (count($parts) === 1 && (int)$parts[0]['non_unique'] === 0 && $parts[0]['column_name'] === 'order_code'
                && $parts[0]['sub_part'] === null) { $hasUnique = true; }
        }
        if (!$hasUnique) {
            $ordinary = $indexes['order_code'] ?? [];
            if (count($ordinary) === 1 && $ordinary[0]['column_name'] === 'order_code' && $ordinary[0]['sub_part'] === null) {
                $alter = 'DROP INDEX `order_code`, ADD UNIQUE INDEX `order_code` (`order_code`)';
            } elseif (!isset($indexes['uniq_order_code'])) {
                $alter = 'ADD UNIQUE INDEX `uniq_order_code` (`order_code`)';
            } else {
                $alter = '';
                $report['blockers'][] = 'uniq_order_code_index_name_conflict';
            }
            if ($alter !== '') {
                $report['changes'][] = ['id'=>'unique_order_code', 'sql'=>'ALTER TABLE ' . $orderTable . ' ' . $alter
                    . ', ALGORITHM=INPLACE, LOCK=SHARED'];
            }
        }

        foreach (['user'=>'user_points','order'=>'order_points'] as $table=>$column) {
            if (!in_array($columns[$table][$column]['type'], ['tinyint','smallint','mediumint','int'], true)) {
                $report['blockers'][] = $table . '_points_capacity_requires_manual_review';
            }
        }
        $points = $columns['plog']['plog_points'];
        $report['ledger_points_type'] = $points['declaration'];
        if (!in_array($points['type'], ['tinyint','smallint','mediumint','int','bigint'], true)) {
            $report['blockers'][] = 'ledger_points_definition_requires_manual_review';
        } elseif ($points['type'] !== 'bigint' && !($points['type'] === 'int' && str_contains($points['declaration'], 'unsigned'))) {
            $plogTable = '`' . $this->prefix . 'plog`';
            $invalid = (int)$this->pdo->query('SELECT COUNT(*) FROM ' . $plogTable
                . ' WHERE plog_points IS NULL OR plog_points < 0 OR plog_points > 4294967295')->fetchColumn();
            if ($invalid > 0) { $report['blockers'][] = 'ledger_points_values_require_manual_reconciliation'; }
            $report['changes'][] = ['id'=>'widen_ledger_points', 'sql'=>'ALTER TABLE ' . $plogTable
                . ' MODIFY COLUMN `plog_points` INT UNSIGNED NOT NULL DEFAULT 0, ALGORITHM=COPY, LOCK=SHARED'];
        }
        return $report;
    }

    /** DDL commits implicitly. A failed/partial run must be inspected and safely rerun. */
    public function apply(): array
    {
        $lock = 'payment-schema:' . substr(hash('sha256', $this->database . '/' . $this->prefix), 0, 40);
        if ((int)$this->rows('SELECT GET_LOCK(?, 0) AS acquired', [$lock])[0]['acquired'] !== 1) {
            throw new RuntimeException('Another payment schema migration is running');
        }
        try {
            $before = $this->preflight();
            if ($before['blockers']) { throw new RuntimeException('Preflight blocked; no schema changes applied'); }
            foreach ($before['changes'] as $change) { $this->pdo->exec($change['sql']); }
            return $this->preflight();
        } finally {
            $this->rows('SELECT RELEASE_LOCK(?) AS released', [$lock]);
        }
    }
}
