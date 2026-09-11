<?php
declare(strict_types=1);

/** Explicit, additive cash-request schema. No application bootstrap and no inferred business database. */
final class CashRequestMigration
{
    public const COLUMNS = [
        'user_id'=>'int unsigned', 'request_id'=>'char(64)', 'payload_hash'=>'char(64)',
        'cash_id'=>'int unsigned', 'created_at'=>'int unsigned',
    ];
    private string $database;
    public function __construct(private PDO $pdo,private string $prefix='mac_')
    {
        if ($pdo->getAttribute(PDO::ATTR_DRIVER_NAME)!=='mysql' || !preg_match('/^[A-Za-z0-9_]{0,50}$/D',$prefix)) {
            throw new InvalidArgumentException('MySQL and a valid table prefix are required');
        }
        $this->database=(string)$pdo->query('SELECT DATABASE()')->fetchColumn();
        if ($this->database==='')throw new InvalidArgumentException('Select the target database explicitly');
    }
    public static function ddl(string $prefix): string
    {
        if (!preg_match('/^[A-Za-z0-9_]{0,50}$/D',$prefix))throw new InvalidArgumentException('Invalid table prefix');
        return 'CREATE TABLE IF NOT EXISTS `'.$prefix.'cash_request` (
  `user_id` int unsigned NOT NULL,
  `request_id` char(64) NOT NULL,
  `payload_hash` char(64) NOT NULL,
  `cash_id` int unsigned NOT NULL,
  `created_at` int unsigned NOT NULL,
  PRIMARY KEY (`user_id`, `request_id`),
  KEY `cash_request_cash` (`cash_id`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin';
    }

    private function rows(string $sql,array $params): array
    {
        $statement=$this->pdo->prepare($sql);$statement->execute($params);return $statement->fetchAll(PDO::FETCH_ASSOC);
    }
    public function preflight(): array
    {
        $params=[$this->database,$this->prefix.'cash_request'];
        $report=['database'=>$this->database,'prefix'=>$this->prefix,'blockers'=>[],'changes'=>[],'existing_rows'=>0,'deletes_existing_data'=>false];
        $tables=$this->rows('SELECT ENGINE AS engine,TABLE_COLLATION AS collation FROM information_schema.tables WHERE table_schema=? AND table_name=?',$params);
        if (!$tables) {$report['changes'][]=['id'=>'cash_request','sql'=>self::ddl($this->prefix)];return $report;}
        if (strtoupper((string)$tables[0]['engine'])!=='INNODB' || $tables[0]['collation']!=='ascii_bin')$report['blockers'][]='cash_request_engine_or_collation_requires_review';
        $columns=array_column($this->rows('SELECT COLUMN_NAME AS name,COLUMN_TYPE AS type,IS_NULLABLE AS nullable,EXTRA AS extra,COLLATION_NAME AS collation FROM information_schema.columns WHERE table_schema=? AND table_name=?',$params),null,'name');
        if (array_diff(array_keys($columns),array_keys(self::COLUMNS)))$report['blockers'][]='unexpected_columns_require_review';
        foreach (self::COLUMNS as $name=>$type) {
            $column=$columns[$name]??null;
            $actual=$column?preg_replace('/^int\(\d+\)/','int',$column['type']):null;
            if (!$column || $actual!==$type || $column['nullable']!=='NO' || $column['extra']!==''
                || (str_contains($type,'char') && $column['collation']!=='ascii_bin'))$report['blockers'][]=$name.'_requires_review';
        }
        $indexes=[];
        foreach ($this->rows('SELECT INDEX_NAME AS name,COLUMN_NAME AS column_name,NON_UNIQUE AS non_unique,SUB_PART AS sub_part FROM information_schema.statistics WHERE table_schema=? AND table_name=? ORDER BY INDEX_NAME,SEQ_IN_INDEX',$params) as $row)$indexes[$row['name']][]=$row;
        foreach (['PRIMARY'=>['user_id','request_id'],'cash_request_cash'=>['cash_id']] as $name=>$parts) {
            $index=$indexes[$name]??[];
            if (array_column($index,'column_name')!==$parts || count(array_filter($index,fn($row)=>$row['sub_part']!==null))
                || ($name==='PRIMARY' && count(array_filter($index,fn($row)=>(int)$row['non_unique']!==0))))$report['blockers'][]=$name.'_requires_review';
        }
        $report['existing_rows']=(int)$this->pdo->query('SELECT COUNT(*) FROM `'.$this->prefix.'cash_request`')->fetchColumn();
        return $report;
    }
    public function apply(): array
    {
        if ($this->pdo->inTransaction())throw new RuntimeException('Cash request schema apply must not implicitly commit an outer transaction');
        $report=$this->preflight();
        if ($report['blockers'])throw new RuntimeException('Cash request schema has preflight blockers');
        foreach ($report['changes'] as $change)$this->pdo->exec($change['sql']);
        return $this->preflight();
    }
}
