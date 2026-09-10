<?php
declare(strict_types=1);

/** Explicit, additive transfer-intent schema. No application bootstrap and no inferred business database. */
final class StorageIntentMigration
{
    public const COLUMNS = [
        'intent_id'=>'char(32)','provider'=>'varchar(16)','destination_hash'=>'char(64)',
        'scope'=>'varchar(16)','owner_id'=>'int unsigned','local_path'=>'varchar(255)',
        'source_bytes'=>'int unsigned','source_sha256'=>'char(64)','expected_url'=>'varchar(2048)',
        'remote_url'=>'varchar(2048)','transfer_state'=>'varchar(24)','reference_state'=>'varchar(16)',
        'annex_id'=>'int unsigned','result_code'=>'varchar(32)','created_at'=>'int unsigned','updated_at'=>'int unsigned',
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
        return 'CREATE TABLE IF NOT EXISTS `'.$prefix.'storage_intent` (
            `intent_id` CHAR(32) NOT NULL,
            `provider` VARCHAR(16) NOT NULL,
            `destination_hash` CHAR(64) NOT NULL,
            `scope` VARCHAR(16) NOT NULL,
            `owner_id` INT UNSIGNED NOT NULL DEFAULT 0,
            `local_path` VARCHAR(255) NOT NULL,
            `source_bytes` INT UNSIGNED NOT NULL,
            `source_sha256` CHAR(64) NOT NULL,
            `expected_url` VARCHAR(2048) NOT NULL,
            `remote_url` VARCHAR(2048) NOT NULL DEFAULT \'\',
            `transfer_state` VARCHAR(24) NOT NULL,
            `reference_state` VARCHAR(16) NOT NULL,
            `annex_id` INT UNSIGNED NOT NULL DEFAULT 0,
            `result_code` VARCHAR(32) NOT NULL DEFAULT \'\',
            `created_at` INT UNSIGNED NOT NULL,
            `updated_at` INT UNSIGNED NOT NULL,
            PRIMARY KEY (`intent_id`),
            UNIQUE KEY `storage_intent_path` (`local_path`),
            KEY `storage_intent_pending` (`reference_state`,`transfer_state`,`updated_at`),
            KEY `storage_intent_owner` (`scope`,`owner_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin';
    }
    private function rows(string $sql,array $params): array
    {
        $statement=$this->pdo->prepare($sql);$statement->execute($params);return $statement->fetchAll(PDO::FETCH_ASSOC);
    }
    public function preflight(): array
    {
        $params=[$this->database,$this->prefix.'storage_intent'];
        $report=['database'=>$this->database,'prefix'=>$this->prefix,'blockers'=>[],'changes'=>[],'existing_rows'=>0,'deletes_existing_data'=>false];
        $tables=$this->rows('SELECT ENGINE AS engine,TABLE_COLLATION AS collation FROM information_schema.tables WHERE table_schema=? AND table_name=?',$params);
        if (!$tables) {$report['changes'][]=['id'=>'storage_intent','sql'=>self::ddl($this->prefix)];return $report;}
        if (strtoupper((string)$tables[0]['engine'])!=='INNODB' || $tables[0]['collation']!=='ascii_bin')$report['blockers'][]='storage_intent_engine_or_collation_requires_review';
        $columns=array_column($this->rows('SELECT COLUMN_NAME AS name,COLUMN_TYPE AS type,IS_NULLABLE AS nullable,EXTRA AS extra,COLLATION_NAME AS collation FROM information_schema.columns WHERE table_schema=? AND table_name=?',$params),null,'name');
        foreach (self::COLUMNS as $name=>$type) {
            $column=$columns[$name]??null;
            $actual=$column?preg_replace('/^int\(\d+\)/','int',$column['type']):null;
            if (!$column || $actual!==$type || $column['nullable']!=='NO' || $column['extra']!==''
                || (str_contains($type,'char') && $column['collation']!=='ascii_bin'))$report['blockers'][]=$name.'_requires_review';
        }
        $indexes=[];
        foreach ($this->rows('SELECT INDEX_NAME AS name,COLUMN_NAME AS column_name,NON_UNIQUE AS non_unique,SUB_PART AS sub_part FROM information_schema.statistics WHERE table_schema=? AND table_name=? ORDER BY INDEX_NAME,SEQ_IN_INDEX',$params) as $row)$indexes[$row['name']][]=$row;
        foreach (['PRIMARY'=>['intent_id'],'storage_intent_path'=>['local_path'],'storage_intent_pending'=>['reference_state','transfer_state','updated_at'],'storage_intent_owner'=>['scope','owner_id']] as $name=>$parts) {
            $index=$indexes[$name]??[];
            if (array_column($index,'column_name')!==$parts || count(array_filter($index,fn($row)=>$row['sub_part']!==null))
                || (in_array($name,['PRIMARY','storage_intent_path'],true) && count(array_filter($index,fn($row)=>(int)$row['non_unique']!==0))))$report['blockers'][]=$name.'_requires_review';
        }
        $report['existing_rows']=(int)$this->pdo->query('SELECT COUNT(*) FROM `'.$this->prefix.'storage_intent`')->fetchColumn();
        return $report;
    }
    public function apply(): array
    {
        if ($this->pdo->inTransaction())throw new RuntimeException('Storage schema apply must not implicitly commit an outer transaction');
        $report=$this->preflight();
        if ($report['blockers'])throw new RuntimeException('Storage intent schema has preflight blockers');
        foreach ($report['changes'] as $change)$this->pdo->exec($change['sql']);
        return $this->preflight();
    }
}
