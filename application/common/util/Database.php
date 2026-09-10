<?php
namespace app\common\util;

use think\facade\Db;

/** Checked, partitioned MySQL dump IO used by the authenticated admin backup flow. */
class Database
{
    private $fp = null;
    private array $file;
    private array $config;
    private int $size = 0;
    private array $createdFiles = [];
    private array $validatedGzip = [];

    public function __construct($file, $config, $type = 'export')
    {
        if (!is_array($file) || !is_array($config) || !is_string($config['path'] ?? null)
            || str_contains($config['path'], "\0") || !is_dir($config['path'])) {
            throw new \InvalidArgumentException('Invalid backup directory');
        }
        $root = realpath($config['path']);
        if ($root === false) { throw new \InvalidArgumentException('Invalid backup directory'); }
        $compress = $config['compress'] ?? 0;
        if (!in_array($compress, [0,1,'0','1',false,true], true)) { throw new \InvalidArgumentException('Invalid compression option'); }
        $part = filter_var($config['part'] ?? 20971520, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]);
        $level = filter_var($config['level'] ?? 6, FILTER_VALIDATE_INT, ['options'=>['min_range'=>0,'max_range'=>9]]);
        $this->config = ['path'=>rtrim($root, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR,'compress'=>(bool)$compress,'part'=>$part,'level'=>$level];
        if ($part === false || $level === false) {
            throw new \InvalidArgumentException('Invalid backup size or compression level');
        }
        $this->file = $file;
        if (!isset($file[1]) && (!is_string($file['name'] ?? null) || !preg_match('/^\d{8}-\d{6}$/D', $file['name'])
            || filter_var($file['part'] ?? null, FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) === false)) {
            throw new \InvalidArgumentException('Invalid backup part name');
        }
    }

    private function header(): string
    {
        return "-- MySQL backup\n-- Part: ".$this->file['part']."\n-- Date: ".date('Y-m-d H:i:s')."\n"
            ."SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n\n";
    }

    private function openPart(): bool
    {
        $filename = $this->config['path'].$this->file['name'].'-'.$this->file['part'].'.sql'.($this->config['compress']?'.gz':'');
        // Never append to or truncate a previous backup with the same timestamp.
        $previousMask = umask(0077);
        try { $reserved = @fopen($filename, 'xb'); }
        finally { umask($previousMask); }
        if ($reserved === false) { return false; }
        $this->createdFiles[] = $filename;
        if ($this->config['compress']) {
            fclose($reserved);
            $this->fp = @gzopen($filename, 'wb'.$this->config['level']);
        } else {
            $this->fp = $reserved;
        }
        $this->size = 0;
        return is_resource($this->fp) && $this->writeBytes($this->header());
    }

    private function writeBytes(string $sql): bool
    {
        if (!is_resource($this->fp)) { return false; }
        $length = strlen($sql);
        for ($offset = 0; $offset < $length;) {
            $written = $this->config['compress'] ? @gzwrite($this->fp, substr($sql, $offset)) : @fwrite($this->fp, substr($sql, $offset));
            if ($written === false || $written === 0) { return false; }
            $offset += $written;
        }
        $this->size += $length;
        return true;
    }

    private function write(string $sql): bool
    {
        if (!is_resource($this->fp) && !$this->openPart()) { return false; }
        // Partition by uncompressed bytes. One complete statement may exceed the limit.
        if ($this->size > strlen($this->header()) && $this->size + strlen($sql) > $this->config['part']) {
            if (!$this->close()) { return false; }
            $this->file['part']++;
            if (!$this->openPart()) { return false; }
        }
        return $this->writeBytes($sql);
    }

    public function create()
    {
        try { return !is_resource($this->fp) && $this->openPart(); }
        catch (\Throwable $error) { return false; }
    }

    private function quoteIdentifier($identifier): string
    {
        if (!is_string($identifier) || $identifier === '' || str_contains($identifier, "\0")) {
            throw new \InvalidArgumentException('Invalid SQL identifier');
        }
        return '`'.str_replace('`', '``', $identifier).'`';
    }

    private function connectionEncoding(): array
    {
        return Db::query('SELECT @@SESSION.character_set_client AS client, @@SESSION.character_set_results AS results, @@SESSION.collation_connection AS collation')[0];
    }

    private function restoreEncoding(array $encoding): void
    {
        Db::execute('SET SESSION character_set_client=?, character_set_results=?, collation_connection=?', [$encoding['client'],$encoding['results'],$encoding['collation']]);
    }

    public function backup($table, $start)
    {
        $encoding = null;
        try {
            $start = filter_var($start, FILTER_VALIDATE_INT, ['options'=>['min_range'=>0]]);
            if ($start === false) { return false; }
            $quotedTable = $this->quoteIdentifier($table);
            $encoding = $this->connectionEncoding();
            Db::execute('SET NAMES utf8mb4');
            $structure = Db::query('SHOW CREATE TABLE '.$quotedTable);
            if (!isset($structure[0]['Create Table'])) { return false; }
            if ($start === 0 && !$this->write('DROP TABLE IF EXISTS '.$quotedTable.";\n".$structure[0]['Create Table'].";\n")) { return false; }
            $columns = [];
            foreach (Db::query('SHOW FULL COLUMNS FROM '.$quotedTable) as $column) {
                if (!preg_match('/(?:VIRTUAL|STORED) GENERATED/i', (string)$column['Extra'])) {
                    $columns[$column['Field']] = preg_match('/^bit\b/i', $column['Type']) ? 'bit'
                        : (preg_match('/blob|binary/i', $column['Type']) ? 'binary'
                            : (preg_match('/^(?:tinyint|smallint|mediumint|int|bigint|decimal|numeric|float|double|real|year)\b/i', $column['Type']) ? 'numeric' : 'text'));
                }
            }
            $columnList = implode(',', array_map([$this,'quoteIdentifier'], array_keys($columns)));
            $selected = [];
            foreach ($columns as $field=>$kind) {
                $quotedField = $this->quoteIdentifier($field);
                $selected[] = $kind === 'bit' ? 'CAST('.$quotedField.' AS UNSIGNED) AS '.$quotedField
                    : ($kind === 'numeric' ? 'CAST('.$quotedField.' AS CHAR) AS '.$quotedField : $quotedField);
            }
            $rows = Db::query('SELECT '.implode(',', $selected).' FROM '.$quotedTable.' LIMIT ?, 1000', [$start]);
            foreach ($rows as $row) {
                $values = [];
                foreach ($row as $field=>$value) {
                    // Hex string literals preserve CR/LF, NUL and quoting across SQL modes.
                    // Text gets an explicit connection charset; BLOB stays binary and BIT uses an unsigned literal.
                    if ($columns[$field] === 'bit' && $value !== null) {
                        if (!ctype_digit((string)$value)) { return false; }
                        $values[] = (string)$value;
                    } else {
                        $values[] = $value === null ? 'NULL' : ($columns[$field] === 'binary' ? '' : '_utf8mb4 ')."X'".bin2hex((string)$value)."'";
                    }
                }
                if (!$this->write('INSERT INTO '.$quotedTable.' ('.$columnList.') VALUES ('.implode(',',$values).");\n")) { return false; }
            }
            if (count($rows) === 1000) {
                $count = (int)(Db::query('SELECT COUNT(*) AS total FROM '.$quotedTable)[0]['total'] ?? 0);
                if ($count > $start + 1000) { return [$start+1000,$count]; }
            }
            return 0;
        } catch (\Throwable $error) { return false; }
        finally { if ($encoding !== null) { $this->restoreEncoding($encoding); } }
    }

    /** Read a complete statement while respecting quoted strings and SQL comments. */
    private function readStatement($stream): ?string
    {
        $sql = ''; $quote = ''; $block = false; $hasSql = false;
        while (($line = $this->config['compress'] ? gzgets($stream) : fgets($stream)) !== false) {
            $lineComment = false;
            for ($i=0, $length=strlen($line); $i<$length; $i++) {
                $char=$line[$i]; $next=$line[$i+1]??''; $sql.=$char;
                if ($lineComment) { continue; }
                if ($block) {
                    if ($char==='*' && $next==='/') { $sql.=$next; $i++; $block=false; }
                    continue;
                }
                if ($quote!=='') {
                    if ($char==='\\') { if ($next!=='') { $sql.=$next; $i++; } }
                    elseif ($char===$quote) {
                        if ($next===$quote) { $sql.=$next; $i++; } else { $quote=''; }
                    }
                    continue;
                }
                if ($char==='/' && $next==='*') {
                    $block=true; $hasSql = $hasSql || ($line[$i+2]??'')==='!'; $sql.=$next; $i++; continue;
                }
                if ($char==='#' || ($char==='-' && $next==='-' && ctype_space($line[$i+2]??' '))) { $lineComment=true; continue; }
                if ($char===';' ) {
                    $remaining=$length-$i-1;
                    if ($hasSql && $remaining>0) {
                        $position=($this->config['compress'] ? gztell($stream) : ftell($stream))-$remaining;
                        $status=$this->config['compress'] ? gzseek($stream,$position) : fseek($stream,$position);
                        if ($status!==0) { throw new \RuntimeException('Cannot position backup stream'); }
                    }
                    if ($hasSql) { return $sql; }
                    $sql=''; continue;
                }
                if (!ctype_space($char)) { $hasSql=true; }
                if ($char==="'" || $char==='"' || $char==='`') { $quote=$char; }
            }
        }
        if ($hasSql || $quote!=='' || $block) { throw new \RuntimeException('Incomplete backup statement'); }
        return null;
    }

    /** Validate gzip framing/CRC before executing statements, with bounded inflate chunks. */
    private function validGzip(string $filename): bool
    {
        clearstatcache(true, $filename);
        $stat = stat($filename);
        $fingerprint = [$stat['ino'], $stat['size'], $stat['mtime']];
        if (($this->validatedGzip[$filename] ?? null) === $fingerprint) { return true; }
        $stream = @fopen($filename, 'rb');
        if ($stream === false) { return false; }
        try {
            $inflate = inflate_init(ZLIB_ENCODING_GZIP);
            while (!feof($stream)) {
                $chunk = fread($stream, 4096);
                if ($chunk === false || ($chunk === '' && !feof($stream))) { return false; }
                if (@inflate_add($inflate, $chunk, ZLIB_SYNC_FLUSH) === false) { return false; }
                if (inflate_get_status($inflate) === ZLIB_STREAM_END) {
                    if (inflate_get_read_len($inflate) !== $stat['size']) { return false; }
                    $this->validatedGzip[$filename] = $fingerprint;
                    return true;
                }
            }
            return false;
        } finally { fclose($stream); }
    }

    public function import($start)
    {
        $stream=null; $foreignKeys=null; $sqlMode=null; $encoding=null;
        try {
            $start=filter_var($start,FILTER_VALIDATE_INT,['options'=>['min_range'=>0]]);
            $filename=$this->file[1]??null;
            if ($start===false || !is_string($filename) || !is_file($filename) || is_link($filename)
                || dirname((string)realpath($filename)).DIRECTORY_SEPARATOR!==$this->config['path']) { return false; }
            if ($this->config['compress']) {
                if (!$this->validGzip($filename)) { return false; }
                $stream=@gzopen($filename,'rb'); $size=0;
            } else {
                $size=filesize($filename);
                if ($size===0 || $start>$size) { return false; }
                $stream=@fopen($filename,'rb');
            }
            if (!is_resource($stream)) { return false; }
            if (($this->config['compress'] ? gzseek($stream,$start) : fseek($stream,$start))!==0) { return false; }
            $settings=Db::query('SELECT @@SESSION.foreign_key_checks AS fk, @@SESSION.sql_mode AS mode')[0];
            $foreignKeys=(int)$settings['fk'];$sqlMode=$settings['mode'];
            $encoding=$this->connectionEncoding();
            // Preserve explicit AUTO_INCREMENT zero values and the connection's original settings.
            Db::execute('SET SESSION FOREIGN_KEY_CHECKS=0');
            Db::execute("SET SESSION sql_mode='NO_AUTO_VALUE_ON_ZERO'");
            for ($i=0;$i<1000;$i++) {
                $sql=$this->readStatement($stream);
                if ($sql===null) { return $start===0 && $i===0 ? false : 0; }
                Db::execute($sql);
            }
            return [$this->config['compress']?gztell($stream):ftell($stream),$size];
        } catch (\Throwable $error) { return false; }
        finally {
            if (is_resource($stream)) { $this->config['compress']?@gzclose($stream):@fclose($stream); }
            if ($foreignKeys!==null) { Db::execute('SET SESSION FOREIGN_KEY_CHECKS='.$foreignKeys); }
            if ($sqlMode!==null) { Db::execute('SET SESSION sql_mode=?',[$sqlMode]); }
            if ($encoding!==null) { $this->restoreEncoding($encoding); }
        }
    }

    public function close(): bool
    {
        if (!is_resource($this->fp)) { $this->fp=null; return true; }
        $stream=$this->fp;$this->fp=null;
        try { return $this->config['compress'] ? @gzclose($stream) : @fclose($stream); }
        catch (\Throwable $error) { return false; }
    }

    public function createdFiles(): array { return $this->createdFiles; }

    public function __destruct() { $this->close(); }
}
