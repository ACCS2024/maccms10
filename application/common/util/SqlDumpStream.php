<?php
namespace app\common\util;

/** Streaming statements for application table dumps; this is not a mysql-client DELIMITER interpreter. */
final class SqlDumpStream
{
    private $stream;
    private array $prefixes;
    private string $buffer = '';
    private int $cursor = 0;
    private bool $eof = false;
    private bool $backslashEscapes = true;
    private array $savedModes = [];
    private bool $conditional = false;

    public function __construct($stream, array $prefixes = [])
    {
        if (!is_resource($stream) || get_resource_type($stream) !== 'stream') { throw new \InvalidArgumentException('Invalid SQL stream'); }
        foreach ($prefixes as $from=>$to) {
            if ((!is_string($from) && !is_int($from)) || !preg_match('/^[a-zA-Z0-9_]+$/D', (string)$from)
                || !is_string($to) || !preg_match('/^[a-zA-Z0-9_]*$/D', $to)) {
                throw new \InvalidArgumentException('Invalid table prefix mapping');
            }
        }
        uksort($prefixes, static fn($a,$b)=>strlen((string)$b)<=>strlen((string)$a));
        $this->prefixes = $prefixes;
        $this->stream = $stream;
        if ($this->peek() === "\xEF" && $this->peek(1) === "\xBB" && $this->peek(2) === "\xBF") { $this->cursor += 3; }
    }

    private function peek(int $ahead = 0): ?string
    {
        while (strlen($this->buffer) <= $this->cursor + $ahead && !$this->eof) {
            $this->buffer = substr($this->buffer, $this->cursor); $this->cursor = 0;
            $bytes = fread($this->stream, 8192);
            if ($bytes === false || ($bytes === '' && !feof($this->stream))) { throw new \RuntimeException('Cannot read SQL stream'); }
            $this->buffer .= $bytes; $this->eof = feof($this->stream);
        }
        return $this->buffer[$this->cursor + $ahead] ?? null;
    }

    private function take(): ?string
    {
        $char = $this->peek();
        if ($char !== null) { $this->cursor++; }
        return $char;
    }

    private function identifier(string $name, bool $remap): string
    {
        if ($remap) {
            foreach ($this->prefixes as $from=>$to) {
                $from = (string)$from;
                if (str_starts_with($name, $from)) { $name = $to.substr($name, strlen($from)); break; }
            }
        }
        return '`'.str_replace('`', '``', $name).'`';
    }

    private function token(string $token, array &$tokens, string &$kind, bool &$modeAssignment): void
    {
        $index = count($tokens)-1;
        if ($token === '=') {
            if (($tokens[$index] ?? '') === ':') { $index--; }
            if (($tokens[$index] ?? '') === 'SQL_MODE'
                && (($tokens[$index-1] ?? '') !== '@' || ($tokens[$index-2] ?? '') === '@')) { $modeAssignment = true; }
        }
        if ($kind === '' && preg_match('/^[A-Z]+$/D', $token)) { $kind = $token; }
        $tokens[] = $token;
        if (count($tokens)>24) { array_shift($tokens); }
    }

    private function tablePosition(array $tokens, string $kind, int $depth, bool $tableList): bool
    {
        $last = $tokens[count($tokens)-1] ?? '';
        if ($last === 'REFERENCES' || ($last === '.' && ($tokens[count($tokens)-2] ?? '') === '#QUALIFIER')) { return true; }
        if ($last === '.' && preg_match('/^[A-Z0-9_$]+$/D', $tokens[count($tokens)-2] ?? '')) {
            return $this->tablePosition(array_slice($tokens, 0, -2), $kind, $depth, $tableList);
        }
        if ($depth !== 0) { return false; }
        $prefix = implode(' ', $tokens);
        if ($tableList && $last === ',') { return true; }
        if (in_array($kind, ['CREATE','DROP','ALTER','TRUNCATE','RENAME'], true)
            && preg_match('/(?:^| )TABLE(?: IF (?:NOT )?EXISTS)?$/D', $prefix)) { return true; }
        if ($kind === 'TRUNCATE' && $prefix === 'TRUNCATE') { return true; }
        if ($kind === 'LOCK' && $last === 'TABLES') { return true; }
        if (in_array($kind, ['INSERT','REPLACE'], true) && ($last === 'INTO'
            || preg_match('/^(?:INSERT|REPLACE)(?: (?:LOW_PRIORITY|HIGH_PRIORITY|DELAYED|IGNORE))*$/D', $prefix))) { return true; }
        if ($kind === 'UPDATE' && preg_match('/^UPDATE(?: (?:LOW_PRIORITY|IGNORE))*$/D', $prefix)) { return true; }
        if (in_array($kind, ['SELECT','DELETE','UPDATE','INSERT','REPLACE'], true) && in_array($last, ['FROM','JOIN'], true)) { return true; }
        if ($kind === 'CREATE' && $last === 'LIKE') { return true; }
        if (($kind === 'RENAME' && $last === 'TO') || ($kind === 'ALTER' && str_ends_with($prefix, 'RENAME TO'))) { return true; }
        return in_array($kind, ['CREATE','DROP'], true) && preg_match('/(?:^| )INDEX #IDENTIFIER ON$/D', $prefix) === 1;
    }

    private function followedByDot(): bool
    {
        $offset = 0;
        while (($char = $this->peek($offset)) !== null && ctype_space($char)) { $offset++; }
        return $char === '.';
    }

    private function constraintPosition(array $tokens, string $kind): bool
    {
        if (!in_array($kind, ['CREATE','ALTER'], true)) { return false; }
        // FK/CHECK symbols share a schema-wide namespace. Columns and ordinary indexes do not.
        if (($tokens[count($tokens)-1] ?? '') === 'CONSTRAINT') { return true; }
        return $kind === 'ALTER' && preg_match('/(?:DROP FOREIGN KEY|DROP CHECK|ALTER CHECK)$/D', implode(' ', $tokens)) === 1;
    }

    private function executableComment(string $comment): string
    {
        if (!preg_match('/^\/\*!(\d{0,6})(.*)\*\/$/s', $comment, $match)) { return $comment; }
        $stream = fopen('php://temp', 'w+b');
        if ($stream === false) { throw new \RuntimeException('Cannot parse executable SQL comment'); }
        try {
            if (fwrite($stream, $match[2]) !== strlen($match[2]) || !rewind($stream)) { throw new \RuntimeException('Cannot parse executable SQL comment'); }
            $parser = new self($stream, $this->prefixes);
            $parser->backslashEscapes = $this->backslashEscapes;
            $parser->conditional = true;
            $sql = '';
            foreach ($parser->statements() as $statement) { $sql .= $statement; }
            return $sql === '' ? $comment : '/*!'.$match[1].$sql.'*/';
        } finally { fclose($stream); }
    }

    /** Track the simple SQL_MODE assignments emitted by application and common table dumps. */
    private function sqlMode(string $statement, bool $modeAssignment, string $kind): void
    {
        $sql = preg_replace('/\A(?:(?:\s+)|(?:--[^\r\n]*(?:\r\n|\r|\n|$))|(?:\#[^\r\n]*(?:\r\n|\r|\n|$))|(?:\/\*.*?\*\/))*/s', '', $statement);
        if (preg_match('/^DELIMITER\b/i', $sql)) { throw new \RuntimeException('DELIMITER scripts are not supported'); }
        if ($kind === 'SET' && $modeAssignment && $this->conditional) { throw new \RuntimeException('Conditional SQL_MODE assignments are not supported'); }
        if (preg_match('/^SET\s+@([a-zA-Z0-9_]+)\s*=\s*@@(?:SESSION\.)?SQL_MODE\s*;?\s*$/i', $sql, $match)) {
            $this->savedModes[strtolower($match[1])] = $this->backslashEscapes;
        } elseif (preg_match('/^SET\s+(?:(?:SESSION\s+)|(?:@@SESSION\.))?SQL_MODE\s*=\s*([\'"])([a-zA-Z0-9_, ]*)\1\s*;?\s*$/i', $sql, $match)) {
            $modes = array_map('trim', explode(',', strtoupper($match[2])));
            if (array_intersect($modes, ['ANSI_QUOTES','ANSI','DB2','MAXDB','MSSQL','ORACLE','POSTGRESQL'])) { throw new \RuntimeException('ANSI identifier quoting modes are not supported'); }
            $this->backslashEscapes = !in_array('NO_BACKSLASH_ESCAPES', $modes, true);
        } elseif (preg_match('/^SET\s+(?:(?:SESSION\s+)|(?:@@SESSION\.))?SQL_MODE\s*=\s*@([a-zA-Z0-9_]+)\s*;?\s*$/i', $sql, $match)
            && isset($this->savedModes[strtolower($match[1])])) {
            $this->backslashEscapes = $this->savedModes[strtolower($match[1])];
        } elseif ($kind === 'SET' && $modeAssignment) {
            throw new \RuntimeException('Unsupported SQL_MODE expression');
        }
    }

    /** Only one complete statement (including its comments) is retained in memory. */
    public function statements(): \Generator
    {
        $sql = ''; $quote = ''; $identifier = ''; $block = false; $line = false; $hasSql = false;
        $executable = false; $commentStart = 0;
        $tokens = []; $word = ''; $kind = ''; $depth = 0; $tableList = false; $modeAssignment = false; $identifierContext = false; $constraintContext = false;
        while (($char = $this->take()) !== null) {
            if ($quote === '`') {
                if ($char === '`') {
                    if ($this->peek() === '`') { $this->take(); $identifier .= '`'; }
                    else {
                        $qualifier = $identifierContext && $this->followedByDot();
                        $sql .= $this->identifier($identifier, ($identifierContext && !$qualifier) || $constraintContext); $quote = '';
                        $token = $kind === 'SET' && strcasecmp($identifier, 'SQL_MODE') === 0 ? 'SQL_MODE' : ($qualifier ? '#QUALIFIER' : '#IDENTIFIER');
                        $this->token($token, $tokens, $kind, $modeAssignment);
                    }
                } else { $identifier .= $char; }
                continue;
            }
            $sql .= $char;
            if ($line) { if ($char === "\n" || $char === "\r") { $line = false; } continue; }
            if ($block) {
                if ($char === '*' && $this->peek() === '/') {
                    $sql .= $this->take(); $block = false;
                    if ($executable) { $sql = substr($sql, 0, $commentStart).$this->executableComment(substr($sql, $commentStart)); }
                }
                continue;
            }
            if ($quote !== '') {
                if ($char === '\\' && $this->backslashEscapes) { $sql .= $this->take() ?? ''; }
                elseif ($char === $quote) {
                    if ($this->peek() === $quote) { $sql .= $this->take(); }
                    else { $quote = ''; $this->token('#STRING', $tokens, $kind, $modeAssignment); }
                }
                continue;
            }
            if (ctype_alnum($char) || $char === '_' || $char === '$') { $word .= $char; $hasSql = true; continue; }
            if ($word !== '') {
                $word = strtoupper($word); $this->token($word, $tokens, $kind, $modeAssignment);
                if ($depth === 0 && (($word === 'TABLE' && in_array($kind, ['DROP','RENAME'], true)) || ($word === 'TABLES' && $kind === 'LOCK'))) { $tableList = true; }
                $word = '';
            }
            if ($char === '#' || ($char === '-' && $this->peek() === '-'
                && ($this->peek(1) === null || ctype_space($this->peek(1))))) { $line = true; continue; }
            if ($char === '/' && $this->peek() === '*') {
                $executable = $this->peek(1) === '!'; $commentStart = strlen($sql)-1;
                $hasSql = $hasSql || $executable; $sql .= $this->take(); $block = true; continue;
            }
            if ($char === ';') {
                if ($hasSql) { $this->sqlMode($sql, $modeAssignment, $kind); yield $sql; }
                $sql = ''; $hasSql = false; $tokens = []; $kind = ''; $depth = 0; $tableList = false; $modeAssignment = false; continue;
            }
            if ($char === '`') {
                $identifierContext = $this->tablePosition($tokens, $kind, $depth, $tableList);
                $constraintContext = $this->constraintPosition($tokens, $kind);
                $quote = '`'; $identifier = ''; $sql = substr($sql, 0, -1);
            }
            elseif ($char === "'" || $char === '"') { $quote = $char; }
            elseif (!ctype_space($char)) {
                $this->token($char, $tokens, $kind, $modeAssignment);
                if ($char === '(') { $depth++; } elseif ($char === ')') { $depth--; }
            }
            if (!ctype_space($char)) { $hasSql = true; }
        }
        if ($quote !== '' || $block) { throw new \RuntimeException('Incomplete SQL quote or comment'); }
        // Historical CLI imports also accepted a complete final statement without a trailing semicolon.
        if ($word !== '') { $this->token(strtoupper($word), $tokens, $kind, $modeAssignment); }
        if ($hasSql) { $this->sqlMode($sql, $modeAssignment, $kind); yield $sql; }
    }
}
