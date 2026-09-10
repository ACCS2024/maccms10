<?php
declare(strict_types=1);

namespace app\common\util;

/** Read legacy PHP array configuration as data. No include, eval or application bootstrap. */
final class DataConfig
{
    private const MAX_BYTES = 8388608;
    private const MAX_TOKENS = 100000;
    private const MAX_DEPTH = 64;
    private array $tokens;
    private int $position = 0;

    public static function read(string $path): array
    {
        // Never resolve URL wrappers or silently replace an unreadable/invalid live configuration.
        if (str_contains($path, '://') || str_contains($path, "\0")) {
            throw new \RuntimeException('Configuration must be a local data file.');
        }
        if (!file_exists($path) && !is_link($path)) {
            return [];
        }
        if (!is_file($path) || is_link($path)) {
            throw new \RuntimeException('Configuration must be a regular data file: ' . basename($path));
        }
        $source = @file_get_contents($path, false, null, 0, self::MAX_BYTES + 1);
        if ($source === false) {
            throw new \RuntimeException('Cannot read configuration: ' . basename($path));
        }
        try {
            return self::parse($source);
        } catch (\RuntimeException $error) {
            // Do not expose configuration contents, credentials or absolute paths in diagnostics.
            throw new \RuntimeException('Unsafe or invalid data configuration: ' . basename($path), 0, $error);
        }
    }

    public static function parse(string $source): array
    {
        if (strlen($source) > self::MAX_BYTES) {
            throw new \RuntimeException('Data configuration exceeds the size limit.');
        }
        self::checkLexicalBudget($source);
        $parser = new self();
        try {
            $tokens = token_get_all($source, TOKEN_PARSE);
        } catch (\ParseError $error) {
            throw new \RuntimeException('Invalid data configuration syntax.');
        }
        if (count($tokens) > self::MAX_TOKENS) {
            throw new \RuntimeException('Data configuration exceeds the token limit.');
        }
        $parser->tokens = [];
        foreach ($tokens as $token) {
            if (!is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                $parser->tokens[] = $token;
            }
        }
        unset($tokens, $token);
        $parser->expect(T_OPEN_TAG);
        $parser->expect(T_RETURN);
        $value = $parser->value(0);
        if (!is_array($value)) {
            throw new \RuntimeException('Data configuration must return an array.');
        }
        $parser->expect(';');
        if ($parser->id() === T_CLOSE_TAG) {
            $parser->position++;
            if ($parser->id() === T_INLINE_HTML && trim($parser->tokens[$parser->position][1]) === '') {
                $parser->position++;
            }
        }
        if ($parser->id() !== null) {
            throw new \RuntimeException('Statements outside the configuration array are forbidden.');
        }
        return $value;
    }

    /** Bound tokenizer allocation before PHP creates its token arrays. This scan never evaluates PHP. */
    private static function checkLexicalBudget(string $source): void
    {
        $length = strlen($source);
        $whitespace = " \t\r\n\v\f";
        if ($length < 5 || strncasecmp($source, '<?php', 5) !== 0
            || ($length > 5 && !str_contains($whitespace, $source[5]))) {
            throw new \RuntimeException('Data configuration must begin with a PHP open tag.');
        }
        $position = 5;
        $units = 1;
        $depth = 0;
        $word = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
        while ($position < $length) {
            if (++$units > self::MAX_TOKENS) {
                throw new \RuntimeException('Data configuration exceeds the token limit.');
            }
            $character = $source[$position];
            if (str_contains($whitespace, $character)) {
                $position += strspn($source, $whitespace, $position);
                continue;
            }
            if ($character === "'" || $character === '"') {
                $quote = $character;
                $position++;
                while (true) {
                    $position += strcspn($source, $quote === "'" ? "'\\" : '"\\$', $position);
                    if ($position >= $length) {
                        throw new \RuntimeException('Unterminated configuration string.');
                    }
                    if ($source[$position] === $quote) {
                        $position++;
                        break;
                    }
                    if ($source[$position] === '\\') {
                        $position += 2;
                        if ($position >= $length) {
                            throw new \RuntimeException('Unterminated configuration string.');
                        }
                        continue;
                    }
                    $next = $source[$position + 1] ?? '';
                    $byte = $next === '' ? 0 : ord($next);
                    if (($source[$position - 1] ?? '') === '{' || $next === '{' || $next === '_'
                        || ($byte >= 65 && $byte <= 90)
                        || ($byte >= 97 && $byte <= 122) || $byte >= 128) {
                        throw new \RuntimeException('String interpolation is forbidden in data configuration.');
                    }
                    $position++;
                }
                continue;
            }
            $next = $source[$position + 1] ?? '';
            if ($character === '/' && $next === '*') {
                $end = strpos($source, '*/', $position + 2);
                if ($end === false) {
                    throw new \RuntimeException('Unterminated configuration comment.');
                }
                $position = $end + 2;
                continue;
            }
            if ($character === '#' && $next === '[') {
                throw new \RuntimeException('Attributes are forbidden in data configuration.');
            }
            if ($character === '#' || ($character === '/' && $next === '/')) {
                $position += $character === '#' ? 1 : 2;
                while ($position < $length) {
                    $position += strcspn($source, "\r\n?", $position);
                    if ($position >= $length || $source[$position] !== '?'
                        || ($source[$position + 1] ?? '') === '>') {
                        break;
                    }
                    $position++;
                }
                continue;
            }
            if ($character === '?' && $next === '>') {
                $position += 2;
                if ($units + 1 > self::MAX_TOKENS || strspn($source, $whitespace, $position) !== $length - $position) {
                    throw new \RuntimeException('Statements outside the configuration array are forbidden.');
                }
                return;
            }
            if ($character === '$' || $character === '`' || $character === '{' || $character === '}'
                || substr_compare($source, '<<<', $position, 3) === 0) {
                throw new \RuntimeException('Executable PHP is forbidden in data configuration.');
            }
            if ($character === '[' || $character === '(') {
                if (++$depth > self::MAX_DEPTH + 1) {
                    throw new \RuntimeException('Data configuration exceeds the nesting limit.');
                }
            } elseif ($character === ']' || $character === ')') {
                if (--$depth < 0) {
                    throw new \RuntimeException('Invalid data configuration syntax.');
                }
            }
            $span = strspn($source, $word, $position);
            if ($span > 0) {
                // A digit-led run may contain a number followed by one identifier. Count both conservatively.
                if ($character >= '0' && $character <= '9' && ++$units > self::MAX_TOKENS) {
                    throw new \RuntimeException('Data configuration exceeds the token limit.');
                }
                $position += $span;
            } else {
                $position++;
            }
        }
    }

    private function id(): int|string|null
    {
        $token = $this->tokens[$this->position] ?? null;
        return is_array($token) ? $token[0] : $token;
    }

    private function expect(int|string $id): void
    {
        if ($this->id() !== $id) {
            throw new \RuntimeException('Only literal configuration data is permitted.');
        }
        $this->position++;
    }

    private function value(int $depth): mixed
    {
        if ($depth > self::MAX_DEPTH) {
            throw new \RuntimeException('Data configuration exceeds the nesting limit.');
        }
        $id = $this->id();
        if ($id === '[' || $id === T_ARRAY) {
            $this->position++;
            $close = ']';
            if ($id === T_ARRAY) {
                $this->expect('(');
                $close = ')';
            }
            $result = [];
            while ($this->id() !== $close) {
                $keyOrValue = $this->value($depth + 1);
                if ($this->id() === T_DOUBLE_ARROW) {
                    if (!is_int($keyOrValue) && !is_string($keyOrValue)) {
                        throw new \RuntimeException('Configuration keys must be strings or integers.');
                    }
                    $this->position++;
                    $result[$keyOrValue] = $this->value($depth + 1);
                } else {
                    if (array_key_exists(PHP_INT_MAX, $result)) {
                        throw new \RuntimeException('Configuration array index exceeds the platform integer range.');
                    }
                    $result[] = $keyOrValue;
                }
                if ($this->id() === $close) {
                    break;
                }
                $this->expect(',');
            }
            $this->expect($close);
            return $result;
        }
        if ($id === T_CONSTANT_ENCAPSED_STRING) {
            $value = $this->stringLiteral($this->tokens[$this->position++][1]);
            // var_export emits NUL bytes as 'a' . "\0" . 'b'. Only literal string joins are accepted.
            while ($this->id() === '.') {
                $this->position++;
                if ($this->id() !== T_CONSTANT_ENCAPSED_STRING) {
                    throw new \RuntimeException('Only literal strings may be concatenated.');
                }
                $value .= $this->stringLiteral($this->tokens[$this->position++][1]);
            }
            return $value;
        }
        $sign = '';
        if ($id === '-' || $id === '+') {
            $sign = $id;
            $this->position++;
            $id = $this->id();
        }
        if ($id === T_LNUMBER || $id === T_DNUMBER) {
            $number = str_replace('_', '', $this->tokens[$this->position++][1]);
            if ($sign === '-' && $number === ltrim((string)PHP_INT_MIN, '-')) {
                return PHP_INT_MIN;
            }
            $based = preg_match('/^0[xXbBoO]/', $number) === 1
                || ($id === T_LNUMBER && preg_match('/^0[0-7]/', $number) === 1);
            if ($id === T_DNUMBER && !$based) {
                $value = (float)($sign . $number);
                if (!is_finite($value)) {
                    throw new \RuntimeException('Non-finite configuration numbers are forbidden.');
                }
                return $value;
            }
            $prefix = strtolower(substr($number, 0, 2));
            $value = match ($prefix) {
                '0x' => hexdec(substr($number, 2)),
                '0b' => bindec(substr($number, 2)),
                '0o' => octdec(substr($number, 2)),
                default => $based ? octdec($number) : intval($number, 10),
            };
            if (is_float($value)) {
                // PHP and base conversion helpers can round huge based integers differently.
                // var_export writes finite floating point data in decimal; do not silently alter it.
                throw new \RuntimeException('Non-decimal configuration integers must fit the platform integer range.');
            }
            // PHP's var_export serializes PHP_INT_MIN as -PHP_INT_MAX-1.
            if ($sign === '-' && $value === PHP_INT_MAX && $this->id() === '-'
                && ($this->tokens[$this->position + 1][0] ?? null) === T_LNUMBER
                && ($this->tokens[$this->position + 1][1] ?? null) === '1') {
                $this->position += 2;
                return PHP_INT_MIN;
            }
            return $sign === '-' ? -$value : $value;
        }
        if ($sign === '' && $id === T_STRING) {
            $literal = strtolower($this->tokens[$this->position++][1]);
            return match ($literal) {
                'true' => true,
                'false' => false,
                'null' => null,
                default => throw new \RuntimeException('Constants and function calls are forbidden in data configuration.'),
            };
        }
        throw new \RuntimeException('Executable PHP is forbidden in data configuration.');
    }

    private function stringLiteral(string $literal): string
    {
        if ($literal[0] === 'b' || $literal[0] === 'B') {
            $literal = substr($literal, 1);
        }
        $quote = $literal[0];
        $value = substr($literal, 1, -1);
        if ($quote === "'") {
            return preg_replace_callback('/\\\\([\\\\\'])/', static fn ($m) => $m[1], $value);
        }
        return preg_replace_callback('/\\\\(?:[nrtvef\\\\$"]|[0-7]{1,3}|x[0-9a-fA-F]{1,2}|u\{[0-9a-fA-F]+\})/', static function ($match) {
            $escape = substr($match[0], 1);
            $simple = ['n' => "\n", 'r' => "\r", 't' => "\t", 'v' => "\v", 'e' => "\x1b", 'f' => "\f", '\\' => '\\', '$' => '$', '"' => '"'];
            if (isset($simple[$escape])) {
                return $simple[$escape];
            }
            if ($escape[0] === 'x') {
                return chr(hexdec(substr($escape, 1)));
            }
            if ($escape[0] === 'u') {
                $code = hexdec(substr($escape, 2, -1));
                if ($code > 0x10ffff || ($code >= 0xd800 && $code <= 0xdfff)) {
                    throw new \RuntimeException('Invalid Unicode string escape.');
                }
                // Keep the offline parser usable with php -n + tokenizer only.
                if ($code <= 0x7f) { return chr($code); }
                if ($code <= 0x7ff) { return chr(0xc0 | ($code >> 6)) . chr(0x80 | ($code & 0x3f)); }
                if ($code <= 0xffff) { return chr(0xe0 | ($code >> 12)) . chr(0x80 | (($code >> 6) & 0x3f)) . chr(0x80 | ($code & 0x3f)); }
                return chr(0xf0 | ($code >> 18)) . chr(0x80 | (($code >> 12) & 0x3f))
                    . chr(0x80 | (($code >> 6) & 0x3f)) . chr(0x80 | ($code & 0x3f));
            }
            return chr(octdec($escape) & 255);
        }, $value);
    }
}
