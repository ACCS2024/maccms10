<?php
/** Inspect flat language arrays as tokens; never include or evaluate audited source. */
declare(strict_types=1);
set_error_handler(static function (int $severity, string $message, string $file, int $line): never {
    throw new ErrorException($message, 0, $severity, $file, $line);
});

function languageLiteral(array $token): string
{
    if ($token[0] !== T_CONSTANT_ENCAPSED_STRING) {
        throw new RuntimeException('Only literal string keys and values are supported');
    }
    $literal = $token[1];
    $quote = $literal[0];
    $body = substr($literal, 1, -1);
    if ($quote === "'") {
        return preg_replace_callback('/\\\\([\\\\\'])/', static fn(array $m): string => $m[1], $body);
    }
    if ($quote !== '"') {
        throw new RuntimeException('Unsupported string prefix');
    }
    // Current language files use only these double-quoted escapes. Refuse other
    // sequences instead of guessing PHP hex/octal/Unicode or unknown escapes.
    $escapes = ['n'=>"\n", 'r'=>"\r", 't'=>"\t", 'v'=>"\v", 'e'=>"\x1b", 'f'=>"\f", '\\'=>'\\', '$'=>'$', '"'=>'"'];
    return preg_replace_callback('/\\\\([\s\S])/', static function (array $m) use ($escapes): string {
        if (!array_key_exists($m[1], $escapes)) {
            throw new RuntimeException('Unsupported double-quoted escape');
        }
        return $escapes[$m[1]];
    }, $body);
}

function languageEntries(string $path): array
{
    $source = file_get_contents($path);
    if ($source === false) { throw new RuntimeException('Cannot read language source'); }
    $tokens = array_values(array_filter(token_get_all($source, TOKEN_PARSE), static fn($t): bool =>
        !is_array($t) || !in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)));
    $position = 0;
    $take = static function ($expected) use (&$tokens, &$position): void {
        $token = $tokens[$position++] ?? null;
        if ((is_array($token) ? $token[0] : $token) !== $expected) {
            throw new RuntimeException('Unsupported language syntax at token ' . ($position - 1));
        }
    };
    $take(T_OPEN_TAG); $take(T_RETURN);
    if (($tokens[$position][0] ?? null) === T_ARRAY) { $take(T_ARRAY); $take('('); $end = ')'; }
    else { $take('['); $end = ']'; }
    $entries = [];
    while (($tokens[$position] ?? null) !== $end) {
        $key = $tokens[$position] ?? null; $take(T_CONSTANT_ENCAPSED_STRING);
        $take(T_DOUBLE_ARROW);
        $value = $tokens[$position] ?? null; $take(T_CONSTANT_ENCAPSED_STRING);
        $entries[] = ['key'=>languageLiteral($key), 'value'=>languageLiteral($value), 'line'=>$key[2]];
        if (($tokens[$position] ?? null) !== $end) { $take(','); }
    }
    $take($end); $take(';');
    if ($position !== count($tokens)) { throw new RuntimeException('Unexpected code after the language array'); }
    return $entries;
}

try {
    $paths = array_slice($argv, 1) ?: glob(dirname(__DIR__, 2) . '/application/lang/*.php');
    if (!$paths) { throw new RuntimeException('No language files selected'); }
    $report = ['totals'=>['files'=>0, 'entries'=>0, 'duplicate_keys'=>0, 'redundant_entries'=>0,
        'identical_keys'=>0, 'conflicting_keys'=>0], 'files'=>[]];
    foreach ($paths as $path) {
        $groups = [];
        $entries = languageEntries($path);
        $effective = [];
        foreach ($entries as $entry) { $effective[$entry['key']] = $entry['value']; }
        foreach ($entries as $entry) { $groups[$entry['key']][] = ['line'=>$entry['line'], 'value'=>$entry['value']]; }
        $duplicates = [];
        foreach ($groups as $key=>$declarations) {
            if (count($declarations) < 2) { continue; }
            $identical = count(array_unique(array_column($declarations, 'value'), SORT_STRING)) === 1;
            $duplicates[] = ['key'=>$key, 'classification'=>$identical ? 'identical' : 'conflicting',
                'effective_line'=>$declarations[count($declarations) - 1]['line'], 'declarations'=>$declarations];
            ++$report['totals']['duplicate_keys'];
            $report['totals']['redundant_entries'] += count($declarations) - 1;
            ++$report['totals'][$identical ? 'identical_keys' : 'conflicting_keys'];
        }
        ++$report['totals']['files'];
        $report['totals']['entries'] += count($entries);
        $report['files'][] = ['file'=>basename($path), 'sha256'=>hash_file('sha256', $path),
            'entries'=>count($entries), 'effective_sha256'=>hash('sha256', serialize($effective)), 'duplicates'=>$duplicates];
    }
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    exit($report['totals']['duplicate_keys'] ? 1 : 0);
} catch (Throwable $error) {
    fwrite(STDERR, 'Language audit incomplete: ' . $error->getMessage() . "\n");
    exit(2);
}
