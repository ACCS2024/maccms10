<?php
/**
 * TP5 Array Where Condition Fixer
 *
 * Fixes:
 *  1. ['eq', $val]  → $val          (equality → direct scalar)
 *  2. ['gt'/'lt'/'egt'/'elt'/'neq', $val]  → append list-tuple to $where array
 *  3. $where['xxx_id'][1]/'[0]=='eq'' pattern in infoData() cache logic
 *  4. ['type_id|type_id_1'] pipe-field → split into whereOr closure
 *
 * Run: php migration/fix_tp5_where.php [--dry-run] [--dir=path]
 */

$dryRun = in_array('--dry-run', $argv);
$targetDir = null;
foreach ($argv as $arg) {
    if (str_starts_with($arg, '--dir=')) {
        $targetDir = substr($arg, 6);
    }
}

$dirs = $targetDir ? [$targetDir] : [
    'application/common/model',
    'application/common/util',
    'application/api/controller',
    'application/admin/controller',
    'application/index/controller',
];
// Also fix common.php (single file)
$singleFiles = ['application/common.php'];

$stats = ['files' => 0, 'eq' => 0, 'cmp' => 0, 'pipe' => 0, 'infocache' => 0];

$cmpMap = [
    'gt' => '>',
    'egt' => '>=',
    'lt' => '<',
    'elt' => '<=',
    'neq' => '<>',
];

function processFile(string $path, bool $dryRun, array &$stats, array $cmpMap): void
{
    $orig = file_get_contents($path);
    $content = $orig;

    // ── 1. Fix ['eq', EXPR] → EXPR ──────────────────────────────────────────
    // Pattern: (= or return or => context) ['eq', EXPR]
    // Replace: = ['eq', EXPR]; → = EXPR;  (only on assignment lines)
    $content = preg_replace_callback(
        "/(\\\$\w+\['[^']+'\]\s*=\s*)\['eq',\s*(.+?)\];/m",
        function ($m) use (&$stats) {
            $stats['eq']++;
            return $m[1] . $m[2] . ';';
        },
        $content
    );

    // Also: $where2['field'] = ['eq', ...]
    // Already covered by pattern above (captures $varname)

    // ── 2. Fix comparison operators → list-tuple format ──────────────────────
    // $where['field'] = ['gt', $val]; → $where[] = ['field', '>', $val];
    $opsPattern = implode('|', array_keys($cmpMap));
    $content = preg_replace_callback(
        "/(\\\$(\w+))\['([^']+)'\]\s*=\s*\['($opsPattern)',\s*(.+?)\];/m",
        function ($m) use (&$stats, $cmpMap) {
            $stats['cmp']++;
            $varName  = $m[1];
            $field    = $m[3];
            $op       = $m[4];
            $val      = $m[5];
            $phpOp    = $cmpMap[$op];
            return "{$varName}[] = ['{$field}', '{$phpOp}', {$val}];";
        },
        $content
    );

    // ── 2b. Fix like/notlike → list-tuple ────────────────────────────────────
    // $where['field'] = ['like', $val]; → $where[] = ['field', 'like', $val];
    $content = preg_replace_callback(
        "/(\\\$(\w+))\['([^']+)'\]\s*=\s*\['(like|notlike)',\s*(.+?)\];/m",
        function ($m) use (&$stats) {
            $stats['like'] = ($stats['like'] ?? 0) + 1;
            $varName = $m[1];
            $field   = $m[3];
            $op      = $m[4];
            $val     = $m[5];
            return "{$varName}[] = ['{$field}', '{$op}', {$val}];";
        },
        $content
    );

    // ── 2c. Fix in/notin → unwrap array (TP8 auto-IN) / list-tuple ───────────
    // $where['field'] = ['in', $arr]; → $where['field'] = $arr; (TP8 auto-IN)
    // $where['field'] = ['notin', $arr]; → $where[] = ['field', 'notin', $arr];
    $content = preg_replace_callback(
        "/(\\\$(\w+))\['([^']+)'\]\s*=\s*\['(in|notin)',\s*(.+?)\];/m",
        function ($m) use (&$stats) {
            $stats['in'] = ($stats['in'] ?? 0) + 1;
            $varName = $m[1];
            $field   = $m[3];
            $op      = $m[4];
            $val     = $m[5];
            if ($op === 'in') {
                return "{$varName}['{$field}'] = {$val};";
            } else {
                return "{$varName}[] = ['{$field}', 'notin', {$val}];";
            }
        },
        $content
    );

    // ── 2d. Fix between/notbetween → list-tuple ───────────────────────────────
    // $where['field'] = ['between', [$a,$b]]; → $where[] = ['field', 'between', [$a,$b]];
    $content = preg_replace_callback(
        "/(\\\$(\w+))\['([^']+)'\]\s*=\s*\['(between|notbetween)',\s*(.+?)\];/m",
        function ($m) use (&$stats) {
            $stats['between'] = ($stats['between'] ?? 0) + 1;
            $varName = $m[1];
            $field   = $m[3];
            $op      = $m[4];
            $val     = $m[5];
            return "{$varName}[] = ['{$field}', '{$op}', {$val}];";
        },
        $content
    );

    // ── 3. Fix infoData cache pattern: $where['xxx_id'][1] / [0]=='eq' ────────
    // Pattern A: $where['xxx_id'][1] → $where['xxx_id'] ?? ''
    $content = preg_replace(
        "/\\\$where\['(\w+)'\]\[1\]/",
        "(\$where['$1'] ?? '')",
        $content
    );
    if (preg_match("/\\\$where\['\w+'\]\[1\]/", $orig)) {
        // count only if pattern existed
        $stats['infocache']++;
    }
    // Pattern B: $where['xxx_id'][0]=='eq' → isset($where['xxx_id'])
    $content = preg_replace(
        "/\\\$where\['(\w+)'\]\[0\]==['\"]eq['\"]/",
        "isset(\$where['$1'])",
        $content
    );

    // ── 4. Pipe-field eq: $where['f1|f2'] = SCALAR → $where[] closure prep ──
    // Cannot fully auto-fix closures, but convert eq-fixed scalar to whereOr-able format
    // For now: $where['f1|f2'] = $val → leave with a TODO marker
    // (will be handled in separate pass)
    $pipeCount = preg_match_all(
        "/\\\$\w+\['[^']*\|[^']*'\]\s*=/",
        $content,
        $pipeMatches
    );
    if ($pipeCount > 0) {
        $stats['pipe'] += $pipeCount;
        // Mark with TODO for visibility
        $content = preg_replace(
            "/^(\s*\\\$\w+\['[^']*\|[^']*'\]\s*=.+);$/m",
            "$1; // TODO:TP8-pipe-or",
            $content
        );
    }

    if ($content !== $orig) {
        $stats['files']++;
        if (!$dryRun) {
            file_put_contents($path, $content);
        } else {
            echo "[DRY] Would modify: $path\n";
        }
    }
}

// Collect files
$files = [];
foreach ($dirs as $dir) {
    if (!is_dir($dir)) continue;
    $iter = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
    foreach ($iter as $f) {
        if ($f->getExtension() === 'php') {
            $files[] = $f->getPathname();
        }
    }
}
foreach ($singleFiles as $f) {
    if (file_exists($f)) $files[] = $f;
}
sort($files);

foreach ($files as $file) {
    processFile($file, $dryRun, $stats, $cmpMap);
}

$mode = $dryRun ? ' (DRY RUN)' : '';
echo "Done{$mode}: {$stats['files']} files modified\n";
echo "  ['eq', X] → X              : {$stats['eq']} replacements\n";
echo "  comparison ops → list-tuple : {$stats['cmp']} replacements\n";
echo "  infoData cache pattern      : {$stats['infocache']} occurrences\n";
echo "  pipe-field TODO markers     : {$stats['pipe']} marked\n";
