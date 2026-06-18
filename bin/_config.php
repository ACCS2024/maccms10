<?php
/**
 * maccms-cli 配置解析器(被 bin/maccms 调用)。
 * 解析一个"简化 YAML 子集"的 maccms-cli.yml,无需 yaml 扩展。
 *
 * 用法:
 *   php _config.php <file> defaults              # 打印 --k=v(每行一个)
 *   php _config.php <file> resolve @name|name     # 打印别名/分组解析出的站点路径(每行一个)
 *
 * 支持的格式(顶层 section:defaults / aliases / groups):
 *   defaults:
 *     db-host: 127.0.0.1
 *     root-user: root
 *   aliases:
 *     site1: /srv/site1
 *     site2: /srv/site2
 *   groups:
 *     all: site1 site2
 */

$file = $argv[1] ?? '';
$action = $argv[2] ?? '';
if ($file === '' || !is_file($file)) {
    fwrite(STDERR, "config not found: {$file}\n");
    exit(3);
}

$sections = ['defaults' => [], 'aliases' => [], 'groups' => []];
$cur = null;
foreach (file($file, FILE_IGNORE_NEW_LINES) as $line) {
    if (preg_match('/^\s*#/', $line) || trim($line) === '') {
        continue;
    }
    // 顶层 section
    if (preg_match('/^([a-zA-Z_][\w-]*):\s*$/', $line, $m)) {
        $cur = $m[1];
        if (!isset($sections[$cur])) {
            $sections[$cur] = [];
        }
        continue;
    }
    // 缩进的 key: value
    if ($cur !== null && preg_match('/^\s+([\w-]+):\s*(.*)$/', $line, $m)) {
        $val = trim($m[2]);
        // 去除成对引号
        if (strlen($val) >= 2 && ($val[0] === '"' || $val[0] === "'") && substr($val, -1) === $val[0]) {
            $val = substr($val, 1, -1);
        }
        $sections[$cur][$m[1]] = $val;
    }
}

if ($action === 'defaults') {
    foreach ($sections['defaults'] as $k => $v) {
        if ($v !== '') {
            echo '--' . $k . '=' . $v . "\n";
        }
    }
    exit(0);
}

if ($action === 'resolve') {
    $name = ltrim((string)($argv[3] ?? ''), '@');
    if ($name === '') {
        fwrite(STDERR, "missing alias\n");
        exit(2);
    }
    $aliases = $sections['aliases'];
    $groups = $sections['groups'];
    $resolve = function ($n) use ($aliases) {
        return $aliases[$n] ?? null;
    };
    if (isset($groups[$name])) {
        $ok = false;
        foreach (preg_split('/[\s,]+/', $groups[$name], -1, PREG_SPLIT_NO_EMPTY) as $a) {
            $p = $resolve(ltrim($a, '@'));
            if ($p !== null) {
                echo $p . "\n";
                $ok = true;
            }
        }
        exit($ok ? 0 : 1);
    }
    $p = $resolve($name);
    if ($p === null) {
        fwrite(STDERR, "unknown alias: @{$name}\n");
        exit(1);
    }
    echo $p . "\n";
    exit(0);
}

fwrite(STDERR, "unknown action: {$action}\n");
exit(2);
