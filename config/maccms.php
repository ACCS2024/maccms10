<?php
// ─────────────────────────────────────────────────────────────────────────────
// 站点运行时配置的加载桩 + 自愈。
//
// application/extra/maccms.php 是【每站独有】的运行时配置(站名/域名/主题/图床/
// 各类密钥)。它曾经被 track 进仓库,而仓库里存的是冒烟机那一份 —— 结果乐播新机
// 部署后主题变成 vozy、site_url 指着 216.180.225.139、图床指向 img.test.com,
// 16.9 万条相对路径封面全部 404。现在该文件已 .gitignore,仓库只保留中性样板
// application/data/config/maccms.example.php。
//
// 不入库带来一个新风险:文件被 git 删掉、部署漏拷、或误删,整站就退回空配置。
// 所以这里按优先级自愈:
//
//   1. 文件在   → 正常加载;顺手把它镜像到 runtime 影子备份(仅当影子比它旧才写)
//   2. 文件丢   → 先从影子备份恢复 —— 这一条专门用来扛「git 把文件删了」
//   3. 影子也没 → 从中性样板播种,让站点至少能起来,再进安装/后台填各站真实值
//
// 任何一步写失败都不影响本次请求取到配置:所有写操作都是 @ 静默 + 失败即跳过。
// ─────────────────────────────────────────────────────────────────────────────

$_dir     = __DIR__ . '/../application/extra/';
$_live    = $_dir . 'maccms.php';
$_example = __DIR__ . '/../application/data/config/maccms.example.php';
$_shadow  = __DIR__ . '/../runtime/config-shadow/maccms.php';

/** 复制 $from -> $to,自动建目录;失败返回 false,绝不抛异常 */
$_copy = static function ($from, $to) {
    if (!is_file($from) || !is_readable($from)) {
        return false;
    }
    $d = dirname($to);
    if (!is_dir($d) && !@mkdir($d, 0755, true) && !is_dir($d)) {
        return false;
    }
    // 先写临时文件再 rename,避免并发下别的请求读到半截文件
    $tmp = $to . '.tmp' . getmypid();
    if (@copy($from, $tmp) && @rename($tmp, $to)) {
        @chmod($to, 0644);
        return true;
    }
    @unlink($tmp);
    return false;
};

// ── 1/2/3:确保 live 文件存在 ────────────────────────────────────────────────
if (!is_file($_live)) {
    if (!$_copy($_shadow, $_live)) {
        $_copy($_example, $_live);
    }
}

if (!is_file($_live)) {
    return [];
}

$_cfg = include $_live;
if (!is_array($_cfg)) {
    return [];
}

// ── 影子备份:只在影子不存在或比 live 旧时才写,平时只花两次 stat ────────────
if (!is_file($_shadow) || @filemtime($_shadow) < @filemtime($_live)) {
    $_copy($_live, $_shadow);
}

return $_cfg;
