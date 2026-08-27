<?php
/**
 * 把本机 application/extra/maccms.php 存进 runtime 影子备份。
 *
 * 什么时候用:该文件已从仓库移除(.gitignore)。已有站点第一次拉这个改动时,
 * git 会因为「上游删了、本地改过」而拒绝合并并中止 —— 配置不会丢,但需要人工处理。
 * 拉之前先跑一次本脚本,影子就位后,无论文件是被 git 删掉还是部署漏拷,
 * config/maccms.php 都能原样自愈回来。
 *
 *   php deploy/preserve-site-config.php            # 存档
 *   php deploy/preserve-site-config.php --status   # 只看状态
 *
 * 拉取推荐姿势(每台机器一次):
 *   php deploy/preserve-site-config.php
 *   cp -a application/extra/maccms.php /root/maccms-$(basename $PWD).keep
 *   git checkout -- application/extra/maccms.php && git pull
 *   # 如果 pull 后文件没了,访问一次站点即自愈;或直接 cp 回来:
 *   cp -a /root/maccms-$(basename $PWD).keep application/extra/maccms.php
 */

$root    = dirname(__DIR__);
$live    = $root . '/application/extra/maccms.php';
$shadow  = $root . '/runtime/config-shadow/maccms.php';
$example = $root . '/application/data/config/maccms.example.php';
$status  = in_array('--status', $argv, true);

$fmt = static function ($p) {
    return is_file($p)
        ? sprintf('%s (%d bytes, %s)', $p, filesize($p), date('Y-m-d H:i:s', filemtime($p)))
        : "$p  —— 不存在";
};

echo "live   : ", $fmt($live), "\n";
echo "shadow : ", $fmt($shadow), "\n";
echo "example: ", $fmt($example), "\n";

if ($status) { exit(0); }

if (!is_file($live)) {
    fwrite(STDERR, "\n本机没有 application/extra/maccms.php —— 无可存档。\n"
        . "访问一次站点即会自愈(影子 → 样板),或先把真实配置放回去再跑本脚本。\n");
    exit(1);
}

$cfg = include $live;
if (!is_array($cfg) || empty($cfg)) {
    fwrite(STDERR, "\n拒绝存档:$live 没有返回有效数组,存进去会把好影子覆盖成坏的。\n");
    exit(1);
}

$dir = dirname($shadow);
if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
    fwrite(STDERR, "\n无法创建 $dir\n");
    exit(1);
}
$tmp = $shadow . '.tmp' . getmypid();
if (!@copy($live, $tmp) || !@rename($tmp, $shadow)) {
    @unlink($tmp);
    fwrite(STDERR, "\n写影子备份失败(检查 runtime/ 权限,应属 www)\n");
    exit(1);
}
@chmod($shadow, 0644);

$check = include $shadow;
if (!is_array($check) || $check !== $cfg) {
    fwrite(STDERR, "\n存档后回读校验不一致,请人工检查 $shadow\n");
    exit(1);
}

echo "\n已存档,回读校验一致。站点标识:",
     ($cfg['site']['site_name'] ?? '?'), " / ",
     ($cfg['site']['template_dir'] ?? '?'), "/", ($cfg['site']['html_dir'] ?? '?'), "\n";
echo "现在即使 application/extra/maccms.php 被删,下一次请求会自动恢复。\n";
