<?php
namespace app\common\model;

use think\facade\Db;

/**
 * 帮助中心配置模型（key-value 表，不使用 ActiveRecord）
 * 对应表：mac_help_cfg  结构：cfg_key PK, cfg_val text, cfg_label varchar(100), cfg_sort int
 */
class HelpCfg
{
    /**
     * 查询全部配置，返回 ['cfg_key' => 'cfg_val', ...] 平铺数组
     */
    public static function getAll(): array
    {
        $rows = Db::name('help_cfg')->select()->toArray();
        $result = [];
        foreach ($rows as $row) {
            $result[$row['cfg_key']] = $row['cfg_val'];
        }
        return $result;
    }

    /**
     * 获取单个配置值
     */
    public static function get(string $key, string $default = ''): string
    {
        $val = Db::name('help_cfg')->where('cfg_key', $key)->value('cfg_val');
        return $val !== null ? (string)$val : $default;
    }

    /**
     * 更新单行配置
     */
    public static function set(string $key, string $val): void
    {
        Db::name('help_cfg')->where('cfg_key', $key)->update(['cfg_val' => $val]);
    }

    /**
     * 批量更新多行配置
     * @param array $data ['cfg_key' => 'cfg_val', ...]
     */
    public static function setMulti(array $data): void
    {
        foreach ($data as $key => $val) {
            Db::name('help_cfg')->where('cfg_key', $key)->update(['cfg_val' => (string)$val]);
        }
    }

    /**
     * 生成所有播放器资源 ZIP 文件，打包到 upload/help/ 目录
     * @return array 已生成的文件名列表，如 ['mac10.zip', 'maccms.zip', ...]
     */
    public static function generateFiles(): array
    {
        // 读取配置
        $cfg = self::getAll();
        $siteName   = $cfg['site_name']   ?? '';
        $playerFlag = $cfg['player_flag'] ?? '';
        $siteHost   = $cfg['site_host']   ?? '';
        $playerHost = $cfg['player_host'] ?? '';
        $playerCode = $cfg['player_code'] ?? '';
        $apiHost    = $cfg['api_host']    ?? '';

        // 确保输出目录存在
        $outDir = ROOT_PATH . 'upload/help/';
        if (!is_dir($outDir)) {
            mkdir($outDir, 0755, true);
        }

        $generated = [];

        // ── 1. mac10.zip ──────────────────────────────────────────────────
        $siteHostNoSlash = rtrim($siteHost, '/');
        $mac10Json = json_encode([
            'status'  => '1',
            'from'    => $playerFlag,
            'show'    => $siteName,
            'des'     => $siteName . '官网: ' . $siteHostNoSlash,
            'target'  => '_self',
            'ps'      => '1',
            'parse'   => $playerHost,
            'sort'    => '9999',
            'tip'     => '无需安装任何插件',
            'id'      => $playerFlag,
            'code'    => $playerCode,
        ], JSON_UNESCAPED_UNICODE);
        $mac10Content = base64_encode($mac10Json);

        $zipPath = $outDir . 'mac10.zip';
        $zip = new \ZipArchive();
        if ($zip->open($zipPath, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) === true) {
            $zip->addFromString('mac10/bfzym3u8.txt', $mac10Content);
            $zip->close();
            $generated[] = 'mac10.zip';
        }

        // ── 2. maccms.zip ─────────────────────────────────────────────────
        $flagSafe = htmlspecialchars($playerFlag, ENT_XML1, 'UTF-8');
        $hostSafe = htmlspecialchars($siteHost, ENT_QUOTES, 'UTF-8');
        $maccmsContent = "<status>1</status><sort></sort>"
            . "<from>{$flagSafe}</from><show>{$flagSafe}</show>"
            . "<des>{$hostSafe}</des><tip></tip><code></code>";

        $zipPath = $outDir . 'maccms.zip';
        $zip = new \ZipArchive();
        if ($zip->open($zipPath, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) === true) {
            $zip->addFromString('maccms/vodplay_bfm3u8.txt', $maccmsContent);
            $zip->close();
            $generated[] = 'maccms.zip';
        }

        // ── 3. seacms.zip ─────────────────────────────────────────────────
        $seacmsTemplate = <<<'NOWDOC'
<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml">
<head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<style>*{margin:0;padding:0}html,body,#play_box{width:100%;height:100%}</style></head>
<body><div id="play_box"><div id="player"></div></div>
<script>
var playerh=parent.playerh?parent.playerh-33:window.innerHeight;
var str=parent.now||'';
document.getElementById('player').innerHTML='<iframe width="100%" height="'+playerh+'" src="__PH__'+str+'" frameborder="0" allowfullscreen="true"></iframe>';
</script></body></html>
NOWDOC;
        $seacmsContent = str_replace('__PH__', addslashes($playerHost), $seacmsTemplate);

        $zipPath = $outDir . 'seacms.zip';
        $zip = new \ZipArchive();
        if ($zip->open($zipPath, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) === true) {
            $zip->addFromString('seacms/seacms/bfzym3u8.html', $seacmsContent);
            $zip->close();
            $generated[] = 'seacms.zip';
        }

        // ── 4. seacms87.zip ───────────────────────────────────────────────
        $zipPath = $outDir . 'seacms87.zip';
        $zip = new \ZipArchive();
        if ($zip->open($zipPath, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) === true) {
            $zip->addFromString('seacms87/seacms87/bfzym3u8.html', $seacmsContent);
            $zip->close();
            $generated[] = 'seacms87.zip';
        }

        // ── 5. ff50player.zip ─────────────────────────────────────────────
        $ff50Template = <<<'NOWDOC'
function $Showhtml(){player='<iframe width="100%" height="'+Player.Height+'" src="__PH__'+Player.Url+'" frameborder="0" border="0" scrolling="no" allowfullscreen="true"></iframe>';return player;}
Player.Show();
NOWDOC;
        $ff50Content = str_replace('__PH__', addslashes($playerHost), $ff50Template);

        $zipPath = $outDir . 'ff50player.zip';
        $zip = new \ZipArchive();
        if ($zip->open($zipPath, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) === true) {
            $zip->addFromString('ff50player/bfzym3u8.js', $ff50Content);
            $zip->addFromString('ff50player/bfzym3u8.min.js', $ff50Content);
            $zip->close();
            $generated[] = 'ff50player.zip';
        }

        // ── 6. player.zip ─────────────────────────────────────────────────
        $playerTemplate = <<<'NOWDOC'
<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml">
<head><meta http-equiv="Content-Type" content="text/html; charset=gb2312" />
<style>body{margin:0;padding:0}</style></head>
<body><div id="player"></div>
<script>
var playurlinfo=window.parent.playurl||'';
var playerh=window.parent.pHeight?window.parent.pHeight-30:window.innerHeight;
document.getElementById('player').innerHTML='<iframe width="100%" height="'+playerh+'" src="__PH__'+playurlinfo+'" frameborder="0" allowfullscreen="true"></iframe>';
</script></body></html>
NOWDOC;
        $playerContent = str_replace('__PH__', addslashes($playerHost), $playerTemplate);

        $zipPath = $outDir . 'player.zip';
        $zip = new \ZipArchive();
        if ($zip->open($zipPath, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) === true) {
            $zip->addFromString('bfzym3u8/bfzym3u8/bfzym3u8.html', $playerContent);
            $zip->close();
            $generated[] = 'player.zip';
        }

        // 记录最后生成时间
        self::set('file_regen_time', (string)time());

        return $generated;
    }
}
