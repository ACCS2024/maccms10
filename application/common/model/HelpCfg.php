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
        try {
            $rows = Db::name('help_cfg')->select()->toArray();
        } catch (\Throwable $e) {
            // 表缺失/库不可用时降级为空配置,详见 self::get() 的说明
            return [];
        }
        $result = [];
        foreach ($rows as $row) {
            $result[$row['cfg_key']] = $row['cfg_val'];
        }
        return $result;
    }

    /**
     * 获取单个配置值
     *
     * 注意:本方法在 application/index/route/web.php 里被【路由定义阶段】调用
     * (用 help_path 决定帮助中心的路由前缀),也就是说它跑在每一个前台请求最前面。
     * 一旦这里抛异常,整站前台直接 500 —— mac_help_cfg 曾因漏在 install.sql 里建表
     * 而导致全新安装的站点首页全部 500。所以这里必须失效降级:
     * 拿不到配置就退回默认值,只让帮助中心这一个功能不可用,不牵连全站。
     */
    public static function get(string $key, string $default = ''): string
    {
        try {
            $val = Db::name('help_cfg')->where('cfg_key', $key)->value('cfg_val');
        } catch (\Throwable $e) {
            return $default;
        }
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
        // 从"线上验证可用"的模板包生成，只做 占位符→本站真实值 替换，保证与老版格式逐字节一致。
        // 模板取自历史 help/jiexi 那批经生产验证的播放器包（占位 flag=155m3u8 / 解析=www.155jx.com）。
        // 关键约束（否则采集方"装上点了不播"）：CMS 按【播放器标识=vod_play_from】识别播放器，故内层
        // 文件名与字段必须等于 player_flag；解析地址必须内嵌进播放器体；maccms8 的 <code> 不能为空。
        $cfg   = self::getAll();
        $flag  = trim((string)($cfg['player_flag'] ?? ''));
        $parse = trim((string)($cfg['player_host'] ?? ''));
        if ($parse === '') {
            $parse = trim((string)($cfg['parse_host'] ?? ''));
        }

        $outDir = ROOT_PATH . 'upload/help/';
        if (!is_dir($outDir)) {
            mkdir($outDir, 0755, true);
        }
        $tplDir = ROOT_PATH . 'application/data/help_player_templates/';

        // 模板里的固定占位符（老 155 包）
        $OLD_PARSE   = 'https://www.155jx.com/?url=';
        $OLD_FLAG    = '155m3u8';
        $OLD_FLAG_UP = '155M3U8';

        // 模板包 => 输出包名（对齐前端 index/Help::$knownFiles 与下载按钮）
        $map = [
            'maccms10.zip' => 'mac10.zip',
            'maccms8.zip'  => 'maccms.zip',
            'seacms.zip'   => 'seacms.zip',
            'seacms87.zip' => 'seacms87.zip',
            'feifei50.zip' => 'ff50player.zip',
        ];

        // 先替换解析地址（其中含 155 子串，必须先于 flag），再替换 flag 的大小写两形态
        $sub = static function (string $s) use ($OLD_PARSE, $OLD_FLAG_UP, $OLD_FLAG, $parse, $flag): string {
            return str_replace(
                [$OLD_PARSE, $OLD_FLAG_UP, $OLD_FLAG],
                [$parse, strtoupper($flag), $flag],
                $s
            );
        };

        $generated = [];
        foreach ($map as $tpl => $out) {
            $tplPath = $tplDir . $tpl;
            if (!is_file($tplPath)) {
                continue;
            }
            $src = new \ZipArchive();
            if ($src->open($tplPath) !== true) {
                continue;
            }
            $dst = new \ZipArchive();
            if ($dst->open($outDir . $out, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) !== true) {
                $src->close();
                continue;
            }
            for ($i = 0; $i < $src->numFiles; $i++) {
                $name = (string)$src->getNameIndex($i);
                if ($name === '' || substr($name, -1) === '/') {
                    continue; // 目录项由 addFromString 的路径自动重建
                }
                $content = $src->getFromIndex($i);
                if ($content === false) {
                    $content = '';
                }
                if (strpos($name, 'maccms10/') === 0) {
                    // maccms10 播放器包体是 base64(JSON)。JSON 里斜杠被转义为 \/，
                    // 直接串替换匹配不到解析地址 —— 必须先 json_decode 成真值再替换字段，
                    // 否则 code 里的解析地址仍指向老 155（表现为采集方能识别播放器但播放走错解析）。
                    $json = base64_decode($content, true);
                    $arr  = $json !== false ? json_decode($json, true) : null;
                    if (is_array($arr)) {
                        foreach ($arr as $kk => $vv) {
                            if (is_string($vv)) {
                                $arr[$kk] = $sub($vv);
                            }
                        }
                        $content = base64_encode(json_encode($arr, JSON_UNESCAPED_UNICODE));
                    } elseif ($json !== false) {
                        // 退路：JSON 解析失败时按字符串替换，兼顾转义斜杠形态
                        $content = base64_encode(strtr($json, [
                            $OLD_PARSE                            => $parse,
                            str_replace('/', '\\/', $OLD_PARSE)   => str_replace('/', '\\/', $parse),
                            $OLD_FLAG_UP                          => strtoupper($flag),
                            $OLD_FLAG                             => $flag,
                        ]));
                    }
                } else {
                    $content = $sub($content);
                }
                // 内层文件名里的 flag 占位也替换成本站 flag（CMS 按文件名识别播放器）
                $dst->addFromString(str_replace($OLD_FLAG, $flag, $name), $content);
            }
            $src->close();
            $dst->close();
            $generated[] = $out;
        }

        self::set('file_regen_time', (string)time());
        return $generated;
    }
}
