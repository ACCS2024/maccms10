<?php

namespace app\common\util;

use think\facade\Cache;

/**
 * OpenCC 转换封装：优先 PHP 扩展 ext-opencc，其次系统 opencc 命令，均不可用时返回原文。
 * 进程内与跨请求（think\Cache）缓存转换结果。
 */
class OpenccConverter
{
    private static $shellChecked = false;
    private static $shellAvailable = false;
    private static $cache = [];
    /** @var array<string, mixed> opencc_open 句柄，false 表示该 config 不可用 */
    private static $extOd = [];
    /** @var bool|null 实测能否完成繁简转换（非仅扩展/命令是否存在） */
    private static $conversionWorks = null;
    /** 进程内缓存条目上限，防止 CLI 批处理无限增长撑爆内存 */
    private static $memCacheMax = 20000;

    /** 跨请求缓存 TTL（秒），简繁映射稳定可设较长 */
    private static $persistTtl = 2592000;
    /** shell opencc 可用性：成功结果缓存 TTL */
    private static $shellAvailableTtl = 86400;
    /** shell 探测失败缓存 TTL（安装后无需等 24h 才重新检测） */
    private static $shellUnavailableTtl = 300;
    /** shell 单次命令最长等待（秒），避免 opencc 卡死拖垮后台搜索 */
    private static $shellExecTimeout = 3;

    /**
     * 是否含汉字（简繁转换仅对汉字有意义；纯英文/番号不必 fork opencc）。
     */
    private static function containsHan($text)
    {
        return is_string($text) && $text !== '' && preg_match('/\p{Han}/u', $text) === 1;
    }

    /**
     * 带超时的 shell 执行，避免 shell_exec 无上限阻塞。
     *
     * @return string|null
     */
    private static function shellExecLimited($cmd, $timeoutSec = null)
    {
        $timeoutSec = max(1, (int)($timeoutSec ?? self::$shellExecTimeout));
        if (!function_exists('proc_open')) {
            return null;
        }
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $proc = @proc_open($cmd, $descriptors, $pipes, null, null, ['bypass_shell' => false]);
        if (!is_resource($proc)) {
            return null;
        }
        @fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $stdout = '';
        $deadline = microtime(true) + $timeoutSec;
        while (true) {
            $stdout .= (string)stream_get_contents($pipes[1]);
            $status = proc_get_status($proc);
            if (!$status['running']) {
                break;
            }
            if (microtime(true) >= $deadline) {
                @proc_terminate($proc);
                break;
            }
            // 用 stream_select 等 fd 就绪，而不是固定睡 50ms。
            // opencc 处理一行文本只要几毫秒，固定 50ms 轮询意味着每次调用
            // 至少浪费一个完整周期；批量场景下这是数量级的差异。
            $r = [$pipes[1]];
            $w = null;
            $x = null;
            @stream_select($r, $w, $x, 0, 5000); // 最多等 5ms
        }
        $stdout .= (string)stream_get_contents($pipes[1]);
        @fclose($pipes[1]);
        @fclose($pipes[2]);
        @proc_close($proc);

        return $stdout !== '' ? $stdout : null;
    }

    /**
     * 简体 -> 繁体（OpenCC s2t）。
     */
    public static function s2t($text)
    {
        return self::convert($text, 's2t');
    }

    /**
     * 繁体 -> 简体（OpenCC t2s）。
     */
    public static function t2s($text)
    {
        return self::convert($text, 't2s');
    }

    /**
     * @param string $config opencc 配置名，例如 s2t / t2s
     */
    public static function convert($text, $config)
    {
        $text = (string)$text;
        $config = trim((string)$config);
        if ($text === '' || $config === '') {
            return $text;
        }
        // 转换能力不可用时（既无 ext-opencc 也无 opencc 命令），转换是恒等变换。
        // 此时必须在【任何缓存操作之前】返回：否则每个字符串都会被写进
        // 进程内静态数组 self::$cache 与文件缓存 —— 全量重建 18 万条内容、
        // 每条数次转换，静态数组无上限增长直接撑爆 memory_limit
        // （实测在 17.8 万条时 OOM），文件缓存也写了上百万条恒等映射。
        if (!self::conversionAvailable()) {
            return $text;
        }

        $key = $config . ':' . md5($text);
        if (isset(self::$cache[$key])) {
            return self::$cache[$key];
        }
        // 进程内缓存加上限：常驻进程（队列/CLI 批处理）下不能无限增长
        if (count(self::$cache) >= self::$memCacheMax) {
            self::$cache = [];
        }

        $persistKey = 'opencc:' . $config . ':' . md5($text);
        if (class_exists('\think\Cache', false)) {
            try {
                $cached = Cache::get($persistKey);
                if (is_string($cached)) {
                    self::$cache[$key] = $cached;

                    return $cached;
                }
            } catch (\Throwable $e) {
                // 未初始化缓存时忽略
            }
        }

        $out = self::convertOnce($text, $config);
        if ($out === null || $out === '') {
            $out = $text;
        }
        self::$cache[$key] = $out;
        if (class_exists('\think\Cache', false)) {
            try {
                Cache::set($persistKey, $out, self::$persistTtl);
            } catch (\Throwable $e) {
            }
        }

        return $out;
    }

    /**
     * 本机是否真的具备繁简转换能力（扩展或命令二者其一）。
     * 结果按进程缓存：批处理里这个判断会被调用几十万次。
     */
    private static function conversionAvailable()
    {
        if (self::$conversionWorks !== null) {
            return self::$conversionWorks;
        }
        $ext = extension_loaded('opencc')
            && function_exists('opencc_open')
            && function_exists('opencc_convert');
        self::$conversionWorks = $ext ? true : self::isShellAvailable();

        return self::$conversionWorks;
    }

    /**
     * @return string|null
     */
    private static function convertOnce($text, $config)
    {
        $ext = self::convertWithExtension($text, $config);
        if ($ext !== null) {
            return $ext;
        }
        if (!self::isShellAvailable()) {
            return $text;
        }

        return self::execOpencc($text, $config);
    }

    /**
     * ext-opencc（opencc4php）：opencc_open / opencc_convert。
     *
     * @return string|null 扩展不可用或失败时返回 null
     */
    private static function convertWithExtension($text, $config)
    {
        if (!extension_loaded('opencc') || !function_exists('opencc_open') || !function_exists('opencc_convert')) {
            return null;
        }
        if (!array_key_exists($config, self::$extOd)) {
            $od = null;
            foreach (self::extensionConfigCandidates($config) as $cfgFile) {
                $od = @opencc_open($cfgFile);
                if ($od !== false && $od !== null) {
                    break;
                }
            }
            self::$extOd[$config] = ($od !== false && $od !== null) ? $od : false;
        }
        $od = self::$extOd[$config];
        if ($od === false || $od === null) {
            return null;
        }
        $converted = @opencc_convert($text, $od);
        if (!is_string($converted)) {
            $converted = @opencc_convert($od, $text);
        }

        return is_string($converted) ? $converted : null;
    }

    /**
     * @return string[]
     */
    private static function extensionConfigCandidates($config)
    {
        $config = trim((string)$config);
        $candidates = [
            $config . '.json',
            $config,
        ];
        $dir = getenv('OPENCC_CONFIG_DIR');
        if (is_string($dir) && $dir !== '') {
            $dir = rtrim($dir, '/\\');
            $candidates[] = $dir . DIRECTORY_SEPARATOR . $config . '.json';
            $candidates[] = $dir . DIRECTORY_SEPARATOR . $config;
        }

        return array_values(array_unique($candidates));
    }

    /**
     * 扩展或 shell 能完成实测转换即视为可用（供后台状态展示与索引/搜索）。
     */
    public static function available()
    {
        return self::conversionWorks();
    }

    /**
     * 搜索用词变体：原词、去空白、小写（英文）、OpenCC 繁简形式。
     *
     * @return string[]
     */
    public static function searchVariants($text)
    {
        $text = trim((string)$text);
        if ($text === '') {
            return [];
        }
        $variants = [$text];
        $compact = preg_replace('/\s+/u', '', $text);
        if (is_string($compact) && $compact !== '' && $compact !== $text) {
            $variants[] = $compact;
        }
        $lower = strtolower($text);
        if ($lower !== '' && $lower !== $text && !in_array($lower, $variants, true)) {
            $variants[] = $lower;
        }
        if (self::containsHan($text) && self::conversionWorks()) {
            foreach (['t2s', 's2t'] as $cfg) {
                $converted = self::convert($text, $cfg);
                if ($converted !== '' && $converted !== $text && !in_array($converted, $variants, true)) {
                    $variants[] = $converted;
                }
            }
        }

        return array_values(array_unique($variants));
    }

    /**
     * 后台 MySQL LIKE 用的 %关键词% 列表（含繁简变体）。
     *
     * @return string[]
     */
    public static function likePatterns($text)
    {
        $patterns = [];
        foreach (self::searchVariants($text) as $v) {
            $patterns[] = '%' . $v . '%';
        }

        return array_values(array_unique($patterns));
    }

    /**
     * 实测 OpenCC 能否完成简繁转换（避免“已装扩展但 opencc_open 失败”误报可用）。
     */
    public static function conversionWorks()
    {
        if (self::$conversionWorks !== null) {
            return self::$conversionWorks;
        }
        $persistKey = 'opencc:conversion_works';
        if (class_exists('\think\Cache', false)) {
            try {
                $cached = Cache::get($persistKey);
                if ($cached === 1 || $cached === '1' || $cached === true) {
                    self::$conversionWorks = true;

                    return true;
                }
                if ($cached === 0 || $cached === '0' || $cached === false) {
                    self::$conversionWorks = false;

                    return false;
                }
                // null = cache miss → fall through to actual detection
            } catch (\Throwable $e) {
                // 未初始化缓存时忽略
            }
        }
        $sample = '软件';
        $expect = '軟件';
        $works = false;
        $ext = self::convertWithExtension($sample, 's2t');
        if (is_string($ext) && $ext === $expect) {
            $works = true;
        } elseif (self::isShellAvailable()) {
            $shell = self::execOpencc($sample, 's2t');
            if (is_string($shell) && $shell === $expect) {
                $works = true;
            }
        }
        self::$conversionWorks = $works;
        if (class_exists('\think\Cache', false)) {
            try {
                Cache::set(
                    $persistKey,
                    $works ? 1 : 0,
                    $works ? self::$shellAvailableTtl : self::$shellUnavailableTtl
                );
            } catch (\Throwable $e) {
            }
        }

        return $works;
    }

    private static function isShellAvailable()
    {
        if (self::$shellChecked) {
            return self::$shellAvailable;
        }
        self::$shellChecked = true;
        $persistKey = 'opencc:shell_available';
        if (class_exists('\think\Cache', false)) {
            try {
                $cached = Cache::get($persistKey);
                if ($cached === 1 || $cached === '1' || $cached === true) {
                    self::$shellAvailable = true;
                    return true;
                }
                if ($cached === 0 || $cached === '0' || $cached === false) {
                    self::$shellAvailable = false;
                    return false;
                }
                // null = cache miss → fall through to shell probe
            } catch (\Throwable $e) {
                // 未初始化缓存时忽略
            }
        }
        if (!function_exists('shell_exec')) {
            self::$shellAvailable = false;
            if (class_exists('\think\Cache', false)) {
                try {
                    Cache::set($persistKey, 0, self::$shellUnavailableTtl);
                } catch (\Throwable $e) {
                }
            }

            return false;
        }
        try {
            // 【探测必须只看 stdout】原实现用 `opencc -V 2>&1` 并只判断
            // "输出非空"，而 opencc 未安装时 shell 会把
            //   sh: 1: opencc: not found
            // 经 2>&1 并入 stdout —— 于是"命令不存在"被判成"可用"。
            // 后果：此后每次繁简转换都去 proc_open 起一个注定失败的进程，
            // 再按 50ms 轮询等它退出，单次转换 ~100ms。全量重建 18 万条时
            // 每文档约 204ms，整体从几分钟劣化到 9 小时（实测）。
            // 这里改为：只取 stdout（不合并 stderr），且要求输出含版本特征。
            $ret = self::shellExecLimited('opencc -V', 2);
            if ($ret === null && function_exists('shell_exec')) {
                $ret = @shell_exec('opencc -V 2>/dev/null');
            }
            $ret = is_string($ret) ? trim($ret) : '';
            // opencc -V 形如 "opencc 1.1.6"；命令不存在时 stdout 为空
            self::$shellAvailable = $ret !== ''
                && stripos($ret, 'not found') === false
                && stripos($ret, 'command not found') === false
                && preg_match('/\d+\.\d+/', $ret) === 1;
        } catch (\Throwable $e) {
            self::$shellAvailable = false;
        }
        if (class_exists('\think\Cache', false)) {
            try {
                Cache::set(
                    $persistKey,
                    self::$shellAvailable ? 1 : 0,
                    self::$shellAvailable ? self::$shellAvailableTtl : self::$shellUnavailableTtl
                );
            } catch (\Throwable $e) {
            }
        }

        return self::$shellAvailable;
    }

    /**
     * 通过临时文件调用 opencc，避免命令行转义导致的文本损坏。
     *
     * @return string|null
     */
    private static function execOpencc($text, $config)
    {
        try {
            $tmpIn = tempnam(sys_get_temp_dir(), 'mcc_in_');
            $tmpOut = tempnam(sys_get_temp_dir(), 'mcc_out_');
            if ($tmpIn === false || $tmpOut === false) {
                return null;
            }
            file_put_contents($tmpIn, $text);
            $out = null;
            foreach ([$config . '.json', $config] as $cfgName) {
                $cmd = 'opencc -c ' . escapeshellarg($cfgName)
                    . ' -i ' . escapeshellarg($tmpIn)
                    . ' -o ' . escapeshellarg($tmpOut) . ' 2>&1';
                self::shellExecLimited($cmd, self::$shellExecTimeout);
                $chunk = @file_get_contents($tmpOut);
                if (is_string($chunk) && trim($chunk) !== '') {
                    $out = trim($chunk);
                    break;
                }
            }
            @unlink($tmpIn);
            @unlink($tmpOut);

            return is_string($out) ? $out : null;
        } catch (\Throwable $e) {
            return null;
        }
    }
}
