<?php
namespace app\common\util;

/** Rebuild only the generated lists, preserving the rest of the player configuration file. */
final class PlayerConfigCache
{
    private const MAX_BYTES = 8388608;

    public static function refresh(string $root, $players, $downloaders, $servers): bool
    {
        $temporary = null;
        try {
            $budget = 1048576;
            $content = 'MacPlayerConfig.player_list=' . self::listJson($players, ['show','des','ps','parse'], $budget)
                . ',MacPlayerConfig.downer_list=' . self::listJson($downloaders, ['show','des','ps','parse'], $budget)
                . ',MacPlayerConfig.server_list=' . self::listJson($servers, ['show','des'], $budget) . ';';
            if (str_contains($root, '://') || str_contains($root, "\0")) { return false; }
            $directory = realpath($root);
            if ($directory === false || !is_dir($directory)) { return false; }
            foreach (['static', 'js'] as $part) {
                $directory .= DIRECTORY_SEPARATOR . $part;
                if (is_link($directory) || !is_dir($directory)) { return false; }
            }
            $target = $directory . DIRECTORY_SEPARATOR . 'playerconfig.js';
            clearstatcache(true, $target);
            if (is_link($target) || (file_exists($target) && !is_file($target))) { return false; }
            $source = file_exists($target) ? $target : $target . '.bak';
            if (is_link($source) || !is_file($source)) { return false; }
            $original = @file_get_contents($source, false, null, 0, self::MAX_BYTES + 1);
            if ($original === false || strlen($original) > self::MAX_BYTES) { return false; }
            $begin = '//缓存开始'; $end = '//缓存结束';
            if (substr_count($original, $begin) !== 1 || substr_count($original, $end) !== 1) { return false; }
            $start = strpos($original, $begin); $stop = strpos($original, $end);
            if ($start >= $stop || ($start !== 0 && $original[$start - 1] !== "\n")
                || $original[$stop - 1] !== "\n") { return false; }
            $afterBegin = $start + strlen($begin);
            if (!in_array($original[$afterBegin] ?? '', ["\r", "\n"], true)
                || !in_array($original[$stop + strlen($end)] ?? '', ['', "\r", "\n"], true)) { return false; }
            $updated = substr($original, 0, $afterBegin) . "\r\n" . $content . "\r\n" . substr($original, $stop);
            if (strlen($updated) > self::MAX_BYTES) { return false; }
            if ($source === $target && $updated === $original) { return true; }
            $mode = @fileperms($source);
            if ($mode === false) { return false; }
            $temporary = $directory . DIRECTORY_SEPARATOR . '.playerconfig-' . bin2hex(random_bytes(16));
            $stream = @fopen($temporary, 'xb');
            if ($stream === false) { return false; }
            try {
                $position = 0; $length = strlen($updated);
                while ($position < $length) {
                    $written = @fwrite($stream, substr($updated, $position));
                    if ($written === false || $written === 0) { return false; }
                    $position += $written;
                }
                if (!@fflush($stream) || !@fsync($stream) || !@chmod($temporary, $mode & 0666)) { return false; }
            } finally { fclose($stream); }
            // Do not overwrite a source changed during generation or follow a substituted target link.
            clearstatcache(true, $target);
            if (is_link($target) || (file_exists($target) && ($source !== $target || !is_file($target)))
                || @file_get_contents($source, false, null, 0, self::MAX_BYTES + 1) !== $original
                || !@rename($temporary, $target)) { return false; }
            $temporary = null;
            return true;
        } catch (\Throwable $error) {
            return false;
        } finally {
            if ($temporary !== null && is_file($temporary)) { @unlink($temporary); }
        }
    }

    private static function listJson($input, array $fields, int &$budget): string
    {
        if (!is_array($input) || count($input) > 4096) { throw new \InvalidArgumentException('Invalid player list'); }
        $list = [];
        foreach ($input as $key => $row) {
            if (!is_array($row) || (string)$key === '' || strlen((string)$key) > 128 || $key === '__proto__'
                || preg_match('/[\x00-\x1f\x7f]/', (string)$key)) { throw new \InvalidArgumentException('Invalid player entry'); }
            $budget -= strlen((string)$key);
            $entry = [];
            foreach ($fields as $field) {
                if (!array_key_exists($field, $row) && $field !== 'show') { $value = ''; }
                else { $value = $row[$field] ?? null; }
                if ((!is_string($value) && !is_int($value)) || strlen((string)$value) > 65536) {
                    throw new \InvalidArgumentException('Invalid player field');
                }
                $budget -= strlen((string)$value);
                if ($budget < 0) { throw new \InvalidArgumentException('Player lists exceed the size limit'); }
                $entry[$field] = (string)$value;
            }
            $list[$key] = $entry;
        }
        return json_encode((object)$list, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
    }
}
