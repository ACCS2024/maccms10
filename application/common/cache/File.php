<?php
namespace app\common\cache;

use app\common\util\Dir;

/** Preserve the framework's storage format while reporting actual directory cleanup results. */
class File extends \think\cache\driver\File
{
    public function clear(): bool
    {
        $path = $this->options['path'];
        $prefix = $this->options['prefix'];
        if (!is_string($path) || !is_string($prefix)) { return false; }
        // Prefixes select a namespace below the configured cache directory.
        if ($prefix !== '' && (preg_match('~[\\\\:\x00-\x1f\x7f]~', $prefix)
            || str_starts_with($prefix, '/') || in_array('..', explode('/', $prefix), true)
            || in_array('.', explode('/', $prefix), true))) { return false; }
        try { return Dir::clearDirectory($path . ($prefix ?: '')); }
        catch (\Throwable $error) { return false; }
    }
}
