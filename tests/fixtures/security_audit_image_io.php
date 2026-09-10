<?php
/** Controlled partial-write/rename faults; all successful I/O uses the real filesystem. */
namespace app\common\util;
function file_put_contents($path, $data, ...$options) {
    if (($GLOBALS['image_io_fault'] ?? '') === 'partial' && str_starts_with(basename($path), '.image-')) {
        return \file_put_contents($path, substr($data, 0, 5), ...$options);
    }
    return \file_put_contents($path, $data, ...$options);
}
function rename($source, $target) {
    if (($GLOBALS['image_io_fault'] ?? '') === 'rename' && str_starts_with(basename($source), '.image-')) { return false; }
    return \rename($source, $target);
}
