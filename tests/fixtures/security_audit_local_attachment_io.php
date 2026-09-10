<?php
namespace app\common\util;
function stream_copy_to_stream($source, $destination, ...$arguments) {
    $GLOBALS['attachment_publish_count'] = ($GLOBALS['attachment_publish_count'] ?? 0) + 1;
    $fault = $GLOBALS['attachment_io_fault'] ?? '';
    if ($fault === 'corrupt-write') { return \fwrite($destination, str_repeat('x', \fstat($source)['size'])); }
    if ($fault === 'short-write') { return \stream_copy_to_stream($source, $destination, 5); }
    if ($fault === 'second-publish' && $GLOBALS['attachment_publish_count'] === 2) { return false; }
    return \stream_copy_to_stream($source, $destination, ...$arguments);
}
function random_bytes($length) {
    return isset($GLOBALS['attachment_random_fixture']) ? str_repeat($GLOBALS['attachment_random_fixture'], $length) : \random_bytes($length);
}
