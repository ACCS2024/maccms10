<?php
declare(strict_types=1);
$process = proc_open([PHP_BINARY, '-d', 'error_reporting=-1', '-d', 'display_errors=1',
    '-d', 'disable_functions=proc_open,proc_get_status,proc_terminate,proc_close,disk_total_space,disk_free_space,shell_exec',
    __DIR__.'/framework_audit_system_metrics.php', 'disabled'], [0=>['file','/dev/null','r'],1=>STDOUT,2=>STDERR], $pipes);
if (!is_resource($process)) { throw new RuntimeException('Cannot start the disabled-function metrics fixture'); }
$status = proc_close($process);
if ($status !== 0) { throw new RuntimeException('Disabled-function metrics fixture failed: '.$status); }
