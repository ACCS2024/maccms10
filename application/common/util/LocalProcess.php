<?php
declare(strict_types=1);
namespace app\common\util;

/** Bounded argv-only child process for trusted local tools. Never expose this as a request command API. */
final class LocalProcess
{
    public static function capture(array $argv, string $input = '', float $timeout = 0.5, int $maxOutput = 65536): ?string
    {
        if ($argv === [] || count($argv) > 32 || !is_finite($timeout) || $timeout < 0.01 || $timeout > 10
            || $maxOutput < 1 || $maxOutput > 16777216 || strlen($input) > 8388608) { return null; }
        foreach ($argv as $argument) {
            if (!is_string($argument) || strlen($argument) > 8192 || str_contains($argument, "\0")) { return null; }
        }
        foreach (['proc_open','proc_get_status','proc_terminate','proc_close'] as $function) {
            if (!function_exists($function)) { return null; }
        }
        $process = null; $pipes = [];
        try {
            $process = @proc_open(array_values($argv), [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']], $pipes, null, null, ['bypass_shell'=>true]);
            if (!is_resource($process)) { return null; }
            foreach ($pipes as $pipe) { stream_set_blocking($pipe, false); }
            $output = ''; $size = 0; $offset = 0; $length = strlen($input);
            $deadline = hrtime(true) + (int)($timeout * 1000000000);
            do {
                $progress = 0;
                if (isset($pipes[0])) {
                    if ($offset < $length) {
                        $written = @fwrite($pipes[0], substr($input, $offset, 8192));
                        if ($written === false) { return null; }
                        $offset += $written; $progress += $written;
                    }
                    if ($offset === $length) { fclose($pipes[0]); unset($pipes[0]); }
                }
                $chunk = stream_get_contents($pipes[1], 8192); $errors = stream_get_contents($pipes[2], 8192);
                if ($chunk === false || $errors === false) { return null; }
                $output .= $chunk; $read = strlen($chunk) + strlen($errors); $size += $read; $progress += $read;
                if ($size > $maxOutput || hrtime(true) >= $deadline) { return null; }
                $state = proc_get_status($process);
                if (!$state['running'] && feof($pipes[1]) && feof($pipes[2])) {
                    return $state['exitcode'] === 0 && $offset === $length ? $output : null;
                }
                if ($progress === 0) { usleep(5000); }
            } while (true);
        } catch (\Throwable $error) { return null; }
        finally {
            if (is_resource($process)) {
                $state = proc_get_status($process);
                if ($state['running']) { @proc_terminate($process, 9); }
            }
            foreach ($pipes as $pipe) { if (is_resource($pipe)) { fclose($pipe); } }
            if (is_resource($process)) { @proc_close($process); }
        }
    }
}
