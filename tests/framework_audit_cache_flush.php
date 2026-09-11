<?php
/** Actual console command, real isolated files, normal and unprivileged cleanup results. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
$temp=audit_temp_dir('cache-flush');define('RUNTIME_PATH',$temp.'/runtime/');
mkdir(RUNTIME_PATH,0700);mkdir($temp.'/outside',0700);file_put_contents($temp.'/outside/sentinel','preserved');
register_shutdown_function(static function()use($temp):void {
    foreach(['cache','temp','log'] as $name){$path=RUNTIME_PATH.$name;if(is_dir($path)&&!is_link($path))chmod($path,0700);}
    audit_remove_temp($temp);
});
function runCacheFlush(bool $withLog=false):array {
    $input=new \think\console\Input($withLog?['--with-log']:[]);$input->setInteractive(false);
    $output=new \think\console\Output('buffer');$command=new \app\command\CacheFlush();
    return [$command->run($input,$output),$output->fetch()];
}
function seedCacheFlush():void {
    foreach(['cache','temp','log'] as $name) {
        mkdir(RUNTIME_PATH.$name,0700);file_put_contents(RUNTIME_PATH.$name.'/ordinary','fixture');
    }
}
seedCacheFlush();[$code,$text]=runCacheFlush();
check($code===0&&!file_exists(RUNTIME_PATH.'cache')&&!file_exists(RUNTIME_PATH.'temp')&&is_file(RUNTIME_PATH.'log/ordinary'),'Ordinary console cleanup must preserve logs unless explicitly requested');
check(str_contains($text,'运行目录清理完成')&&!str_contains($text,'缓存已清空'),'CLI result must describe its actual runtime-directory scope');
if(function_exists('opcache_reset'))check(str_contains($text,'当前 PHP CLI 的 OPcache'),'OPcache output must identify the current CLI scope');
[$code,$text]=runCacheFlush(true);
check($code===0&&!file_exists(RUNTIME_PATH.'log')&&str_contains($text,'跳过(不存在) runtime/cache'),'Repeated cleanup and explicit log removal must remain usable');
symlink($temp.'/outside',RUNTIME_PATH.'cache');symlink($temp.'/missing',RUNTIME_PATH.'temp');
[$code,$text]=runCacheFlush();
check($code===0&&!is_link(RUNTIME_PATH.'cache')&&!is_link(RUNTIME_PATH.'temp')&&file_get_contents($temp.'/outside/sentinel')==='preserved','Real console paths must remove directory/broken links without touching their targets');
check(substr_count($text,'目标目录未改动')===2,'Symlink cleanup must not claim the target cache was emptied');
file_put_contents(RUNTIME_PATH.'cache','unexpected file');mkdir(RUNTIME_PATH.'temp',0700);file_put_contents(RUNTIME_PATH.'temp/ordinary','fixture');
[$code,$text]=runCacheFlush();
check($code===1&&file_get_contents(RUNTIME_PATH.'cache')==='unexpected file'&&!is_dir(RUNTIME_PATH.'temp'),'A misconfigured path must fail while unrelated permitted cleanup can finish');
check(str_contains($text,'清理失败 runtime/cache')&&str_contains($text,'未全部完成')&&!str_contains($text,'已清空 runtime/cache'),'Partial cleanup cannot print a successful result for the failed directory');
unlink(RUNTIME_PATH.'cache');
if(($argv[1]??'')==='unprivileged') {
    mkdir(RUNTIME_PATH.'cache',0700);file_put_contents(RUNTIME_PATH.'cache/protected','preserved');chmod(RUNTIME_PATH.'cache',0555);
    check(!is_writable(RUNTIME_PATH.'cache'),'Permission fixture must run as an unprivileged account');
    [$code,$text]=runCacheFlush();
    check($code===1&&file_get_contents(RUNTIME_PATH.'cache/protected')==='preserved'&&str_contains($text,'未全部完成'),'Actual deletion permission failure must return a nonzero exit code without a PHP diagnostic');
    chmod(RUNTIME_PATH.'cache',0700);
    check(runCacheFlush()[0]===0,'A deliberate retry after permissions are repaired must succeed');
}
echo 'Cache flush command: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($argv[1]??'ordinary')."\n";
