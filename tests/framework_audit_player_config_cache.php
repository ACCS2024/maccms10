<?php
/** Real, bounded player configuration replacement in an isolated deployment root. */
declare(strict_types=1);
require dirname(__DIR__).'/vendor/autoload.php';
require __DIR__.'/fixtures/security_audit_test_helpers.php';
use app\common\util\PlayerConfigCache;
$temp=audit_temp_dir('player-config');mkdir($temp.'/site/static/js',0700,true);mkdir($temp.'/outside',0700);
$root=$temp.'/site';$directory=$root.'/static/js';$target=$directory.'/playerconfig.js';
register_shutdown_function(static function()use($temp,$directory):void{if(is_dir($directory)&&!is_link($directory))chmod($directory,0700);audit_remove_temp($temp);});
$prefix="var MacPlayerConfig={width:'100%'};\n//缓存开始";$suffix="//缓存结束\nvar preserved='tail';\n";
$original=$prefix."\nold_cache();\n".$suffix;file_put_contents($target,$original);
$players=['ordinary'=>['show'=>'中文 player','des'=>'Quotes " and <text>','ps'=>1,'parse'=>'https://example.invalid/?url=']];
check(PlayerConfigCache::refresh($root,$players,[],[]),'Ordinary player configuration must publish successfully');
$updated=file_get_contents($target);
check(str_starts_with($updated,$prefix."\r\n")&&str_ends_with($updated,$suffix),'Only the generated section may change; player parameters and suffix must remain byte-exact');
preg_match('/MacPlayerConfig.player_list=(.*),MacPlayerConfig.downer_list=(.*),MacPlayerConfig.server_list=(.*);\r\n/',$updated,$match);
$decoded=json_decode($match[1],true,512,JSON_THROW_ON_ERROR);
check($decoded['ordinary']===['show'=>'中文 player','des'=>'Quotes " and <text>','ps'=>'1','parse'=>'https://example.invalid/?url='],'Published JSON must preserve ordinary text and established string field values');
check($match[2]==='{}'&&$match[3]==='{}','Empty player lists remain lookup objects');
check(PlayerConfigCache::refresh($root,$players,[],[])&&file_get_contents($target)===$updated,'Repeated identical refresh must remain usable');
check(PlayerConfigCache::refresh($root,['minimal'=>['show'=>'Minimal']],[],[]),'Legacy entries missing optional description/parser fields must remain usable');
preg_match('/MacPlayerConfig.player_list=(.*),MacPlayerConfig.downer_list=/',$v=file_get_contents($target),$m);
check(json_decode($m[1],true,512,JSON_THROW_ON_ERROR)['minimal']===['show'=>'Minimal','des'=>'','ps'=>'','parse'=>''],'Only documented optional display fields receive defaults');
$badLists=[null,true,'invalid',[['show'=>[]]],[['show'=>null]],[['des'=>'missing name']],[['show'=>true]],
    [['show'=>"bad\xff"]],['__proto__'=>['show'=>'invalid']],['bad'."\0"=>['show'=>'invalid']],
    [['show'=>str_repeat('x',65537)]],array_fill(0,4097,['show'=>'ordinary'])];
foreach($badLists as $bad) {
    foreach([0,1,2] as $group) {
        $args=[$players,[],[]];$args[$group]=$bad;
        check(!PlayerConfigCache::refresh($root,...$args)&&file_get_contents($target)===$v,'Malformed player/server lists must fail without replacing the last valid configuration');
    }
}
$large=array_fill(0,17,['show'=>str_repeat('x',65536)]);
check(!PlayerConfigCache::refresh($root,$large,[],[])&&file_get_contents($target)===$v,'Aggregate input budget must be enforced before unbounded output allocation');
foreach(['','no generated section',$suffix."\n".$prefix."\n",$original.$original,
    "var x='//缓存开始';\n//缓存结束",$prefix.'same line'."\n".$suffix,$prefix."\n".'//缓存结束suffix'] as $badFile) {
    file_put_contents($target,$badFile);
    check(!PlayerConfigCache::refresh($root,$players,[],[])&&file_get_contents($target)===$badFile,'Missing, duplicated, misordered or embedded markers must preserve the original file');
}
unlink($target);file_put_contents($target.'.bak',$original);
check(PlayerConfigCache::refresh($root,$players,[],[])&&is_file($target)&&file_get_contents($target.'.bak')===$original,'A missing live file may be recreated from its regular backup without changing that backup');
unlink($target);unlink($target.'.bak');
check(!PlayerConfigCache::refresh($root,$players,[],[])&&!file_exists($target),'Missing live and backup files must report failure');
file_put_contents($temp.'/outside/sentinel',$original);symlink($temp.'/outside/sentinel',$target);
check(!PlayerConfigCache::refresh($root,$players,[],[])&&is_link($target)&&file_get_contents($temp.'/outside/sentinel')===$original,'A live-file symlink must not permit replacing or modifying its target');
unlink($target);symlink($temp.'/outside/sentinel',$target.'.bak');
check(!PlayerConfigCache::refresh($root,$players,[],[])&&!file_exists($target),'A backup symlink must not be used as a source');
unlink($target.'.bak');rmdir($directory);symlink($temp.'/outside',$directory);
check(!PlayerConfigCache::refresh($root,$players,[],[])&&!file_exists($temp.'/outside/playerconfig.js'),'A linked managed JavaScript directory must be rejected');
unlink($directory);mkdir($directory,0700);mkdir($target,0700);
check(!PlayerConfigCache::refresh($root,$players,[],[])&&is_dir($target),'A directory in place of the target file must be preserved and reported as failure');
rmdir($target);file_put_contents($target,$original);
if(($argv[1]??'')==='unprivileged') {
    chmod($directory,0555);check(!is_writable($directory),'Permission fixture must run as an unprivileged account');
    check(!PlayerConfigCache::refresh($root,$players,[],[])&&file_get_contents($target)===$original,'Real publication permission failure must preserve the complete old configuration without a PHP diagnostic');
    chmod($directory,0700);check(PlayerConfigCache::refresh($root,$players,[],[]),'Publication must work after directory permissions are repaired');
}
check(glob($directory.'/.playerconfig-*')===[],'Success and ordinary failures must not leave publication temporary files');
echo 'Player configuration cache: '.$checks.' checks passed on PHP '.PHP_VERSION.' / '.($argv[1]??'ordinary')."\n";
