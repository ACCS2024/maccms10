<?php
/** Directory object and symlink-safe recursive cleanup regressions. */
require __DIR__ . "/fixtures/security_audit_test_helpers.php";
require dirname(__DIR__) . '/application/common/util/Dir.php';
$temp = audit_temp_dir('directory');
try {
mkdir($temp . '/managed');
mkdir($temp . '/outside');
file_put_contents($temp . '/outside/sentinel', 'preserved');
file_put_contents($temp . '/managed/no-extension', 'fixture');
$dir = new \app\common\util\Dir($temp . '/managed');
check($dir->getFilename() === 'no-extension', 'Instance directory listing failed');
check($dir->getSize() === 7 && $dir->isFile(), 'Directory metadata failed');
check(count(iterator_to_array($dir)) === 1, 'Directory iteration failed');
check($dir->toArray()[0]['ext'] === '', 'Extensionless file failed');
file_put_contents($temp . '/managed/new.txt', 'second');
$dir->listFile($temp . '/managed/');
check(count($dir->toArray()) === 2, 'Directory listing reused a stale process snapshot');
$empty = new \app\common\util\Dir($temp . '/missing');
check($empty->getFilename() === false && $empty->getChildren() === false, 'Empty directory metadata raised a diagnostic');
symlink($temp . '/outside', $temp . '/managed/escape');
symlink($temp . '/managed', $temp . '/managed/cycle');
check(\app\common\util\Dir::delDir($temp . '/managed'), 'Managed cleanup failed');
check(file_get_contents($temp . '/outside/sentinel') === 'preserved', 'Recursive cleanup followed outside symlink');
symlink($temp . '/outside', $temp . '/linked-root');
check(\app\common\util\Dir::delDir($temp . '/linked-root'), 'Root symlink cleanup failed');
check(file_get_contents($temp . '/outside/sentinel') === 'preserved', 'Root symlink cleanup deleted target');
foreach (['/', '///', '/.', '/./'] as $suffix) {
    symlink($temp.'/outside', $temp.'/linked-root');
    check(\app\common\util\Dir::delDir($temp.'/linked-root'.$suffix), 'Root symlink with directory suffix must remove only the link');
    check(!is_link($temp.'/linked-root') && file_get_contents($temp.'/outside/sentinel') === 'preserved', 'Trailing directory notation must never expose the symlink target to recursive deletion');
}
symlink($temp.'/outside', $temp.'/parent-link');
mkdir($temp.'/outside/child');file_put_contents($temp.'/outside/child/sentinel','preserved');
check(!\app\common\util\Dir::delDir($temp.'/parent-link/child/'), 'Linked ancestor must not redirect cleanup into an external subtree');
check(file_get_contents($temp.'/outside/child/sentinel')==='preserved', 'Refused linked ancestor cleanup must preserve the entire external subtree');
symlink($temp.'/absent-target',$temp.'/broken-root');
check(\app\common\util\Dir::delDir($temp.'/broken-root/')&&!is_link($temp.'/broken-root'),'Broken root links must also be removable without following their target');
foreach ([null,[],true,'',$temp.'/outside/../outside',$temp."/bad\0path",'file://'.$temp.'/outside'] as $invalid) {
    check(!\app\common\util\Dir::delDir($invalid) && file_get_contents($temp.'/outside/sentinel')==='preserved', 'Malformed, root or parent traversal cleanup paths must fail before removal');
}
// Test system-root rejection through the pure path validator; never hand a real root to deletion code.
$normalize=new ReflectionMethod(\app\common\util\Dir::class,'cleanupDirectoryPath');
foreach (['/','///','.','./','/.','/./'] as $root) { check($normalize->invoke(null,$root)===null, 'Filesystem/current roots must be rejected before any filesystem operation'); }
mkdir($temp.'/ordinary');file_put_contents($temp.'/ordinary/file','fixture');
check(\app\common\util\Dir::delDir($temp.'/ordinary/')&&!file_exists($temp.'/ordinary'), 'Ordinary runtime directory cleanup must retain trailing-slash compatibility');

echo 'Directory regressions: ' . $checks . " assertions passed\n";
} finally { audit_remove_temp($temp); }
