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

echo 'Directory regressions: ' . $checks . " assertions passed\n";
} finally { audit_remove_temp($temp); }
