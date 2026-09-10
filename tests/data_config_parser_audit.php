<?php
/** Tool-only tests: no framework bootstrap, configuration loaders or real site configuration. */
declare(strict_types=1);
namespace app\common\util {
    function token_get_all(string $source, int $flags = 0): array
    {
        $GLOBALS['data_config_token_calls']++;
        return \token_get_all($source, $flags);
    }
}
namespace {
require dirname(__DIR__) . '/application/common/util/DataConfig.php';
use app\common\util\DataConfig;
set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $severity)) { return false; }
    throw new ErrorException($message, 0, $severity, $file, $line);
});
$checks = 0;
$GLOBALS['data_config_token_calls'] = 0;
function expectData(bool $condition, string $message): void
{
    global $checks;
    $checks++;
    if (!$condition) { throw new RuntimeException($message); }
}
function rejectData(string $source, bool $beforeTokenizing = false): void
{
    $calls = $GLOBALS['data_config_token_calls'];
    $rejected = false;
    try { DataConfig::parse($source); } catch (RuntimeException $error) { $rejected = true; }
    expectData($rejected, 'Expected a controlled data configuration rejection');
    if ($beforeTokenizing) {
        expectData($GLOBALS['data_config_token_calls'] === $calls, 'Oversized/unsupported lexical structure reached native token allocation');
    }
}
$scenario = $argv[1] ?? 'compatibility';
$started = hrtime(true);
switch ($scenario) {
    case 'compatibility':
        $values = [[], ['nested'=>[0, -1, PHP_INT_MIN, PHP_INT_MAX, 1.25, 1.0e-100, true, false, null]],
            ['url'=>'https://fixture.invalid/a?b=c&d=e', 'quoted'=>"a' \\ \n\0b", '中文'=>'😀'],
            ['labels'=>'eval base64_decode file_put_contents are ordinary text', 'binary'=>implode('', array_map('chr', range(0,255)))]];
        for ($i=0; $i<32; $i++) { $values[] = ['bytes'=>random_bytes(64), 'id'=>$i]; }
        foreach ($values as $expected) {
            expectData(DataConfig::parse("<?php\nreturn ".var_export($expected,true).";\n") === $expected, 'var_export data meaning changed');
        }
        expectData(DataConfig::parse('<?php /* comment */ return ["a\\nb\\t\\x41\\101\\$", "a\\qb", b\'binary\']; ?>' . "\n")
            === ["a\nb\tAA$", 'a\qb', 'binary'], 'String escapes/comment/close-tag contract changed');
        expectData(DataConfig::parse('<?PHP return [0o77,-0o77,077,0xff,0b110,1_000,00.5,01e2];')
            === [0o77,-0o77,077,0xff,0b110,1_000,00.5,01e2], 'Numeric literal meaning changed');
        rejectData('<?php return ["${}"];',true);
        break;
    case 'literal_edges':
        expectData(DataConfig::parse('<?php return ["\\u{4e2d}\\u{6587}\\u{1f600}", "$5", "$", "a\\\\b"];')
            === ['中文😀','$5','$','a\\b'], 'Literal dollar or Unicode escapes changed');
        expectData(DataConfig::parse('<?php return [1 /*?>*/ , 2 // comment ? question'."\n".'];') === [1,2], 'Block and line comments must follow PHP close-tag behavior');
        expectData(DataConfig::parse('<?php return []; //?>') === [], 'A close tag terminates a trailing line comment');
        break;
    case 'syntax_rejections':
        foreach (['<?php return 1;', '<?php return [UNKNOWN];', '<?php return [1+2];', '<?php return [1e9999];',
            '<?php return [0xFFFFFFFFFFFFFFFF];', '<?php return [NAN];', '<?php return [;',
            '<?php return ["a" . false];', '<?php return ["\\u{d800}"];', '<?php return ["\\u{110000}"];',
            '<?php return ['.PHP_INT_MAX.'=>0,1];'] as $source) { rejectData($source); }
        expectData(DataConfig::parse('<?php return ['.PHP_INT_MAX.'=>0];') === [PHP_INT_MAX=>0], 'An explicit maximum integer key remains valid');
        break;
    case 'dense_array':
        $source='<?php return ['.str_repeat('0,',33331).'];';
        $result=DataConfig::parse($source);
        expectData(count($result)===33331 && $result[33330]===0, 'The exact conservative token boundary changed array entries');
        unset($result);
        rejectData('<?php return ['.str_repeat('0,',33332).'];',true);
        break;
    case 'normal_configuration':
        $expected=[];
        for ($i=0; $i<1000; $i++) {
            $expected['option_'.$i]=['enabled'=>$i%2===0,'url'=>'https://fixture.invalid/'.$i,'points'=>$i];
        }
        expectData(DataConfig::parse('<?php return '.var_export($expected,true).';')===$expected,'A normal large associative var_export configuration changed meaning');
        $nested=DataConfig::parse('<?php return '.str_repeat('[',64).'0'.str_repeat(']',64).';');
        for ($i=0; $i<64; $i++) { $nested=$nested[0]; }
        expectData($nested===0,'Existing nesting boundary for literal values changed');
        expectData(is_array(DataConfig::parse('<?php return '.str_repeat('[',65).str_repeat(']',65).';')),'The deepest already-supported empty array remains valid');
        rejectData('<?php return '.str_repeat('[',66).str_repeat(']',66).';',true);
        break;
    case 'dense_rejection':
        rejectData('<?php return ['.str_repeat('0,',524288).'];',true);
        break;
    case 'large_string':
        $prefix="<?php return ['payload'=>'"; $suffix="'];";
        $bytes=8388608-strlen($prefix)-strlen($suffix);
        $source=$prefix.str_repeat('a',$bytes).$suffix;
        expectData(strlen($source)===8388608,'Large literal must reach exact byte boundary');
        $result=DataConfig::parse($source);
        expectData(strlen($result['payload'])===$bytes && strspn($result['payload'],'a')===$bytes,'Valid large literal was truncated or rejected');
        unset($result);
        rejectData($source.' ',true);
        break;
    case 'mixed':
        $source="<?php return ['payload'=>'".str_repeat('m',7*1024*1024)."','rows'=>[".str_repeat('0,',30000).']];';
        $result=DataConfig::parse($source);
        expectData(strlen($result['payload'])===7*1024*1024 && count($result['rows'])===30000,'Large literal plus normal array changed meaning');
        break;
    case 'escaped_string':
        $source='<?php return ["'.str_repeat('\\n',4*1024*1024-32).'"];';
        $result=DataConfig::parse($source);
        expectData(strlen($result[0])===4*1024*1024-32 && strspn($result[0],"\n")===strlen($result[0]),'A valid escape-dense large string changed meaning');
        break;
    case 'comments':
        $prefix='<?php /*';$suffix='*/ return [];';
        expectData(DataConfig::parse($prefix.str_repeat('c',8388608-strlen($prefix)-strlen($suffix)).$suffix)===[],'A valid large comment is not a dense token stream');
        rejectData('<?php '.str_repeat('/**/ ',250000).'return [];',true);
        break;
    case 'lexical_rejections':
        $dense=str_repeat('0,',524288);
        foreach (['<?php return ["'.str_repeat('$entry ',150000).'"];',
            '<?php return []; ?> "<?php return ['.$dense.'];"',
            '<?php return []; //?> "<?php return ['.$dense.'];"',
            '<?php return []; #?> "<?php return ['.$dense.'];"',
            '<?php return [<<<END'."\n".'text'."\n".'END];',
            '<?php return [`text`];', '<?php return [$_SERVER];', '<?php return ["{$0}"];',
            '<?php #[Example] function a(){} return [];',
            '<?php return ['.str_repeat('[',50000).'0'.str_repeat(']',50000).'];'] as $source) { rejectData($source,true); }
        break;
    case 'read':
        $temporary=sys_get_temp_dir().'/data-config-parser-'.bin2hex(random_bytes(8));
        if (!mkdir($temporary,0700)) { throw new RuntimeException('Cannot create parser fixture'); }
        try {
            expectData(DataConfig::read($temporary.'/missing.php')===[],'Absent optional data file changed');
            file_put_contents($temporary.'/safe.php','<?php return ["safe"=>true];');
            expectData(DataConfig::read($temporary.'/safe.php')===['safe'=>true],'Actual local data read failed');
            symlink($temporary.'/safe.php',$temporary.'/linked.php');
            foreach ([$temporary.'/linked.php',$temporary,'data://text/plain,<?php return [];'] as $path) {
                $rejected=false;
                try { DataConfig::read($path); } catch (RuntimeException $error) { $rejected=true; }
                expectData($rejected,'Only regular local data files may be read');
            }
            $marker=$temporary.'/executed';
            file_put_contents($temporary.'/bad.php','<?php file_put_contents('.var_export($marker,true).',"x"); return [];');
            $rejected=false;
            try { DataConfig::read($temporary.'/bad.php'); } catch (RuntimeException $error) {
                $rejected=true;expectData(!str_contains($error->getMessage(),$temporary),'Read diagnostic exposes absolute path');
            }
            expectData($rejected && !file_exists($marker),'Configuration code executed or escaped controlled rejection');
        } finally {
            foreach (glob($temporary.'/*') as $file) { unlink($file); }
            rmdir($temporary);
        }
        break;
    default: throw new RuntimeException('Unknown test scenario');
}
printf("DataConfig %s: %d checks; PHP %s; native_calls=%d; peak=%.2fMiB; limit=%s; %.3fs\n",
    $scenario,$checks,PHP_VERSION,$GLOBALS['data_config_token_calls'],memory_get_peak_usage(true)/1048576,ini_get('memory_limit'),(hrtime(true)-$started)/1e9);
}
