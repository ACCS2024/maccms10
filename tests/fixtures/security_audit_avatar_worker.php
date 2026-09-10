<?php
/** A real independent DB connection/process; only pause boundaries and transport faults are controlled. */
declare(strict_types=1);
namespace app\common\util {
    function fopen($path, $mode, ...$arguments) {
        if (($GLOBALS['case'] ?? '') !== 'permissions' || $mode !== 'x+b') { return \fopen($path,$mode,...$arguments); }
        $uid=posix_geteuid();
        if ($uid===0 && !posix_seteuid(65534)) throw new \RuntimeException('Cannot drop privilege for filesystem test');
        try { return \fopen($path,$mode,...$arguments); }
        finally { if ($uid===0 && !posix_seteuid($uid)) throw new \RuntimeException('Cannot restore fixture privilege'); }
    }

    function stream_copy_to_stream($source, $destination, ...$arguments) {
        $copied=\stream_copy_to_stream($source,$destination,...$arguments);
        $GLOBALS['avatar_event']=['stage'=>dirname(stream_get_meta_data($source)['uri']),
            'path'=>substr(stream_get_meta_data($destination)['uri'],strlen(ROOT_PATH))];
        \avatarPause('published');
        return $copied;
    }
}
namespace {
    require dirname(__DIR__,2).'/vendor/autoload.php';
    [$script,$root,$case,$prefix]=$argv;
    if (!is_dir($root) || !str_contains(basename(rtrim($root,'/')),'upload-identity-')) {
        throw new RuntimeException('Avatar worker requires its isolated fixture root');
    }
    define('ROOT_PATH',$root);define('MAC_PATH','/');chdir($root);
    function request() { return \think\Container::getInstance()->make('request'); }
    function lang($key,$variables=[]) { return $key; }
    function mac_validate($name) { $class='app\\common\\validate\\'.$name;return new $class(); }
    function config($key,$default=null) { return \think\facade\Config::get($key,$default); }
    function avatarPause(string $at): void {
        global $case,$prefix;
        if ($case!==$at) return;
        file_put_contents($prefix.'.ready',json_encode($GLOBALS['avatar_event'],JSON_THROW_ON_ERROR));
        $until=microtime(true)+15;
        while (!is_file($prefix.'.release') && microtime(true)<$until) {usleep(10000);clearstatcache();}
        if (!is_file($prefix.'.release')) throw new RuntimeException('Avatar fault controller did not release the worker');
    }
    trait AvatarCommitEvents {
        public function commit(): void {
            avatarPause('before-commit');
            if ($GLOBALS['case']==='throw-before') throw new RuntimeException('Fixture rejected COMMIT');
            parent::commit();
            if ($GLOBALS['case']==='throw-after') throw new RuntimeException('Fixture lost COMMIT acknowledgement');
            avatarPause('after-commit');
        }
    }
    class AvatarProcessMysql extends \think\db\connector\Mysql {
        use AvatarCommitEvents;
        public function __construct(array $config=[]) { $config['type']='mysql';parent::__construct($config); }
    }
    class AvatarProcessSqlite extends \think\db\connector\Sqlite {
        use AvatarCommitEvents;
        public function __construct(array $config=[]) { $config['type']='sqlite';parent::__construct($config); }
    }
    $database=json_decode(file_get_contents($root.'avatar-process.json'),true,512,JSON_THROW_ON_ERROR);
    $database['connections']['upload']['type']=$database['connections']['upload']['type']==='mysql' ? '\\AvatarProcessMysql' : '\\AvatarProcessSqlite';
    $manager=new \think\DbManager();$manager->setConfig($database);
    $configuration=new \think\Config();$configuration->set($database,'database');
    \think\Container::getInstance()->instance('think\\DbManager',$manager);
    \think\Container::getInstance()->instance('config',$configuration);
    $GLOBALS['config']['user']['portrait_size']='30x20';
    \think\Container::getInstance()->instance('request',(new \think\Request())->withServer(['REQUEST_METHOD'=>'POST','REQUEST_TIME'=>time()]));
    if ($case==='permissions') chmod(ROOT_PATH.'upload/user/1',0555);
    try {
        $data=\app\common\util\LocalAttachment::storeAvatar(['flag'=>'user','input'=>'file','thumb'=>'0','thumb_class'=>'',
            'imgdata'=>'data:image/png;base64,'.base64_encode(file_get_contents('source.png'))],[],1,true);
        echo json_encode(['code'=>1,'file'=>$data['file']],JSON_THROW_ON_ERROR);
    } catch (Throwable $error) {
        echo json_encode(['code'=>0,'message'=>$error->getMessage(),'event'=>$GLOBALS['avatar_event']??null],JSON_THROW_ON_ERROR);
    } finally {
        if ($case==='permissions') chmod(ROOT_PATH.'upload/user/1',0755);
    }
}
