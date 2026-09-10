<?php
/** Independent process/connection. Only actual filesystem permission, SDK side effect and COMMIT boundaries are controlled. */
declare(strict_types=1);
namespace app\common\util {
    function fopen($path,$mode,...$arguments) {
        if(($GLOBALS['remote_case']??'')!=='permissions'||$mode!=='x+b')return \fopen($path,$mode,...$arguments);
        $uid=posix_geteuid();if($uid===0&&!posix_seteuid(65534))throw new \RuntimeException('Cannot drop fixture privilege');
        try{return \fopen($path,$mode,...$arguments);}finally{if($uid===0&&!posix_seteuid($uid))throw new \RuntimeException('Cannot restore fixture privilege');}
    }
    function stream_copy_to_stream($source,$destination,...$arguments) {
        $copied=\stream_copy_to_stream($source,$destination,...$arguments);
        $GLOBALS['remote_event']=['stage'=>dirname(stream_get_meta_data($source)['uri']),
            'path'=>substr(stream_get_meta_data($destination)['uri'],strlen(ROOT_PATH))];
        \remotePause('published');return $copied;
    }
}
namespace {
    require __DIR__.'/security_audit_remote_providers.php';
    require dirname(__DIR__,2).'/vendor/autoload.php';
    [$script,$root,$remoteCase,$prefix]=$argv;$GLOBALS['remote_case']=$remoteCase;
    if(!is_dir($root)||!str_contains(basename(rtrim($root,'/')),'upload-identity-'))throw new RuntimeException('Remote worker requires an isolated upload fixture');
    define('ROOT_PATH',$root);define('MAC_PATH','/');chdir($root);
    function request(){return think\Container::getInstance()->make('request');}
    function lang($key,$variables=[]){return $key;}
    function mac_validate($name){$class='app\\common\\validate\\'.$name;return new $class();}
    function config($key,$default=null){return think\facade\Config::get($key,$default);}
    function remotePause(string $boundary):void {
        global $remoteCase,$prefix;if($remoteCase!==$boundary)return;
        file_put_contents($prefix.'.ready',json_encode($GLOBALS['remote_event'],JSON_THROW_ON_ERROR));
        $until=microtime(true)+20;
        while(!is_file($prefix.'.release')&&microtime(true)<$until){usleep(10000);clearstatcache();}
        if(!is_file($prefix.'.release'))throw new RuntimeException('Remote fixture was not released');
    }
    trait RemoteCommitBoundary {
        public function commit():void {
            if(++$GLOBALS['remote_commit_count']!==4){parent::commit();return;}
            remotePause('before-commit');
            if($GLOBALS['remote_case']==='throw-before')throw new RuntimeException('Controlled business COMMIT failure');
            parent::commit();
            if($GLOBALS['remote_case']==='throw-after')throw new RuntimeException('Controlled business COMMIT acknowledgement loss');
            remotePause('after-commit');
        }
    }
    class RemoteProcessMysql extends think\db\connector\Mysql {
        use RemoteCommitBoundary;
        public function __construct(array $settings=[]){$settings['type']='mysql';parent::__construct($settings);}
    }
    class RemoteProcessSqlite extends think\db\connector\Sqlite {
        use RemoteCommitBoundary;
        public function __construct(array $settings=[]){$settings['type']='sqlite';parent::__construct($settings);}
    }
    $fixture=json_decode(file_get_contents(ROOT_PATH.'remote-process.json'),true,512,JSON_THROW_ON_ERROR);$database=$fixture['database'];
    $database['connections']['upload']['type']=$database['connections']['upload']['type']==='mysql'?'\\RemoteProcessMysql':'\\RemoteProcessSqlite';
    $manager=new think\DbManager();$manager->setConfig($database);$configuration=new think\Config();$configuration->set($database,'database');
    think\Container::getInstance()->instance('think\\DbManager',$manager);think\Container::getInstance()->instance('config',$configuration);
    think\Container::getInstance()->instance('request',(new think\Request())->withServer(['REQUEST_METHOD'=>'POST','REQUEST_TIME'=>time()]));
    $GLOBALS['config']=$fixture['settings'];$GLOBALS['storage_provider_mode']='success';$GLOBALS['storage_provider_calls']=0;$GLOBALS['remote_commit_count']=0;
    $GLOBALS['storage_provider_callback']=static function(string $path):void {
        if(think\facade\Db::connect()->getPdo()->inTransaction())throw new RuntimeException('Network retained a transaction');
        $intent=think\facade\Db::name('StorageIntent')->where('local_path',$path)->select()->toArray()[0];
        if($intent['transfer_state']!=='attempting'||$intent['reference_state']!=='pending')throw new RuntimeException('External write has no durable attempt');
        copy(ROOT_PATH.$path,ROOT_PATH.'remote-fixture/'.$intent['intent_id']);
        $GLOBALS['remote_event']+=['intent_id'=>$intent['intent_id'],'url'=>$intent['expected_url']];
        remotePause('provider');
    };
    if($remoteCase==='permissions')chmod(ROOT_PATH.'upload/user/1',0555);
    try {
        $data=app\common\util\LocalAttachment::storeAvatar(['flag'=>'user','input'=>'file','thumb'=>'0','thumb_class'=>'',
            'imgdata'=>'data:image/png;base64,'.base64_encode(file_get_contents('source.png'))],['mode'=>'s3','keep_local'=>0],1,true);
        echo json_encode(['code'=>1,'file'=>$data['file'],'path'=>$data['_portrait_path'],'event'=>$GLOBALS['remote_event'],'calls'=>$GLOBALS['storage_provider_calls']],JSON_THROW_ON_ERROR);
    } catch(Throwable $error) {
        echo json_encode(['code'=>0,'error'=>$error->getMessage(),'event'=>$GLOBALS['remote_event']??null,'calls'=>$GLOBALS['storage_provider_calls']],JSON_THROW_ON_ERROR);
    } finally {if($remoteCase==='permissions')chmod(ROOT_PATH.'upload/user/1',0755);}
}
