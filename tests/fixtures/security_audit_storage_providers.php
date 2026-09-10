<?php
namespace Aws\S3 {
    class S3Client {
        public function __construct(private array $options=[]) {}
        public function getObjectUrl($bucket,$key) {return 'https://'.$bucket.'.s3.'.$this->options['region'].'.amazonaws.com/'.$key;}
        public function putObject($parameters) {
            \storageProviderFault();
            if ($GLOBALS['storage_provider_mode']==='false')return false;
            if ($GLOBALS['storage_provider_mode']==='null')return null;
            return new \Aws\Result(['ObjectURL'=>'https://objects.fixture.invalid/'.$parameters['Bucket'].'/'.$parameters['Key'],
                '@metadata'=>['statusCode'=>$GLOBALS['storage_provider_mode']==='202'?202:200]]);
        }
    }
}
namespace Upyun {
    class Config {public function __construct(...$arguments) {}}
    class Uploader {
        public function __construct(...$arguments) {}
        public function upload($path,$stream,$params,$async) {
            \storageProviderFault();
            return match($GLOBALS['storage_provider_mode']) {
                'false'=>false,'null'=>null,'array'=>[],
                '202'=>new \GuzzleHttp\Psr7\Response(202),
                default=>new \GuzzleHttp\Psr7\Response(200),
            };
        }
    }
    class Upyun {
        public function __construct(...$arguments) {}
        public function write($path,$stream) {
            \storageProviderFault();
            return match($GLOBALS['storage_provider_mode']){'false'=>false,'null'=>null,default=>[]};
        }
    }
}
namespace Qiniu {
    class Auth {public function __construct(...$arguments) {} public function uploadToken(...$arguments) {return 'fixture-token';}}
}
namespace Qiniu\Storage {
    class UploadManager {
        public function putFile($token,$path,$absolute) {
            \storageProviderFault();
            return match($GLOBALS['storage_provider_mode']){
                'false'=>[null,new \RuntimeException('controlled provider failure')],
                'null'=>[[],null],
                'wrong-key'=>[['newName'=>'another-object','fsize'=>filesize($absolute),'hash'=>'etag'],null],
                'wrong-size'=>[['newName'=>$path,'fsize'=>filesize($absolute)+1,'hash'=>'etag'],null],
                'missing-hash'=>[['newName'=>$path,'fsize'=>filesize($absolute)],null],
                default=>[['newName'=>$path,'fsize'=>filesize($absolute),'hash'=>'etag'],null],
            };
        }
    }
}
namespace app\common\util {
    class Ftp {
        public function __construct(...$arguments) {} public function connect() {return $this;}
        public function put($source,$destination) {\storageProviderFault();return match($GLOBALS['storage_provider_mode']){'false'=>false,'null'=>'unexpected',default=>true};}
    }
}
namespace {
    function storageProviderFault():void {
        $GLOBALS['storage_provider_calls']++;
        if (isset($GLOBALS['storage_provider_callback']))($GLOBALS['storage_provider_callback'])();
        if ($GLOBALS['storage_provider_mode']==='throw')throw new RuntimeException('secret-bearing provider error must not be stored');
    }
}
