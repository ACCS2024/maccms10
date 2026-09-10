<?php
/** Controlled SDK boundary with the actual requested key/source, never an in-memory business database. */
namespace Aws\S3 {
    class S3Client {
        public function __construct(private array $options=[]) {}
        public function getObjectUrl($bucket,$key) {return 'https://'.$bucket.'.s3.'.$this->options['region'].'.amazonaws.com/'.$key;}
        public function putObject($parameters) {
            \remoteProviderWrite($parameters['Key']);
            return match($GLOBALS['storage_provider_mode']) {
                'false'=>false,'null'=>null,
                default=>new \Aws\Result(['ObjectURL'=>'https://objects.fixture.invalid/'.$parameters['Bucket'].'/'.$parameters['Key'],
                    '@metadata'=>['statusCode'=>200]]),
            };
        }
    }
}
namespace Upyun {
    class Config {public function __construct(...$arguments) {}}
    class Upyun {public function __construct(...$arguments) {}}
    class Uploader {
        public function __construct(...$arguments) {}
        public function upload($path,$stream,$parameters,$async) {
            \remoteProviderWrite($path);
            return match($GLOBALS['storage_provider_mode']){'false'=>false,'null'=>null,default=>new \GuzzleHttp\Psr7\Response(200)};
        }
    }
}
namespace Qiniu {class Auth {public function __construct(...$arguments) {} public function uploadToken(...$arguments) {return 'fixture-token';}}}
namespace Qiniu\Storage {
    class UploadManager {
        public function putFile($token,$path,$absolute) {
            \remoteProviderWrite($path);
            return $GLOBALS['storage_provider_mode']==='false'?[null,new \RuntimeException('controlled provider failure')]
                :[['newName'=>$path,'fsize'=>filesize($absolute),'hash'=>'fixture-etag'],null];
        }
    }
}
namespace app\common\util {
    class Ftp {
        public function __construct(...$arguments) {} public function connect() {return $this;}
        public function put($source,$destination) {\remoteProviderWrite($destination);return $GLOBALS['storage_provider_mode']!=='false';}
    }
    class SinaUpload {
        public array $_config=['cookie'=>'fixture-cookie'];
        public function config($config){}
        public function check(){return ['code'=>1];}
        public function upload($absolute,...$arguments){$url=\remoteImageWrite($absolute);return $GLOBALS['storage_provider_mode']==='false'?[]:['url'=>$url];}
    }
}
namespace app\common\extend\upload {
    function curl_init(){return new \stdClass();}
    function curl_setopt($handle,$option,$value){$handle->{$option}=$value;return true;}
    function curl_exec($handle){
        $url=\remoteImageWrite($handle->{CURLOPT_POSTFIELDS}['file']->getFilename());
        return json_encode(['code'=>$GLOBALS['storage_provider_mode']==='false'?1:0,'url'=>$url],JSON_THROW_ON_ERROR);
    }
    function curl_close($handle){}
    function mac_curl_post($url,$data){
        $image=\remoteImageWrite($data['Filedata']->getFilename());
        return json_encode(['code'=>$GLOBALS['storage_provider_mode']==='false'?0:1,'imgurl'=>$image],JSON_THROW_ON_ERROR);
    }
}
namespace {
    function remoteProviderWrite(string $path):void {
        $GLOBALS['storage_provider_calls']++;
        ($GLOBALS['storage_provider_callback'])($path);
        if($GLOBALS['storage_provider_mode']==='throw')throw new RuntimeException('controlled provider failure after a possible external write');
    }
    function remoteImageWrite(string $absolute):string {
        $path=substr($absolute,strlen(ROOT_PATH));remoteProviderWrite($path);
        return ($GLOBALS['storage_provider_mode']==='wrong-url'?'https://attacker.invalid/':'https://images.fixture.invalid/objects/').basename($path);
    }
}
