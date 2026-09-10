<?php
namespace app\common\extend\upload;

use app\common\util\SinaUpload as suOper;

class Weibo
{
    public $name = '新浪图床';
    public $ver = '1.0';
    private $config = [];

    public function __construct($config = []) {
        $this->config = $config;
    }

    public function submit($file_path)
    {
        $weibo =  new suOper();

        $weibo->config($GLOBALS['config']['upload']['api']['weibo']);
        $res = $weibo->check();

        if($res['code']>1){
            return $file_path;
        }
        $res = $weibo->upload(ROOT_PATH . $file_path, false, $weibo->_config['cookie']);
        if(!empty($res['url'])){
            return StorageResult::complete($file_path, $res['url'], $this->config);
        }
        return $file_path;
    }
}
