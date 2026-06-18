<?php
namespace app\common\taglib;
use think\template\TagLib;
use think\facade\Db;

class Macdiy extends Taglib {

	protected $tags = [
        'test'=> ['attr'=>'order,by,num'],
    ];

    public function tagTest($tag,$content)
    {
        // 安全加固(V17):移除 dump()+die 调试输出(信息泄露/DoS),生产环境置空
        return '';
    }
}
