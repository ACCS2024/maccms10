<?php
namespace app\api\controller;

/**
 * 赞片(zanpian) 专用采集接口
 * 路由：api.php/Zanpian/vod/
 *
 * 老站上 Zanpian.php 与 Feifei.php 除类名和缓存键前缀外逐字节相同 ——
 * 两个接口并存只是因为下游采集软件按固定路径名请求，输出格式完全一致。
 * 因此这里直接继承 Feifei，只覆盖缓存键前缀，避免两份代码日后各自漂移。
 */
class Zanpian extends Feifei
{
    protected $cachePrefix = 'zanpian_api_vod_';
}
