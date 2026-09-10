<?php
namespace app\common\extend\urlsend;

class Baidufast
{
    public $name = '百度推送快速';
    public $ver = '1.0';

    public function submit($data)
    {
        // Baidu retired this channel on 2024-04-26. Fast Crawl is a separate entitlement/API.
        // Keep the configured adapter name readable, without silently sending its token to the ordinary API.
        return ['code' => 105, 'msg' => '百度旧快速收录渠道已于 2024 年 4 月 26 日下线，本次未发送网址。'
            . '新“快速抓取”需要百度平台权益及最新接口；请到百度搜索资源平台操作，或使用本系统普通推送渠道。'];
    }
}
