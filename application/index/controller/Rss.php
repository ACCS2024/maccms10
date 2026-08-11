<?php
namespace app\index\controller;

class Rss extends Base
{
    public function __construct()
    {
        parent::__construct();
        // 注意:这里的 header() 会被 TP8 的 Response::send() 覆盖掉
        // (框架按 Response 自身的 contentType 再发一次同名头,后发者生效)。
        // 真正决定对外 Content-Type 的是每个动作返回的 Response,见下方 ->contentType('text/xml')。
        // 留着它只为兼容"动作里直接 echo 后 die"的老路径。
        header("Content-Type:text/xml");
    }

    /**
     * 渲染一个 rss 模板;主题没提供就干净地 404,不要 500。
     *
     * 为什么需要这层:恢复 .xml 后缀解析之后,/rss.xml 这类路径开始真正落到本控制器,
     * 于是「主题缺模板」从原来的路由不匹配(404)变成了 TemplateNotFoundException(500)。
     * rss 是给搜索引擎爬的公开端点,主题是第三方产物、rss/ 目录本就是可选项
     * (线上 155zy 主题只有 art/comment/index/public/topic/user/vod 七个目录,没有 rss/)。
     *
     * 这里选 404 而不是像 map 那样 302 回首页:feed 地址上 302 到一篇 HTML,
     * 爬虫拿到的是内容类型不符的响应;404 才是"本站不提供这个 feed"的诚实表达。
     */
    private function feed(string $tpl)
    {
        try {
            return response($this->label_fetch($tpl))->contentType('text/xml');
        } catch (\think\template\exception\TemplateNotFoundException $e) {
            return response(
                '<?xml version="1.0" encoding="utf-8"?>' . "\n"
                . '<!-- feed not available: current template provides no ' . $tpl . ' -->',
                404
            )->contentType('text/xml');
        }
    }

    public function index()
    {
        return $this->feed('rss/index');
    }

    public function baidu()
    {
        return $this->feed('rss/baidu');
    }

    public function google()
    {
        return $this->feed('rss/google');
    }

    public function so()
    {
        return $this->feed('rss/so');
    }

    public function sogou()
    {
        return $this->feed('rss/sogou');
    }

    public function bing()
    {
        return $this->feed('rss/bing');
    }

    public function sm()
    {
        return $this->feed('rss/sm');
    }

}
