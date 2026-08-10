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

    public function index()
    {
        return response($this->label_fetch('rss/index'))->contentType('text/xml');
    }

    public function baidu()
    {
        return response($this->label_fetch('rss/baidu'))->contentType('text/xml');
    }

    public function google()
    {
        return response($this->label_fetch('rss/google'))->contentType('text/xml');
    }

    public function so()
    {
        return response($this->label_fetch('rss/so'))->contentType('text/xml');
    }

    public function sogou()
    {
        return response($this->label_fetch('rss/sogou'))->contentType('text/xml');
    }

    public function bing()
    {
        return response($this->label_fetch('rss/bing'))->contentType('text/xml');
    }

    public function sm()
    {
        return response($this->label_fetch('rss/sm'))->contentType('text/xml');
    }

}
