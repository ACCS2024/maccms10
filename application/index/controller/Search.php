<?php
namespace app\index\controller;

class Search extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    public function index()
    {
        return $this->label_fetch('vod/search');
    }

}
