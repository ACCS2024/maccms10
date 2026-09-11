<?php
namespace app\index\controller;

class Gbook extends Base
{
    var $_config;
    public function __construct()
    {
        parent::__construct();
        //关闭中
        if($GLOBALS['config']['gbook']['status'] == 0){
            throw new \think\exception\HttpResponseException(\think\Response::create('gbook is close'));
        }
    }

    public function index()
    {
        if (Request()->isPost()) {
            return $this->saveData();
        }
        $param = mac_param_url();
        $this->assign('param',$param);
        $this->assign('gbook',$GLOBALS['config']['gbook']);
        return $this->label_fetch('gbook/index');
    }

    public function ajax()
    {
        $param = mac_param_url();
        $this->assign('param',$param);
        $this->assign('gbook',$GLOBALS['config']['gbook']);
        return $this->label_fetch('gbook/ajax',0,'json');
    }

    public function report()
    {
        $param = mac_param_url();
        $this->assign('param',$param);
        $this->assign('gbook',$GLOBALS['config']['gbook']);
        return $this->label_fetch('gbook/report');
    }
    
    public function saveData() {
        return \app\common\util\GbookSubmission::submit(request(), true);
    }

}
