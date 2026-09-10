<?php
// 修改本文件后同步 application/extra/version.php 的 update_hash。
namespace app\admin\controller;

class Update extends Base
{
    public function index()
    {
        return $this->fetch('admin@update/index');
    }

    // Legacy routes remain harmless bookmarks. Code updates use this fork's repository;
    // database changes use the reviewed, local automatic migrations in application code.
    public function step1($file = '')
    {
        return $this->index();
    }

    public function step2()
    {
        return $this->index();
    }

    public function step3()
    {
        return $this->index();
    }
}
