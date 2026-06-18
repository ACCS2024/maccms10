<?php
namespace think;

/**
 * TP8 迁移 Shim：TP8 framework 不含 think\Controller，此桩保持向后兼容。
 * 实际功能通过 All.php 中的 success/error/assign/fetch 方法提供。
 */
class Controller
{
    public function __construct()
    {
        if (method_exists($this, 'initialize')) {
            $this->initialize();
        }
    }
}
