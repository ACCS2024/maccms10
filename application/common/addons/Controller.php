<?php
namespace think;

/**
 * TP8 迁移 Shim：TP8 framework 不含 think\Controller，此桩保持向后兼容。
 *
 * 剩余依赖（All.php / Verify.php / Qrcode.php 已完成去 shim）：
 *   - application/install/controller/Index.php — 仍需单独 PR 处理，
 *     该文件还用了 $this->validate()、$this->request 等 TP5 特有 API，
 *     需整体重写安装控制器后才能删除此 shim。
 *
 * TODO: 在 install/controller/Index.php 完成 TP8 重写后删除此文件。
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
