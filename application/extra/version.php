<?php
return array (
    'name' => '苹果CMS内容管理系统',
    'copyright' => 'MacCMS',
    'url' => '//github.com/magicblack',
    'code' => '2026.1000.4053',
    'license' => '开源版',
    // ⚠ 这是 application/admin/controller/Update.php 的 md5。
    // admin/controller/Base.php 在每次进后台时校验它，不匹配就 exit 整个后台
    // （只放行 Update 控制器本身作为自救入口）。
    // 【改动 Update.php 后必须同步更新这里】，否则全新部署的站点后台会直接锁死。
    // 历史教训：c905031 改了 Update.php 的 curl 超时却漏改本值，导致后台不可用。
    //   校验方式：md5sum application/admin/controller/Update.php
    'update_hash' => '25deef4217de375b471864a2a1b6605a',
);
?>
