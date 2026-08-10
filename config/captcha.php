<?php
// 验证码配置：沿用 maccms 的 application/extra/captcha.php。
// 这个加载器在 TP8 迁移时漏建，导致 think-captcha 只用自己的默认值，
// 站点在后台改的验证码位数/字符集/干扰线等设置全部不生效。
$_f = __DIR__ . '/../application/extra/captcha.php';
return file_exists($_f) ? (include $_f) : [];
