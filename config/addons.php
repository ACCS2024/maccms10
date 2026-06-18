<?php
$_f = __DIR__ . '/../application/extra/addons.php';
return file_exists($_f) ? (include $_f) : [];
