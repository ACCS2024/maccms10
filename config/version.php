<?php
$_f = __DIR__ . '/../application/extra/version.php';
return file_exists($_f) ? (include $_f) : [];
