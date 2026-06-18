<?php

use think\facade\Route;

// Front-end routes are still served from application/route.php via the
// ThinkPHP5-compatible route loader in application/common/addons/Route.php.
// This file is loaded by TP8 route discovery; it just ensures the pattern
// constraints applied in api.php also apply to the index app.
//
// Full route definitions are in application/route.php (legacy format).
// The Route::import() shim in addons/Route.php handles them at boot time.
