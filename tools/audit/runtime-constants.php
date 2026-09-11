<?php
/** Static analysis declarations only: scan this file, never bootstrap it or load a site's configuration. */
declare(strict_types=1);
// AppInit computes these per request. dynamicConstantNames prevents the representative values pruning branches.
define('MAC_PATH', '/');
define('MAC_PAGE_SP', '-');
define('MAC_PLAYER_SORT', '0');
define('MAC_MOB', 0);
// All maintained HTTP front controllers initialize this before dispatch.
define('MAC_START_TIME', 0.0);
// User's constructor initializes the OAuth callback before constructing its provider SDK.
define('THIRD_LOGIN_CALLBACK', '');
