<?php
/** Same isolated database/barrier contract as R2, with a local portrait value for post-commit cookies. */
function mac_get_user_portrait($uid) { return '/fixture-portrait.png'; }
require __DIR__.'/framework_audit_registration_worker.php';
