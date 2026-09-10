<?php
/** Explicit regression inventory. Each test gets its own process and a bounded runtime. */
declare(strict_types=1);
if (PHP_VERSION_ID < 80300 || PHP_VERSION_ID >= 80500) {
    fwrite(STDERR, "Audit runtime must be PHP 8.3 or 8.4.\n");
    exit(2);
}
$groups = [
    'unit' => [
        ['security_audit_image_processing.php'], ['security_audit_image_upload.php'], ['security_audit_tinymce.php'],
        ['core_audit_helpers.php'], ['core_audit_substring.php'],
        ['extensions_audit_addons.php'], ['extensions_audit_aws.php'], ['extensions_audit_discovery.php'],
        ['extensions_audit_collection.php'], ['extensions_audit_ip_location.php'],
        ['extensions_audit_lifecycle.php'], ['extensions_audit_oauth_sdk.php'],
        ['extensions_audit_qiniu_sdk.php'], ['extensions_audit_qiniu_upload.php'], ['extensions_audit_qiniu_response.php'], ['extensions_audit_qiniu_blocks.php'], ['extensions_audit_qrcode.php'],
        ['extensions_audit_qrcode_http.php'], ['extensions_audit_upyun_blocks.php'], ['extensions_audit_upyun_secure_purge.php'], ['extensions_audit_upyun.php'],
        ['extensions_audit_upyun.php', 'embedded-first'], ['extensions_audit_upload_adapters.php'],
        ['framework_audit_cache_connection.php'], ['framework_audit_cli_failures.php'], ['framework_audit_collection_paging.php'],
        ['framework_audit_csv.php'], ['framework_audit_csv_roundtrip.php'], ['framework_audit_csv_budget.php'], ['framework_audit_bulk_export.php'], ['framework_audit_xlsx_text.php'], ['framework_audit_xlsx_budget.php'], ['framework_audit_request_injection.php'], ['framework_audit_request_method.php'], ['framework_audit_client_ip.php'], ['framework_audit_receive.php'], ['framework_audit_request_security.php'],
        ['framework_audit_api_runtime.php'], ['framework_audit_api_validation.php'],
        ['framework_audit_api_defaults.php'], ['framework_audit_detail_routes.php'],
        ['framework_audit_user_forms.php'], ['framework_audit_auto_registration_views.php'], ['framework_audit_purchase_views.php'], ['framework_audit_user_lists.php'], ['framework_audit_ulog_template.php'], ['security_audit_member_order_url.php'], ['security_audit_order_amount.php'], ['security_audit_order_price_template.php'],
        ['validator_audit_chatroom_danmaku.php'],
        ['framework_audit_strict_errors.php', 'strict'], ['framework_audit_strict_errors.php', 'default'],
        ['security_audit_admin.php'], ['security_audit_annex.php'], ['security_audit_api.php'],
        ['security_audit_bulk_forms.php'], ['security_audit_cj.php'], ['security_audit_crypto.php'],
        ['security_audit_csrf.php'], ['security_audit_config_preservation.php'], ['security_audit_dir.php'], ['security_audit_http.php'],
        ['security_audit_jwt.php'], ['security_audit_logging.php'], ['security_audit_make.php'],
        ['security_audit_oauth.php'], ['security_audit_oauth_profiles.php'], ['security_audit_paths.php'], ['security_audit_safety.php'],
        ['security_audit_sms.php'], ['security_audit_sina.php'], ['security_audit_tls.php'], ['security_audit_urlsend.php'],
        ['security_audit_wechat.php'], ['security_audit_xml.php'],
        ['security_audit_pay_weixin.php'], ['security_audit_pay_alipay.php'],
        ['security_audit_pay_epay.php'], ['security_audit_pay_codepay.php'],
        ['security_audit_pay_zhapay.php'], ['security_audit_pay_jeepay.php'],
        ['ppvod_legacy_compat.php'],
    ],
    // Default: SQLite. FRAMEWORK_AUDIT_MYSQL=1 selects only the dedicated audit database.
    'models' => [
        ['framework_audit_ai_task.php'], ['framework_audit_ai_task.php', 'default-prefix'],
        ['framework_audit_manga_save.php'],
        ['framework_audit_user_registration.php'], ['framework_audit_registration_transactions.php'], ['framework_audit_auto_registration.php'],
        ['framework_audit_user_binding.php'], ['framework_audit_user_messages.php'], ['framework_audit_find_password.php'], ['framework_audit_password_reset.php'], ['framework_audit_password_changes.php'], ['framework_audit_lists.php'], ['framework_audit_collection_nodes.php'],
        ['framework_audit_queries.php'], ['framework_audit_payment.php'],
        ['framework_audit_cash.php'], ['framework_audit_admin_session.php'], ['framework_audit_member_session.php'], ['framework_audit_member_cookie.php'], ['framework_audit_auth_jwt.php'], ['framework_audit_purchase_csrf.php'], ['framework_audit_video_purchase.php'], ['framework_audit_art_purchase.php'], ['framework_audit_manga_purchase.php'],
        ['framework_audit_checkout.php'], ['security_audit_user_log_delete.php'], ['framework_audit_ulog_users.php'], ['framework_audit_ulog_writes.php'], ['framework_audit_ledger_usernames.php'], ['framework_audit_type_navigation.php'], ['framework_audit_vod_home.php'],
    ],
    // Separate environment: MEMBERSHIP_AUDIT_MYSQL selects the financial installation schema.
    'financial' => [['security_audit_task_retention.php'], ['security_audit_visit_retention.php'], ['security_audit_visit_rewards.php'], ['security_audit_visit_redirect.php'], ['security_audit_cash_refund.php'], ['security_audit_membership.php'], ['security_audit_points_overflow.php'], ['security_audit_referral_storage.php'], ['security_audit_content_purchase.php'], ['framework_audit_purchase_owner.php'], ['security_audit_card_credit.php'], ['security_audit_task_rewards.php'], ['security_audit_task_eligibility.php'], ['security_audit_comment_submission.php'], ['framework_audit_gbook_normal.php'], ['security_audit_comment_provenance.php'], ['security_audit_ledger_retention.php'], ['security_audit_order_create.php']],
    // Separate upload schema; both response formats use the same identity guard.
    'upload' => [['security_audit_avatar_consistency.php'], ['security_audit_local_attachment.php'], ['framework_audit_attachment_owner.php'], ['security_audit_upload_identity.php'], ['security_audit_upload_identity.php', 'admin'], ['security_audit_upload_csrf.php'], ['security_audit_upload_csrf.php', 'admin']],
    // Separate storage intent schema; SDK fixtures stay on loopback.
    'storage' => [['security_audit_storage_intents.php'], ['security_audit_storage_sdk.php']],
    // Dedicated remote object and reader fixture; no real cloud credentials.
    'remote_upload' => [['security_audit_remote_upload.php'], ['framework_audit_download_asset.php']],
    // Execute as an unprivileged account so denied-write cases are meaningful.
    'install' => [['framework_audit_install.php']],
];
$selected = ['unit', 'models', 'financial', 'upload', 'storage', 'remote_upload'];
$listOnly = false;
foreach (array_slice($argv, 1) as $arg) {
    if (str_starts_with($arg, '--suite=')) {
        $value = substr($arg, 8);
        $selected = $value === 'all' ? array_keys($groups) : explode(',', $value);
    } elseif ($arg === '--list') {
        $listOnly = true;
    } else {
        fwrite(STDERR, "Unknown option: {$arg}\n"); exit(2);
    }
}
$commands = [];
foreach (array_unique($selected) as $suite) {
    if (!isset($groups[$suite])) { fwrite(STDERR, "Unknown suite: {$suite}\n"); exit(2); }
    foreach ($groups[$suite] as $args) {
        $file = __DIR__ . '/' . array_shift($args);
        if (!is_file($file)) { fwrite(STDERR, "Missing regression: {$file}\n"); exit(2); }
        $commands[] = [PHP_BINARY, '-d', 'error_reporting=-1', '-d', 'display_errors=1', $file, ...$args];
    }
}
if ($commands === []) { fwrite(STDERR, "No regression tests selected.\n"); exit(2); }
if ($listOnly) { echo json_encode($commands, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"; exit(0); }
if (in_array('install', $selected, true) && function_exists('posix_geteuid') && posix_geteuid() === 0) {
    fwrite(STDERR, "Installer permission regressions must run as an unprivileged user.\n"); exit(2);
}
$failures = 0;
foreach ($commands as $command) {
    $process = proc_open($command, [0 => ['file', '/dev/null', 'r'], 1 => STDOUT, 2 => STDERR], $pipes, dirname(__DIR__));
    if (!is_resource($process)) { fwrite(STDERR, "Cannot start regression process.\n"); exit(2); }
    $deadline = microtime(true) + 180;
    do {
        $state = proc_get_status($process);
        if (!$state['running']) { break; }
        usleep(20000);
    } while (microtime(true) < $deadline);
    if ($state['running']) {
        proc_terminate($process, 9);
        $status = 124;
    } else {
        $status = $state['exitcode'];
    }
    $closed = proc_close($process);
    if ($status < 0) { $status = $closed >= 0 ? $closed : 255; }
    if ($status !== 0) {
        ++$failures;
        fwrite(STDERR, 'FAIL ' . basename($command[5]) . ' (exit ' . $status . ")\n");
    }
}
printf("Audit: %d processes, %d failures on PHP %s.\n", count($commands), $failures, PHP_VERSION);
exit($failures === 0 ? 0 : 1);
