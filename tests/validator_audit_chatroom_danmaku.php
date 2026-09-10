<?php
/** Real TP8 Validator/Lang contracts; temporary language data, no site configuration or database. */
declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';
error_reporting(E_ALL);
set_error_handler(static function ($level, $message, $file, $line) {
    if (!(error_reporting() & $level)) { return false; }
    throw new ErrorException($message, 0, $level, $file, $line);
});
$temporary = sys_get_temp_dir() . '/maccms-validator-' . bin2hex(random_bytes(6));
mkdir($temporary, 0700);
$translations = [
    'validate/chatroom_vod_require' => '请选择聊天视频',
    'validate/chatroom_content_require' => '聊天内容不能为空',
    'validate/chatroom_content_max' => '聊天内容过长',
    'validate/danmaku_vod_require' => '请选择弹幕视频',
    'validate/danmaku_text_require' => '弹幕文本不能为空',
    'validate/danmaku_text_max' => '弹幕文本过长',
    ':attribute require' => '字段 :attribute 必填',
];
file_put_contents($temporary . '/audit.json', json_encode($translations, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
$app = new think\App($temporary . '/');
$GLOBALS['validatorAuditLang'] = new think\Lang($app, ['default_lang' => 'audit']);
$GLOBALS['validatorAuditLang']->load($temporary . '/audit.json');
function lang($name) { return $GLOBALS['validatorAuditLang']->get($name); }
$initialized = 0;
think\Validate::maker(static function (think\Validate $validator) use (&$initialized): void {
    $initialized++;
    $validator->setLang($GLOBALS['validatorAuditLang']);
});
$checks = 0;
$check = static function ($condition, string $message) use (&$checks): void {
    if (!$condition) { throw new RuntimeException($message); }
    $checks++;
};
$classes = [
    app\api\validate\Chatroom::class => ['content', ['vod_id' => 1, 'content' => 'hello', 'chat_id' => 7]],
    app\common\validate\Chatroom::class => ['chat_content', ['vod_id' => 1, 'chat_content' => 'hello', 'chat_id' => 7]],
    app\api\validate\Danmaku::class => ['text', ['vod_id' => 1, 'sid' => 1, 'nid' => 1, 'time' => 1.25, 'text' => 'hello', 'danmaku_id' => 7]],
    app\common\validate\Danmaku::class => ['text', ['vod_id' => 1, 'sid' => 1, 'nid' => 1, 'time' => 1.25, 'text' => 'hello', 'danmaku_id' => 7]],
];
try {
    foreach ($classes as $class => [$textField, $valid]) {
        $kind = str_contains($class, 'Chatroom') ? 'chatroom' : 'danmaku';
        $before = $initialized;
        $validator = new $class();
        $check($initialized === $before + 1, $class . ' still runs parent service initialization once');
        $check($validator->check($valid), $class . ' accepts its default valid payload');
        $missing = $valid;
        unset($missing['vod_id']);
        $expected = lang('validate/' . $kind . '_vod_require');
        $check(!$validator->check($missing) && $validator->getError() === $expected,
            $class . ' preserves required fields and translated default messages');
        $tooLong = array_replace($valid, [$textField => str_repeat('x', $kind === 'chatroom' ? 501 : 201)]);
        $expectedMax = lang('validate/' . $kind . ($kind === 'chatroom' ? '_content_max' : '_text_max'));
        $check(!$validator->check($tooLong) && $validator->getError() === $expectedMax,
            $class . ' preserves default text length validation and translation');

        $custom = new $class([$textField => 'require|max:3'], [$textField . '.max' => 'custom length message']);
        $check(!$custom->check($valid) && $custom->getError() === 'custom length message',
            $class . ' explicit rule and message override the corresponding defaults');
        $short = array_replace($valid, [$textField => 'ok']);
        $check($custom->check($short), $class . ' accepts input satisfying the explicit rule');
        unset($short['vod_id']);
        $check(!$custom->check($short) && $custom->getError() === $expected,
            $class . ' overriding one rule/message does not discard unrelated defaults');

        $custom = new $class(['audit_token' => 'require|in:allowed'],
            ['audit_token.in' => 'custom token message'], ['audit_token' => '审计标记']);
        $check(!$custom->check($valid) && $custom->getError() === '字段 审计标记 必填',
            $class . ' explicit field label reaches the real translated Validator error');
        $check(!$custom->check($valid + ['audit_token' => 'denied']) && $custom->getError() === 'custom token message',
            $class . ' added rule rejects an invalid explicit value');
        $check($custom->check($valid + ['audit_token' => 'allowed']), $class . ' added rule accepts a valid explicit value');
        $check(!$custom->check($missing) && $custom->getError() === $expected,
            $class . ' retains default error ordering when adding required fields');

        $custom = new $class([], ['vod_id.require' => 'explicit missing video']);
        $check(!$custom->check($missing) && $custom->getError() === 'explicit missing video',
            $class . ' explicit message works when no custom rules are supplied');
        $fresh = new $class();
        $check($fresh->check($valid), $class . ' constructor overrides do not leak into other instances');

        if (str_contains($class, '\\api\\')) {
            $list = $kind === 'chatroom' ? ['vod_id' => 1] : ['vod_id' => 1, 'sid' => 1, 'nid' => 1];
            $check((new $class())->scene('get_list')->check($list), $class . ' list scene remains limited to its original fields');
            $idField = $kind === 'chatroom' ? 'chat_id' : 'danmaku_id';
            $check((new $class())->scene('report')->check([$idField => 7]), $class . ' report scene remains usable');
            $send = $valid;
            unset($send[$idField]);
            $check((new $class())->scene('send')->check($send), $class . ' send scene does not require the database-assigned ID');
        }
    }
    echo "OK {$checks} Chatroom/Danmaku validator checks on PHP " . PHP_VERSION . "\n";
} finally {
    unlink($temporary . '/audit.json');
    rmdir($temporary);
}
