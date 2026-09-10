<?php
/** Message parameter/lifecycle checks with normal fixture recipients and real isolated ORM. */
declare(strict_types=1);
require __DIR__ . '/fixtures/framework_audit_user_messages.php';
$model = new \app\common\model\User();

foreach (['email'=>'fixture@example.invalid', 'phone'=>'13000000000'] as $channel=>$target) {
    foreach ([1, 2, 3] as $type) {
        messageFixtureSeed();
        \think\facade\Db::name('Msg')->insert(messageFixtureRow(['msg_to'=>$target, 'msg_type'=>$type]));
        $before = messageFixtureState();
        $res = $model->check_msg(messageFixtureParam(['ac'=>$channel, 'to'=>$target, 'type'=>$type]));
        check($res['code'] === 1 && messageFixtureState() === $before,
            'A matching unconsumed fixture message must validate without being consumed');
    }
}
foreach ([['msg_to'=>'another-fixture@example.invalid'], ['msg_type'=>1], ['msg_status'=>1],
    ['msg_time'=>time()-601], ['msg_time'=>time()+601], ['user_id'=>1], ['msg_code'=>'654321']] as $changedField) {
    messageFixtureSeed();
    \think\facade\Db::name('Msg')->insert(messageFixtureRow($changedField));
    $before = messageFixtureState();
    $res = $model->check_msg(messageFixtureParam());
    check($res['code'] > 1 && messageFixtureState() === $before,
        'An unrelated, expired or consumed message must not satisfy the supplied verification form');
}
messageFixtureSeed();
\think\facade\Db::name('Msg')->insert(messageFixtureRow(['msg_to'=>'fixture+tag@example.invalid']));
check($model->check_msg(messageFixtureParam(['to'=>' fixture+tag@example.invalid ']))['code'] === 1,
    'Recipient normalization must preserve a literal plus in email addresses');
messageFixtureSeed();
\think\facade\Db::name('Msg')->insert(messageFixtureRow());
check($model->check_msg(messageFixtureParam(['type'=>'2']))['code'] === 1,
    'Ordinary HTTP string purpose values must remain accepted');
foreach (['12345', '1234567', 'letters'] as $code) {
    check($model->check_msg(messageFixtureParam(['code'=>$code]))['code'] > 1,
        'Mistyped verification codes must be rejected before lookup');
}
foreach (['check_msg', 'send_msg'] as $method) {
    $before = messageFixtureState();
    check($model->$method(messageFixtureParam(['to'=>str_repeat('a', 31).'@example.invalid']))['code'] > 1
        && messageFixtureState() === $before, 'Message recipients must fit the persisted destination field');
}
foreach (['check_msg', 'send_msg'] as $method) {
    foreach ([[], ['ac'=>'email'], ['ac'=>'phone'], ['ac'=>'email', 'to'=>'mistyped-address'],
        ['ac'=>'phone', 'to'=>'123'], messageFixtureParam(['type'=>0]), messageFixtureParam(['type'=>4]),
        messageFixtureParam(['ac'=>'other'])] as $invalid) {
        messageFixtureSeed();
        $before = messageFixtureState();
        $res = $model->$method($invalid);
        check(is_array($res) && ($res['code'] ?? 1) > 1 && messageFixtureState() === $before
            && $GLOBALS['message_fixture_deliveries'] === [], 'Incomplete message fields must be controlled');
    }
    foreach ($method === 'check_msg' ? ['ac', 'to', 'type', 'code'] : ['ac', 'to', 'type'] as $field) {
        foreach ([[], ['ordinary-field'], null, true, 1.5] as $invalid) {
            messageFixtureSeed();
            $before = messageFixtureState();
            $res = $model->$method(messageFixtureParam([$field=>$invalid]));
            check(is_array($res) && ($res['code'] ?? 1) > 1 && messageFixtureState() === $before
                && $GLOBALS['message_fixture_deliveries'] === [], $method.' must reject non-text '.$field);
        }
    }
}
foreach (['email'=>'fixture@example.invalid', 'phone'=>'13000000000'] as $channel=>$target) {
    foreach ([1, 2, 3] as $type) {
        messageFixtureSeed();
        $res = $model->send_msg(['ac'=>$channel, 'to'=>$target, 'type'=>$type]);
        $row = \think\facade\Db::name('Msg')->where('user_id', 0)->find();
        check($res['code'] === 1 && $row && $row['msg_to'] === $target && (int)$row['msg_type'] === $type
            && (int)$row['msg_status'] === 0 && preg_match('/^[0-9]{6}$/D', $row['msg_code']) === 1
            && $GLOBALS['message_fixture_deliveries'] === [[$channel, $target]],
            'A valid message form without code must create a matching record after isolated delivery');
        $before = messageFixtureState();
        $res = $model->send_msg(['ac'=>$channel, 'to'=>$target, 'type'=>$type]);
        check($res['code'] > 1 && messageFixtureState() === $before && count($GLOBALS['message_fixture_deliveries']) === 1,
            'Resend timing must continue preventing immediate duplicates');
    }
}
foreach (['email_white_hosts', 'email_black_hosts'] as $key) {
    messageFixtureSeed();
    $GLOBALS['config']['user'][$key] = ['ordinary-config-value'];
    check($model->send_msg(messageFixtureParam(['type'=>3]))['code'] > 1 && $GLOBALS['message_fixture_deliveries'] === [],
        'Mistyped email host configuration must fail without delivery');
}
messageFixtureSeed();
$GLOBALS['config']['user']['email_white_hosts'] = 'EXAMPLE.INVALID';
check($model->send_msg(messageFixtureParam(['type'=>3]))['code'] === 1,
    'Email host allowlists must compare case-insensitively');
messageFixtureSeed();
$GLOBALS['config']['user']['email_black_hosts'] = 'EXAMPLE.INVALID';
check($model->send_msg(messageFixtureParam(['type'=>3]))['code'] > 1 && $GLOBALS['message_fixture_deliveries'] === [],
    'Email host denylists must compare case-insensitively');
messageFixtureSeed();
$GLOBALS['config']['email']['tpl']['user_findpass_body'] = '<p>'.str_repeat('普通邮件内容', 100).'</p>';
check($model->send_msg(messageFixtureParam())['code'] === 1
    && mb_strlen((string)\think\facade\Db::name('Msg')->where('user_id', 0)->value('msg_content'), 'UTF-8') === 255,
    'Long legitimate HTML email templates must fit the message audit column');
messageFixtureSeed();
$GLOBALS['message_fixture_throttle'] = false;
check($model->send_msg(messageFixtureParam())['code'] > 1 && $GLOBALS['message_fixture_deliveries'] === [],
    'Existing send throttle must remain effective');
foreach ([null, [], ['code'=>0, 'msg'=>'Fixture unavailable'], new RuntimeException('Fixture service unavailable')] as $failure) {
    messageFixtureSeed();
    $GLOBALS['message_fixture_delivery'] = $failure;
    $res = $model->send_msg(messageFixtureParam());
    check(is_array($res) && ($res['code'] ?? 1) > 1 && \think\facade\Db::name('Msg')->count() === 0,
        'A malformed, failed or throwing delivery service must not produce a successful message record');
}
messageFixtureSeed();
\think\facade\Db::execute("CREATE TRIGGER audit_message_insert_failure BEFORE INSERT ON audit_msg BEGIN SELECT RAISE(ABORT, 'Fixture database write failure'); END");
try {
    $res = $model->send_msg(messageFixtureParam());
    check(is_array($res) && ($res['code'] ?? 1) > 1 && \think\facade\Db::name('Msg')->count() === 0,
        'A real database write failure after fixture delivery must return a controlled failure');
} finally {
    \think\facade\Db::execute('DROP TRIGGER audit_message_insert_failure');
}
echo 'framework_audit_user_messages: '.$checks.' checks passed on PHP '.PHP_VERSION.PHP_EOL;
