<?php
require __DIR__ . '/fixtures/security_audit_comment_submission_db.php';
use think\facade\Db;
use app\common\util\JwtService;
$valid = ['comment_mid'=>'1','comment_rid'=>'1','comment_content'=>'A valid comment'];
$forged = ['comment_id'=>1,'user_id'=>2,'comment_name'=>'forged name','comment_status'=>0,
    'comment_time'=>999999999,'comment_ip'=>5,'comment_up'=>200,'comment_down'=>200,'comment_reply'=>200,'comment_report'=>200];
foreach (['index','api'] as $entry) {
    commentSeed();
    $original = commentRows()[0];
    $start = time();
    check(publicComment($entry, $valid + $forged)['code'] === 1, "$entry anonymous comment failed");
    $rows = commentRows(); $created = $rows[1];
    check(count($rows) === 2 && $rows[0] === $original && (int)$created['comment_id'] !== 1,
        "$entry client-selected comment_id edited another user's comment");
    check((int)$created['user_id'] === 0 && (int)$created['comment_status'] === 1
        && (int)$created['comment_time'] >= $start && (int)$created['comment_ip'] === 2130706433,
        "$entry accepted client identity, moderation, time or IP");
    check((int)$created['comment_up'] === 0 && (int)$created['comment_down'] === 0
        && (int)$created['comment_reply'] === 0 && (int)$created['comment_report'] === 0,
        "$entry mass-assigned comment counters");

    commentSeed(); commentLogin();
    check(publicComment($entry, $valid + $forged)['code'] === 1, "$entry authenticated comment failed");
    $created = commentRows()[1];
    check((int)$created['user_id'] === 1 && $created['comment_name'] === 'alice-nickname',
        "$entry ignored the verified identity or trusted client nickname");
    commentSeed();
    $GLOBALS['comment_cookies'] = ['user_id'=>'2','user_name'=>'bob','user_check'=>'forged'];
    check(publicComment($entry, $valid)['code'] === 1 && (int)commentRows()[1]['user_id'] === 0,
        "$entry forged login cookie attributed an anonymous comment to a member");
    foreach ([['user_id'=>'2'], ['user_id'=>['2'],'user_name'=>'bob','user_check'=>'x'],
        ['user_id'=>'999','user_name'=>'ghost','user_check'=>'x']] as $cookies) {
        commentSeed(); $GLOBALS['comment_cookies'] = $cookies;
        check(publicComment($entry, $valid)['code'] === 1 && (int)commentRows()[1]['user_id'] === 0,
            "$entry incomplete, deleted or array cookie crashed or acquired member attribution");
    }
    commentSeed(); commentLogin();
    Db::name('User')->where('user_id',1)->update(['user_status'=>0]);
    check(publicComment($entry,$valid)['code'] === 1 && (int)commentRows()[1]['user_id'] === 0,
        "$entry disabled member retained authenticated attribution");
    commentSeed(); commentLogin();
    $GLOBALS['config']['comment']['login'] = '1';
    check(publicComment($entry, $valid)['code'] === 1 && (int)commentRows()[1]['user_id'] === 1,
        "$entry valid login could not submit when login is required");
    foreach ([[], ['user_id'=>'2','user_name'=>'bob','user_check'=>'forged']] as $cookies) {
        commentSeed(); $GLOBALS['comment_cookies'] = $cookies;
        $GLOBALS['config']['comment']['login'] = '1'; $before = commentRows();
        check(publicComment($entry,$valid)['code'] !== 1 && commentRows() === $before,
            "$entry login-required policy accepted an unauthenticated writer");
    }

    commentSeed();
    $GLOBALS['config']['app']['api_jwt_enabled'] = '1';
    $GLOBALS['config']['app']['api_jwt_secret'] = str_repeat('isolated-fixture-',3);
    $token = JwtService::encode(1, md5('fixture-nonce-1'));
    check(publicComment($entry,$valid + $forged,'POST',[],'Bearer ' . $token)['code'] === 1
        && (int)commentRows()[1]['user_id'] === 1, "$entry valid bearer authentication lost comment ownership");
    $GLOBALS['comment_cookies'] = [];
    Db::name('User')->where('user_id',1)->update(['user_random'=>'revoked-fixture']);
    check(publicComment($entry,$valid,'POST',[],'Bearer ' . $token)['code'] === 1
        && (int)commentRows()[2]['user_id'] === 0, "$entry revoked bearer retained comment ownership");

    commentSeed(); $GLOBALS['config']['comment']['audit'] = '1';
    check(publicComment($entry,$valid + ['comment_status'=>1])['code'] === 1
        && (int)commentRows()[1]['comment_status'] === 0, "$entry bypassed server moderation");
    commentSeed(); $GLOBALS['config']['comment']['status'] = '0'; $before=commentRows();
    check(publicComment($entry,$valid)['code'] !== 1 && commentRows() === $before, "$entry bypassed comment closure");
    commentSeed(); $GLOBALS['config']['comment']['verify'] = '1'; $before=commentRows();
    check(publicComment($entry,$valid + ['verify'=>['x']])['code'] !== 1 && commentRows() === $before,
        "$entry bypassed verification or passed an array to captcha");
    check(publicComment($entry,$valid + ['verify'=>'fixture-valid-captcha'])['code'] === 1,
        "$entry valid verification was rejected");

    foreach (['GET','PUT','DELETE','HEAD'] as $method) {
        commentSeed(); $before=commentRows();
        check(publicComment($entry,$valid,$method)['code'] !== 1 && commentRows() === $before,
            "$entry accepted a non-POST create");
    }
    commentSeed();
    check(publicComment($entry,$valid,'POST',['comment_id'=>1,'user_id'=>2,'comment_status'=>0,'comment_content'=>'query override'])['code'] === 1
        && commentRows()[1]['comment_content'] === $valid['comment_content'], "$entry query parameters overrode the create body");
    foreach ([['comment_mid'=>[1]], ['comment_mid'=>'1e0'], ['comment_rid'=>[1]], ['comment_rid'=>0],
        ['comment_rid'=>'4294967296'], ['comment_pid'=>[1]], ['comment_pid'=>-1], ['comment_content'=>['bad']],
        ['comment_content'=>''], ['comment_content'=>str_repeat('x',256)], ['comment_content'=>"\xff"]] as $bad) {
        commentSeed(); $before=commentRows();
        check(publicComment($entry,array_replace($valid,$bad))['code'] !== 1 && commentRows() === $before,
            "$entry malformed request caused a type error, coercion or mutation");
    }
    foreach ([999,2] as $target) {
        commentSeed(); $before=commentRows();
        check(publicComment($entry,array_replace($valid,['comment_rid'=>$target]))['code'] !== 1 && commentRows() === $before,
            "$entry accepted a missing or unpublished comment target");
    }
    commentSeed();
    check(publicComment($entry,$valid + ['comment_pid'=>1])['code'] === 1,
        "$entry valid same-target reply failed");
    foreach ([999,1] as $pid) {
        commentSeed();
        if ($pid === 1) { Db::name('Comment')->where('comment_id',1)->update(['comment_rid'=>999]); }
        $before = commentRows();
        check(publicComment($entry,$valid + ['comment_pid'=>$pid])['code'] !== 1 && commentRows() === $before,
            "$entry accepted a missing or cross-target parent");
    }
    commentSeed();
    Db::name('Comment')->where('comment_id',1)->update(['comment_status'=>0]); $before = commentRows();
    check(publicComment($entry,$valid + ['comment_pid'=>1])['code'] !== 1 && commentRows() === $before,
        "$entry accepted a reply to an unapproved parent");
    commentSeed(); $GLOBALS['comment_throttled'] = true; $before=commentRows();
    check(publicComment($entry,$valid)['code'] !== 1 && commentRows() === $before, "$entry ignored the existing IP throttle");
    commentSeed(); think\facade\Config::set(['black_keyword_list'=>['valid']], 'blacks'); $before=commentRows();
    check(publicComment($entry,$valid)['code'] !== 1 && commentRows() === $before, "$entry ignored the configured keyword blacklist");
    commentSeed(); think\facade\Config::set(['black_ip_list'=>['127.0.0.1']], 'blacks'); $before=commentRows();
    check(publicComment($entry,$valid)['code'] !== 1 && commentRows() === $before, "$entry ignored the configured IP blacklist");
}
foreach (['vod'=>1,'art'=>2,'topic'=>3,'actor'=>8,'role'=>9,'website'=>11,'manga'=>12] as $alias=>$mid) {
    commentSeed();
    check(publicComment('index',['mid'=>$alias,'rid'=>1,'comment_content'=>'Legacy alias'])['code'] === 1
        && (int)commentRows()[1]['comment_mid'] === $mid, 'Legacy module alias stopped working');
}
commentSeed();
check(publicComment('index',['comment_mid'=>4,'mid'=>1,'rid'=>1,'comment_content'=>'Legacy fallback'])['code'] === 1,
    'Legacy comment-mid fallback stopped working');
foreach (['',0,'0',null] as $empty) {
    commentSeed();
    check(publicComment('index',['comment_mid'=>$empty,'comment_rid'=>$empty,'mid'=>'vod','rid'=>1,
        'comment_pid'=>'','comment_content'=>'Legacy empty canonical fields'])['code'] === 1,
        'Empty canonical module/resource fields stopped falling back to valid legacy aliases');
}
foreach (['comment_mid','comment_rid'] as $field) {
    commentSeed(); $before=commentRows();
    check(publicComment('index',[$field=>[],'mid'=>'vod','rid'=>1,'comment_content'=>'Invalid container'])['code'] !== 1
        && commentRows() === $before, 'Array canonical field was silently replaced by a valid alias');
}
foreach (['index','api'] as $entry) {
    foreach ([1=>'vod',2=>'art',12=>'manga'] as $mid=>$target) {
        commentSeed();
        Db::name($target)->where($target . '_id',1)->update([$target . '_recycle_time'=>time()]);
        $before=commentRows();
        check(publicComment($entry,array_replace($valid,['comment_mid'=>$mid]))['code'] !== 1 && commentRows() === $before,
            "$entry accepted a recycled $target whose publication status remained enabled");
    }
}

commentSeed();
Db::execute($mysql
    ? "CREATE TRIGGER audit_comment_insert_failure BEFORE INSERT ON audit_comment FOR EACH ROW
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'fixture insertion failure'"
    : "CREATE TRIGGER audit_comment_insert_failure BEFORE INSERT ON audit_comment
        BEGIN SELECT RAISE(ABORT, 'fixture insertion failure'); END");
foreach (['index','api'] as $entry) {
    $before=commentRows();
    $result=publicComment($entry,$valid);
    check($result['code'] !== 1 && !str_contains($result['msg'],'fixture') && commentRows() === $before
        && empty($GLOBALS['comment_cookies']['comment_timespan']), "$entry database failure escaped or set a successful submission throttle");
}
Db::execute('DROP TRIGGER audit_comment_insert_failure');
echo "comment submission audit: $checks checks passed on PHP " . PHP_VERSION . ($mysql ? ' / MySQL non-strict' : ' / SQLite') . "\n";
