<?php
/** Visit evidence is append-only for member rewards and website referral quotas. */
declare(strict_types=1);
require __DIR__.'/fixtures/security_audit_visit_db.php';
require __DIR__.'/fixtures/security_audit_reward_retention_admin.php';
use think\facade\Db;

visitSeed();
check(visitCall()['code'] === 1 && memberRow()['user_points'] === 120
    && Db::name('Plog')->count() === 1 && Db::name('Visit')->count() === 1, 'The original rewarded visit did not commit');
$model = new app\common\model\Visit();
$row = Db::name('Visit')->order('visit_id')->find();
$before = visitState();
foreach ([['visit_id'=>$row['visit_id']], [['visit_id', 'in', [$row['visit_id']]]], [['visit_id', '>', 0]],
    ['user_id'=>1], [], true, null, 'invalid'] as $where) {
    check($model->delData($where)['code'] === 1005 && visitState() === $before, 'Visit deletion changed quota or financial evidence');
}
foreach (['visit_id', 'user_id', 'visit_ip', 'visit_time', 'visit_ly', 'VISIT_TIME', '', null, []] as $field) {
    check($model->fieldData(['visit_id'=>$row['visit_id']], $field, 0)['code'] === 1005
        && visitState() === $before, 'Visit field update changed original evidence');
}
foreach (['visit_id', 'VISIT_ID', 'Visit_Id'] as $key) {
    foreach ([$row['visit_id'], 0, '', null, []] as $id) {
        $data = ['user_id'=>2, 'visit_ip'=>1, 'visit_time'=>1, 'visit_ly'=>'changed', $key=>$id];
        check($model->saveData($data)['code'] === 1005 && visitState() === $before,
            'An explicit Visit primary key updated evidence or created a replacement');
    }
}
foreach (['GET', 'POST'] as $method) {
    foreach ([[], ['ids'=>(string)$row['visit_id']], ['ids'=>'1', 'all'=>'1'], ['all'=>'1'], ['ids'=>[], 'all'=>[]]] as $parameters) {
        $result = retentionAdmin('Visit', 'del', $parameters, $method);
        check($result['code'] === 0 && str_contains($result['msg'], '网站引荐') && visitState() === $before,
            'Admin '.$method.' visit deletion changed original evidence');
    }
}
check(visitCall()['code'] === 102 && visitState() === $before, 'Deleting/editing visits reopened a paid daily quota');

// Both valid member and website inserts remain available, with a server-owned timestamp.
foreach ([0, 1] as $userId) {
    $time = time();
    check($model->saveData(['user_id'=>$userId, 'visit_ip'=>2130706434, 'visit_time'=>1, 'visit_ly'=>'new referral'])['code'] === 1,
        'Normal append failed for beneficiary '.$userId);
    $new = Db::name('Visit')->order('visit_id desc')->find();
    check((int)$new['user_id'] === $userId && (int)$new['visit_time'] >= $time && $new['visit_ly'] === 'new referral',
        'Append lost its source or trusted a caller-supplied date');
    check(membershipState() === $before[0], 'Appending evidence alone unexpectedly moved money');
}
foreach ([null, false, 'invalid', [], ['visit_ip'=>1], ['user_id'=>0], ['user_id'=>0, 'visit_ip'=>[]]] as $data) {
    $state = visitState();
    check($model->saveData($data)['code'] !== 1 && visitState() === $state, 'Malformed append changed records');
}
Db::execute($mysql
    ? "CREATE TRIGGER retention_visit_fail BEFORE INSERT ON audit_visit FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture failure'"
    : "CREATE TRIGGER retention_visit_fail BEFORE INSERT ON audit_visit BEGIN SELECT RAISE(FAIL,'fixture failure'); END");
$state = visitState();
check($model->saveData(['user_id'=>0, 'visit_ip'=>1, 'visit_ly'=>'failure'])['code'] === 1002
    && visitState() === $state, 'An append database failure escaped or left evidence behind');
Db::execute('DROP TRIGGER retention_visit_fail');

// user_id=0 is an existing website referral policy, not an unowned row safe to purge.
visitSeed();
$GLOBALS['config']['website'] = ['refer_visit_num'=>1];
$website = (new ReflectionClass(app\common\model\Website::class))->newInstanceWithoutConstructor();
check($website->visit(['url'=>'https://website.fixture/ref?a=1&b=2'])['code'] === 1 && Db::name('Visit')->count() === 1,
    'The real website referral path lost normal append support');
$state = visitState();
check($model->delData(['user_id'=>0])['code'] === 1005 && visitState() === $state,
    'Website referral evidence was silently excluded from retention');
check($website->visit(['url'=>'https://website.fixture/ref?a=1&b=2'])['code'] === 102 && visitState() === $state,
    'Website deletion reopened its daily referral quota');

// The actual nonempty admin page resolves only usernames, including missing/deleted owners.
Db::name('User')->where('user_id', 1)->update(['user_name'=>'<b>member</b>']);
foreach ([1, 999999] as $id) {
    check($model->saveData(['user_id'=>$id, 'visit_ip'=>2, 'visit_ly'=>'<script>retained</script>'])['code'] === 1,
        'The nonempty list fixture could not append');
}
$state = visitState();
$page = retentionAdmin('Visit', 'index');
check(count($page['data']['list']) === 3 && (int)$page['data']['total'] === 3, 'Real admin query lost retained rows');
$byOwner = array_column($page['data']['list'], null, 'user_id');
check($byOwner[1]['user_name'] === '<b>member</b>' && $byOwner[0]['user_name'] === '' && $byOwner[999999]['user_name'] === '',
    'Usernames are missing, mismatched, or fail for deleted/website owners');
check($byOwner[0]['visit_mid'] === 11 && $byOwner[1]['visit_mid'] === 6 && $byOwner[999999]['visit_mid'] === 6,
    'The page changed the meaning of website/member rows');
$keys = array_keys($byOwner[1]);
sort($keys);
check($keys === ['user_id', 'user_name', 'visit_id', 'visit_ip', 'visit_ly', 'visit_mid', 'visit_time'],
    'Username lookup exposed unrelated private user fields');
$html = retentionRender($page);
retentionReadOnlyPage($html, 'Visit');
check(str_contains($html, '&lt;b&gt;member&lt;/b&gt;') && str_contains($html, '&lt;script&gt;retained&lt;/script&gt;')
    && !str_contains($html, '<b>member</b>') && !str_contains($html, '<script>retained</script>'),
    'Nonempty Visit template failed to escape retained names or referers');
check(str_contains($html, '[999999]') && str_contains($html, 'website') && visitState() === $state,
    'Read-only rendering failed for deleted owners or mutated financial records');
check(str_contains($html, 'https://website.fixture/ref?a=1&amp;b=2') && !str_contains($html, '&amp;amp;'),
    'Already escaped referral URLs were encoded twice');
$selected = $model->listData(['user_id'=>1], 'visit_id desc', 1, 1);
check($selected['total'] === 1 && count($selected['list']) === 1 && $selected['list'][0]['user_name'] === '<b>member</b>',
    'Visit username mapping changed owner filtering or pagination');
$projected = $model->listData([], 'visit_id desc', 1, 1, 0, 'visit_id');
check(count($projected['list']) === 1 && $projected['list'][0]['user_name'] === '', 'Custom field projections triggered a missing owner warning');

echo 'Visit retention: '.$checks.' checks passed on PHP '.PHP_VERSION.' ('.($mysql ? 'MySQL' : 'SQLite').")\n";
