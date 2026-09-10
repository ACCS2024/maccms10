<?php
/** Independent connection for normal simultaneous fixture submissions; uses only the dedicated audit DB. */
declare(strict_types=1);
namespace app\common\model {
    function captcha_check($value) { return $value === 'fixture-captcha'; }
    class Group { public function getCache(...$args) { return [2=>['group_id'=>2,'group_name'=>'Member','group_type'=>'']]; } }
}
namespace {
    if (getenv('FRAMEWORK_AUDIT_MYSQL') !== '1') { throw new \RuntimeException('Concurrency worker requires the isolated MySQL fixture'); }
    define('REGISTRATION_FIXTURE_EXISTING_DB', true);
    require __DIR__.'/framework_audit_user_registration.php';
    function cookie($name, ...$args) { return null; }
    $job = json_decode(base64_decode($argv[1]), true, 32, JSON_THROW_ON_ERROR);
    registrationFixtureConfig($job['configuration']);
    foreach ($job['configuration'] as $key=>$expected) {
        if ((config('maccms')['user'][$key] ?? null) !== $expected) { throw new \RuntimeException('Concurrent worker configuration differs from its scenario'); }
    }
    $GLOBALS['registration_fixture_throttle'] = true;
    $GLOBALS['registration_fixture_hash_failure'] = false;
    $GLOBALS['registration_fixture_ip'] = $job['ip'] ?? '2130706433';
    $GLOBALS['user'] = ['user_id'=>0,'user_name'=>''];
    if ($job['action'] === 'bind') {
        $account = \think\facade\Db::name('User')->where('user_id',400)->find();
        $token = \app\common\util\JwtService::encode(400, $account['user_random']);
        $app->instance('request', (new \think\Request())->withHeader(['authorization'=>'Bearer '.$token]));
    }
    file_put_contents($argv[2].'/ready-'.$job['slot'], 'ready');
    $deadline = microtime(true) + 20;
    while (!is_file($argv[2].'/go')) {
        if (microtime(true) > $deadline) { throw new \RuntimeException('Fixture start barrier timed out'); }
        usleep(10000);
    }
    $model = new \app\common\model\User();
    $result = $model->{$job['action']}($job['param']);
    fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR)."\n");
}
