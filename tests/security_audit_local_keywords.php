<?php
require __DIR__ . '/fixtures/security_audit_test_helpers.php';
require dirname(__DIR__) . '/application/common/util/LocalKeywords.php';
require dirname(__DIR__) . '/application/common.php';
error_reporting(E_ALL);
check(mac_get_tag('庆余年 第二季', '<p>张若昀，电视剧，电视剧</p>') === '庆余年,第二季,电视剧,张若昀', 'Chinese title and repeated prose tags changed');
check(mac_get_tag('The Matrix', '<p>matrix Science Fiction and action</p>') === 'Matrix,Science,Fiction,action', 'English stopwords, priority or case deduplication failed');
check(mac_get_tag('安全测试', '<script>tracking payload</script><style>external source</style><p>安全测试</p>') === '安全测试', 'Active HTML leaked into local tags');
check(mac_get_tag('', '') === false && mac_get_tag([], 'content') === false, 'Empty or invalid input contract changed');
check(mac_get_tag('A &amp; B', 'the and 123') === false, 'Noise became a tag');
check(count(explode(',', mac_get_tag('one two three four five six seven', ''))) === 5, 'Tag limit ignored');
echo "Local keyword suggestions: {$checks} assertions passed on PHP " . PHP_VERSION . "\n";
