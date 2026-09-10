<?php
/** Fixed remote fixtures, real HTML/RSS extraction, no outbound requests or application bootstrap. */
declare(strict_types=1);
namespace app\common\util {
    function mac_curl_get($url) {
        $GLOBALS['collection_audit_requests'][] = $url;
        return $GLOBALS['collection_audit_pages'][$url] ?? false;
    }
}
namespace {
    require dirname(__DIR__) . '/vendor/autoload.php';
    require dirname(__DIR__) . '/application/common.php';
    error_reporting(E_ALL);
    set_error_handler(static function ($level, $message, $file, $line) {
        if (!(error_reporting() & $level)) { return false; }
        throw new \ErrorException($message, 0, $level, $file, $line);
    });
    use app\common\util\Collection;
    $checks = 0;
    $check = static function ($condition, string $message) use (&$checks): void {
        if (!$condition) { throw new \RuntimeException($message); }
        $checks++;
    };
    $origin = 'https://fixture.invalid:8443';
    $base = $origin . '/articles/one.html';
    $GLOBALS['collection_audit_requests'] = [];
    $GLOBALS['collection_audit_pages'] = [$base => '<title>第一篇</title><article>Hello <b>world</b><img src="../pic.jpg"></article>'];
    $config = ['title_rule' => '<title>[内容]</title>', 'type_rule' => '新闻',
        'content_rule' => '<article>[内容]</article>', 'content_html_rule' => '<b>(.*)</b>[|]$1',
        'customize_config' => json_encode([['en_name' => 'author', 'rule' => '固定作者', 'html_rule' => '']])];
    $snapshot = $config;
    $result = Collection::get_content($base, $config);
    $check($result['title'] === '第一篇' && $result['type'] === '新闻' && $result['author'] === '固定作者', 'Configured title, type and custom fields survive');
    $check($result['content'] === 'Hello world<img src="' . $origin . '/pic.jpg">', 'Filtering and relative image resolution use the real namespaced callback');
    $check(is_int($result['time']) && $config === $snapshot, 'Call does not mutate caller config or JSON custom fields');
    $check(Collection::get_content($base, [])['content'] === '', 'Missing optional rules are warning-free');
    foreach ([['content_rule' => []], ['customize_config' => '{broken'], ['customize_config' => [['rule' => []]]], ['content_rule' => 'a[内容]b[内容]c']] as $bad) {
        $check(Collection::get_content($base, $bad) === false, 'Malformed configured rule/custom field fails in a controlled way');
    }
    $check(Collection::get_content('https://fixture.invalid/missing', $config) === false, 'Remote failure propagates');
    $check(Collection::get_content($base, ['content_rule' => '<missing>[内容]</missing>']) === false, 'Missing extraction markers are a parse failure');
    $check(Collection::get_content($base, $config + ['sourcecharset' => 'NO_SUCH_CHARSET']) === false, 'Unsupported charset does not emit a warning or accept unreadable data');
    $badFilter = array_replace($config, ['content_html_rule' => '([|]x']);
    $check(Collection::get_content($base, $badFilter) === false, 'Invalid regular expression fails rather than becoming null content');
    $badFilter['content_html_rule'] = 'missing replacement separator';
    $check(Collection::get_content($base, $badFilter) === false, 'Malformed filter has a controlled failure');
    $GLOBALS['collection_audit_pages'][$base] = iconv('UTF-8', 'GBK', '<title>中文标题</title><article>正文</article>');
    $result = Collection::get_content($base, array_replace($config, ['sourcecharset' => 'GBK']));
    $check($result['title'] === '中文标题' && $result['content'] === '正文', 'GBK source text converts to UTF-8');

    $GLOBALS['collection_audit_pages'][$base] = '<article><img src=../icons.svg#mark><img src=\'//cdn.invalid/p.png\'></article>';
    $result = Collection::get_content($base, ['content_rule' => '<article>[内容]</article>']);
    $check($result['content'] === '<img src="' . $origin . '/icons.svg#mark"><img src="https://cdn.invalid/p.png">', 'Unquoted/single-quoted images preserve SVG fragments and resolve protocol-relative URLs');

    $paging = ['content_rule' => '<article>[内容]</article>', 'content_page_start' => '<nav>', 'content_page_end' => '</nav>',
        'content_page_rule' => '2', 'content_nextpage' => '下一页', 'content_page' => '1',
        'customize_config' => json_encode([['en_name' => 'author', 'rule' => '作者']])];
    $second = $origin . '/chapter/two.html';
    $GLOBALS['collection_audit_pages'] = [
        $base => '<article>one<img src="a.jpg"></article><nav><a href="../chapter/two.html"><b>下一页</b></a></nav>',
        $second => '<article>two<img src="b.jpg"></article><nav><a href="../articles/one.html#again">下一页</a></nav>',
    ];
    $expected = 'one<img src="' . $origin . '/articles/a.jpg">[page]two<img src="' . $origin . '/chapter/b.jpg">';
    $GLOBALS['collection_audit_requests'] = [];
    $check(Collection::get_content($base, $paging)['content'] === $expected, 'Next-page mode resolves each page image relative to its own URL');
    $check(count($GLOBALS['collection_audit_requests']) === 2, 'Cyclic next-page links fetch each normalized page once');
    $check(Collection::get_content($base, $paging)['content'] === $expected, 'Consecutive collections do not inherit earlier visited URLs');
    $paging['content_page_rule'] = '1';
    $GLOBALS['collection_audit_pages'][$base] = '<article>one</article><nav><a href="#">self</a><a href="../chapter/two.html">2</a><a href="../chapter/two.html#same">duplicate</a></nav>';
    $GLOBALS['collection_audit_requests'] = [];
    $check(Collection::get_content($base, $paging)['content'] === 'one[page]two<img src="' . $origin . '/chapter/b.jpg">', 'All-page mode iterates the correct href without false string offsets');
    $check(count($GLOBALS['collection_audit_requests']) === 2, 'All-page mode ignores fragments and duplicate pages');
    unset($GLOBALS['collection_audit_pages'][$second]);
    $check(Collection::get_content($base, $paging) === false, 'A failed required child page never returns partial successful content');
    $paging['content_page_rule'] = '2';
    $GLOBALS['collection_audit_pages'] = [];
    for ($i = 0; $i < 101; $i++) {
        $GLOBALS['collection_audit_pages'][$origin . '/' . $i] = '<article>' . $i . '</article><nav><a href="/' . ($i + 1) . '">下一页</a></nav>';
    }
    $GLOBALS['collection_audit_requests'] = [];
    $check(Collection::get_content($origin . '/0', $paging) === false && count($GLOBALS['collection_audit_requests']) === 100,
        'Unbounded remote pagination stops at a finite budget without claiming partial success');

    $sequence = ['sourcetype' => '1', 'urlpage' => $origin . '/(*)', 'pagesize_start' => '2', 'pagesize_end' => '8', 'par_num' => '3'];
    $check(Collection::url_list($sequence) === [$origin . '/2', $origin . '/5', $origin . '/8'], 'Inclusive stepped URL sequence');
    $check(Collection::url_list($sequence, 5) === [$origin . '/2', $origin . '/5'], 'Optional sequence limit is honored');
    foreach (['0', '-1', 'invalid', []] as $step) {
        $bad = array_replace($sequence, ['par_num' => $step]);
        $check(Collection::url_list($bad) === [], 'Invalid/zero/negative step cannot create an infinite loop');
    }
    $bad = array_replace($sequence, ['pagesize_end' => PHP_INT_MAX, 'par_num' => '1']);
    $check(Collection::url_list($bad) === [], 'Huge range fails before allocation/overflow');
    $bad = array_replace($sequence, ['pagesize_start' => PHP_INT_MAX - 1, 'pagesize_end' => PHP_INT_MAX, 'par_num' => 1]);
    $check(count(Collection::url_list($bad)) === 2, 'Maximum integer range terminates without overflowing the loop counter');
    $multi = ['sourcetype' => 2, 'urlpage' => " a\nb\r\nc\r\n \r d "];
    $check(Collection::url_list($multi) === ['a', 'b', 'c', 'd'], 'All line endings and empty lines in multi-URL input');
    foreach ([3, 4] as $kind) {
        $single = ['sourcetype' => $kind, 'urlpage' => $base];
        $check(Collection::url_list($single) === [$base], 'Single-page and RSS source list contracts');
    }

    $list = ['sourcetype' => 3, 'url_start' => '<main>', 'url_end' => '</main>'];
    $GLOBALS['collection_audit_pages'] = [$base => '<main><a class="x" href="../a?x=1&amp;y=2"><b>A</b> &amp; B</a><a href=//cdn.invalid/two>2</a><a href="?p=2">query</a><a href="javascript:bad()">bad</a><a data-href="/wrong">wrong</a></main>'];
    $urls = Collection::get_url_lists($base, $list);
    $check($urls === [
        ['url' => $origin . '/a?x=1&y=2', 'title' => 'A & B'],
        ['url' => 'https://cdn.invalid/two', 'title' => '2'],
        ['url' => $base . '?p=2', 'title' => 'query'],
    ], 'Anchor attributes, nested labels, numeric titles, entities, port, relative and protocol-relative URLs');
    $filtered = $list + ['url_contain' => 'two', 'url_except' => 'nothing'];
    $check(Collection::get_url_lists($base, $filtered) === [$urls[1]], 'Contain/exclude filters retain URL records');
    $list['url_start'] = '<absent>';
    $check(Collection::get_url_lists($base, $list) === false, 'Failed list extraction is distinguishable from an empty list');
    $list = ['sourcetype' => 3];
    $GLOBALS['collection_audit_pages'][$base] = '<p>empty</p>';
    $check(Collection::get_url_lists($base, $list) === [], 'A valid page with no anchors returns an empty list');
    unset($GLOBALS['collection_audit_pages'][$base]);
    $check(Collection::get_url_lists($base, $list) === false, 'List transport failure remains false for the controller');

    $rss = ['sourcetype' => 4];
    $GLOBALS['collection_audit_pages'][$base] = '<?xml version="1.0"?><rss version="2.0"><channel><title>Feed</title><item><title><![CDATA[新闻 & 更新]]></title><link>../item?id=1&amp;x=2</link></item></channel></rss>';
    $check(Collection::get_url_lists($base, $rss) === [['url' => $origin . '/item?id=1&x=2', 'title' => '新闻 & 更新']], 'Single RSS item and CDATA use the actual safe XML helper, without pc_base');
    $GLOBALS['collection_audit_pages'][$base] = '<rss><channel><title>Feed</title><item><title>A</title><link>/1</link></item><item><title>B</title><link>/2</link></item></channel></rss>';
    $check(count(Collection::get_url_lists($base, $rss)) === 2, 'Multiple RSS items');
    $GLOBALS['collection_audit_pages'][$base] = '<rss><channel><title>Feed</title></channel></rss>';
    $check(Collection::get_url_lists($base, $rss) === [], 'Valid empty RSS feed');
    foreach (['<rss>', '<html/>', '<!DOCTYPE rss [<!ENTITY secret SYSTEM "file:///etc/passwd">]><rss><channel><title>&secret;</title></channel></rss>'] as $xml) {
        $GLOBALS['collection_audit_pages'][$base] = $xml;
        $check(Collection::get_url_lists($base, $rss) === false, 'Malformed/non-RSS/DTD XML fails without external entities');
    }
    echo "OK {$checks} Collection checks on PHP " . PHP_VERSION . "\n";
}
