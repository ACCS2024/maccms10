<?php

namespace app\common\util;

/**
 * Meilisearch：索引维护与搜索。
 */
class MeilisearchService
{
    /** @var array<string, array{ok:bool,hits:array,estimatedTotalHits:int}> 单次请求内相同参数去重，避免列表与 AI 联想等对 Meili 重复打网 */
    private static $searchMemo = [];

    /** 历史共享默认索引名。多个 maccms 共用同一 Meilisearch 且都用此名会串库（主键 vod_<id> 全局，互相覆盖）。 */
    const LEGACY_SHARED_UID = 'maccms_contents';

    public static function cfg()
    {
        // AppInit sets the global during HTTP requests. Console maintenance commands
        // have no middleware phase, so read the already-loaded config directly there.
        $c = $GLOBALS['config']['meilisearch'] ?? config('maccms.meilisearch', []);
        return is_array($c) ? $c : [];
    }

    public static function enabled()
    {
        $c = self::cfg();
        return !empty($c['enabled']) && (string)$c['enabled'] === '1'
            && !empty($c['host'])
            && self::indexUid() !== '';
    }

    public static function host()
    {
        return rtrim((string)(self::cfg()['host'] ?? ''), '/');
    }

    /**
     * 本站唯一的默认索引名，按数据库连接派生（库名为主 + host/端口/前缀短哈希兜底），
     * 保证多个 maccms 共用同一 Meilisearch 时各自独立 index、绝不串库。
     * 即便两台不同 MySQL 都叫同名库，host/端口/前缀的哈希也会区分开。
     */
    public static function defaultIndexUid()
    {
        // 这三个键在 TP8 只存在于 database.connections.<name> 之下,扁平路径
        // config('database.database') 等一律解析为 null。原写法让 $db/$host/$port
        // 全部退化成 '',于是 name 落到 'site' 兜底、hash 收敛成 md5('||mac_|'),
        // 每个用默认 mac_ 前缀的 maccms 装机都得到【同一个】maccms_site_<常量>,
        // 上面那句「绝不串库」的承诺被完全打穿。
        $conn   = \think\facade\Db::connect();
        $db     = (string)$conn->getConfig('database');
        $host   = (string)$conn->getConfig('hostname');
        $port   = (string)$conn->getConfig('hostport');
        $prefix = (string)$conn->getConfig('prefix');
        // 库名解析不出来时【拒绝派生】:派生名必然与其它站点相撞并互相覆盖,
        // 而这个返回值会被 admin/controller/Meilisearch 回填进站点配置、驱动整库重建。
        // 返回空串而不是抛异常 —— indexUid() 会把空串一路带到 enabled(),
        // Meili 自动判为未启用、回落 MySQL;抛异常则会打穿前台搜索(enabled() 在热路径上)。
        if ($db === '') {
            return '';
        }
        // Meili 索引名仅允许 [A-Za-z0-9_-]
        $name = preg_replace('/[^A-Za-z0-9_-]/', '_', $db);
        $name = trim((string)$name, '_');
        if ($name === '') {
            $name = 'site';
        }
        if (strlen($name) > 40) {
            $name = substr($name, 0, 40);
        }
        $hash = substr(md5($host . '|' . $port . '|' . $prefix . '|' . $db), 0, 6);
        return 'maccms_' . $name . '_' . $hash;
    }

    public static function indexUid()
    {
        $uid = trim((string)(self::cfg()['index_uid'] ?? ''));
        return $uid !== '' ? $uid : self::defaultIndexUid();
    }

    /** 当前用的是否历史共享默认名（后台据此提示多站点串库风险）。 */
    public static function isLegacySharedUid()
    {
        return trim((string)(self::cfg()['index_uid'] ?? '')) === self::LEGACY_SHARED_UID;
    }

    public static function apiKey()
    {
        return (string)(self::cfg()['api_key'] ?? '');
    }

    public static function timeout()
    {
        return max(1, (int)(self::cfg()['timeout'] ?? 8));
    }

    public static function sslVerify()
    {
        $v = self::cfg()['ssl_verify'] ?? '1';
        return (string)$v !== '0';
    }

    public static function syncOnSave()
    {
        $c = self::cfg();
        return !isset($c['sync_on_save']) || (string)$c['sync_on_save'] !== '0';
    }

    /**
     * 已发布内容统一过滤（与索引文档字段 kind / recycle / status 一致）。
     * 供 AI 搜索、AI 聊天、内部联想等与 Meilisearch 共用。
     */
    public static function filterPublishedKind($kind)
    {
        $k = strtolower((string)$kind);
        if (!in_array($k, ['vod', 'art', 'manga', 'topic', 'actor', 'role', 'website'], true)) {
            return '';
        }
        return 'kind = "' . $k . '" AND recycle = 0 AND status = 1';
    }

    public static function health()
    {
        if (!self::enabled()) {
            return ['ok' => false, 'msg' => 'disabled'];
        }
        $r = MeilisearchHttp::request(self::host(), 'GET', '/health', '', null, self::timeout(), self::sslVerify());
        return ['ok' => !empty($r['ok']), 'status' => $r['status'], 'data' => $r['data']];
    }

    public static function ensureIndex()
    {
        if (!self::enabled()) {
            return ['ok' => false, 'msg' => 'disabled'];
        }
        // MeilisearchSync 在【每一次】文档保存前都会调一次本方法,而它内部是一次
        // GET /indexes/{uid} 网络往返。采集高峰一小时几千次入库时,等于把对 Meili 的
        // HTTP 调用翻倍,纯属浪费 —— 索引只要确认存在过一次,本进程内就不必再问。
        // 只记忆「确认存在」这一种结果:失败不记忆,下次仍会重试(Meili 恢复后能自愈)。
        static $verified = [];
        $memoKey = self::host() . '|' . self::indexUid();
        if (isset($verified[$memoKey])) {
            return ['ok' => true, 'created' => false, 'memo' => true];
        }
        $uid = rawurlencode(self::indexUid());
        $r = MeilisearchHttp::request(self::host(), 'GET', '/indexes/' . $uid, self::apiKey(), null, self::timeout(), self::sslVerify());
        if (!empty($r['ok'])) {
            $verified[$memoKey] = true;
            return ['ok' => true, 'created' => false];
        }
        $create = MeilisearchHttp::request(self::host(), 'POST', '/indexes', self::apiKey(), [
            'uid' => self::indexUid(),
            'primaryKey' => 'id',
        ], self::timeout(), self::sslVerify());
        if (!empty($create['ok'])) {
            $verified[$memoKey] = true;
            self::updateSettings();
        }
        return ['ok' => !empty($create['ok']), 'created' => true, 'response' => $create['data'] ?? null];
    }

    /**
     * 索引 settings PATCH 请求体（searchable / filterable / sortable 等）。
     *
     * @return array<string, mixed>
     */
    public static function indexSettingsPayload()
    {
        return [
            'searchableAttributes' => [
                'title', 'subtitle', 'en', 'extra', 'tags', 'class_text',
                'title_py', 'title_initials', 'subtitle_py', 'subtitle_initials',
                'extra_py', 'extra_initials', 'tags_py', 'tags_initials',
                'title_t2s', 'title_s2t', 'subtitle_t2s', 'subtitle_s2t',
                'extra_t2s', 'extra_s2t', 'tags_t2s', 'tags_s2t',
                'blurb', 'body',
            ],
            'filterableAttributes' => [
                'kind', 'type_id', 'type_id_1', 'recycle', 'status', 'level', 'group_id', 'isend', 'plot',
                'year', 'area', 'lang', 'state', 'version', 'rid',
                // ts 同时用于时间范围过滤(build*Filter 的 thinkTimeToMeili 生成 ts>x/ts<y);
                // 缺失会导致"关键词+时间筛选"被 Meili 拒绝而静默回退 LIKE。ts 亦在 sortable 中,两者可共存。
                'ts',
            ],
            'sortableAttributes' => ['hits_month', 'ts'],
            // API pages use the legacy pg parameter. Keep deep pages on Meili rather than
            // letting them fall back to an unbounded MySQL OFFSET scan.
            'pagination' => ['maxTotalHits' => 400000],
            'rankingRules' => [
                'words',
                'typo',
                'proximity',
                'attribute',
                'sort',
                'exactness',
            ],
            'typoTolerance' => [
                'enabled' => true,
                'minWordSizeForTypos' => [
                    'oneTypo' => 3,
                    'twoTypos' => 6,
                ],
                'disableOnWords' => [],
                'disableOnAttributes' => [],
            ],
        ];
    }

    public static function getSettings()
    {
        if (!self::enabled()) {
            return ['ok' => false, 'data' => null];
        }
        $uid = rawurlencode(self::indexUid());
        $r = MeilisearchHttp::request(
            self::host(),
            'GET',
            '/indexes/' . $uid . '/settings',
            self::apiKey(),
            null,
            self::timeout(),
            self::sslVerify()
        );

        return ['ok' => !empty($r['ok']), 'status' => $r['status'] ?? 0, 'data' => $r['data'] ?? null, 'error' => (string)($r['error'] ?? '')];
    }

    /**
     * @param array<string, mixed> $settings GET /settings 响应
     * @return array{ok:bool,missing_filterable:array,missing_searchable:array,filterableAttributes:array,searchableAttributes:array}
     */
    public static function verifyIndexSettings(array $settings)
    {
        $requiredFilter = ['kind', 'recycle', 'status'];
        $requiredSearch = ['title', 'title_t2s', 'title_s2t'];
        $filter = is_array($settings['filterableAttributes'] ?? null) ? $settings['filterableAttributes'] : [];
        $search = is_array($settings['searchableAttributes'] ?? null) ? $settings['searchableAttributes'] : [];
        $missingFilter = array_values(array_diff($requiredFilter, $filter));
        $missingSearch = array_values(array_diff($requiredSearch, $search));

        return [
            'ok' => empty($missingFilter) && empty($missingSearch),
            'missing_filterable' => $missingFilter,
            'missing_searchable' => $missingSearch,
            'filterableAttributes' => $filter,
            'searchableAttributes' => $search,
        ];
    }

    /**
     * 等待 Meilisearch 异步任务完成（settings PATCH 等）。
     *
     * @return array{ok:bool,status:string,skipped?:bool,data?:mixed}
     */
    public static function waitForTask($taskUid, $maxWaitSec = 30)
    {
        $taskUid = (int)$taskUid;
        if ($taskUid <= 0) {
            return ['ok' => true, 'status' => 'skipped', 'skipped' => true];
        }
        $deadline = time() + max(1, (int)$maxWaitSec);
        $last = null;
        while (time() <= $deadline) {
            $r = MeilisearchHttp::request(
                self::host(),
                'GET',
                '/tasks/' . $taskUid,
                self::apiKey(),
                null,
                self::timeout(),
                self::sslVerify()
            );
            $last = $r;
            if (empty($r['ok']) || !is_array($r['data'] ?? null)) {
                break;
            }
            $status = (string)($r['data']['status'] ?? '');
            if ($status === 'succeeded') {
                return ['ok' => true, 'status' => $status, 'data' => $r['data']];
            }
            if ($status === 'failed' || $status === 'canceled') {
                return ['ok' => false, 'status' => $status, 'data' => $r['data']];
            }
            usleep(200000);
        }

        return ['ok' => false, 'status' => 'timeout', 'data' => is_array($last) ? ($last['data'] ?? null) : null];
    }

    /**
     * 一键初始化：建索引 + PATCH settings + 等待任务 + 校验 filterable/searchable。
     *
     * @param array{wait_sec?:int,filter_test?:bool} $options
     * @return array{ok:bool,msg:string,steps:array}
     */
    public static function bootstrapIndex(array $options = [])
    {
        if (!self::enabled()) {
            return ['ok' => false, 'msg' => 'disabled', 'steps' => []];
        }
        $waitSec = max(5, min(120, (int)($options['wait_sec'] ?? 30)));
        $runFilterTest = !isset($options['filter_test']) || $options['filter_test'];
        $steps = [];

        $steps['ensure_index'] = self::ensureIndex();
        if (empty($steps['ensure_index']['ok'])) {
            return ['ok' => false, 'msg' => 'ensure index failed', 'steps' => $steps];
        }

        $steps['update_settings'] = self::updateSettings();
        if (empty($steps['update_settings']['ok'])) {
            return ['ok' => false, 'msg' => 'update settings failed', 'steps' => $steps];
        }

        $taskUid = 0;
        $patchData = $steps['update_settings']['data'] ?? null;
        if (is_array($patchData) && isset($patchData['taskUid'])) {
            $taskUid = (int)$patchData['taskUid'];
        }
        $steps['wait_task'] = self::waitForTask($taskUid, $waitSec);
        if (empty($steps['wait_task']['ok'])) {
            return ['ok' => false, 'msg' => 'settings task failed or timeout', 'steps' => $steps];
        }

        $steps['get_settings'] = self::getSettings();
        if (empty($steps['get_settings']['ok'])) {
            return ['ok' => false, 'msg' => 'get settings failed', 'steps' => $steps];
        }

        $steps['verify_settings'] = self::verifyIndexSettings(is_array($steps['get_settings']['data']) ? $steps['get_settings']['data'] : []);
        if (empty($steps['verify_settings']['ok'])) {
            return ['ok' => false, 'msg' => 'settings verification failed', 'steps' => $steps];
        }

        if ($runFilterTest) {
            $steps['filter_search_test'] = self::search('软件', self::filterPublishedKind('vod'), 1, 0);
        }

        return ['ok' => true, 'msg' => 'ok', 'steps' => $steps];
    }

    public static function updateSettings()
    {
        if (!self::enabled()) {
            return ['ok' => false];
        }
        $uid = rawurlencode(self::indexUid());
        $body = self::indexSettingsPayload();
        $r = MeilisearchHttp::request(self::host(), 'PATCH', '/indexes/' . $uid . '/settings', self::apiKey(), $body, self::timeout(), self::sslVerify());
        return ['ok' => !empty($r['ok']), 'data' => $r['data'] ?? null];
    }

    public static function addDocuments(array $docs)
    {
        if (!self::enabled() || empty($docs)) {
            return ['ok' => false];
        }
        $uid = rawurlencode(self::indexUid());
        $r = MeilisearchHttp::request(self::host(), 'POST', '/indexes/' . $uid . '/documents', self::apiKey(), $docs, self::timeout(), self::sslVerify());
        // 写入侧此前是纯静默的:8 个 MeilisearchSync 调用点没有一个检查返回值,
        // 外面还套着 catch(\Throwable){} 。采集高峰时 Meili 一旦不可用,新入库的片子
        // 就永久不进索引,而且没有任何痕迹 —— 与 2026-08-26 查询侧静默失败同一个病。
        if (empty($r['ok'])) {
            self::logSearchFailure($r, 'write');
        }
        return ['ok' => !empty($r['ok']), 'data' => $r['data'] ?? null, 'status' => $r['status'] ?? 0];
    }

    public static function deleteDocument($id)
    {
        if (!self::enabled() || $id === '') {
            return ['ok' => false];
        }
        $uid = rawurlencode(self::indexUid());
        $did = rawurlencode((string)$id);
        $r = MeilisearchHttp::request(self::host(), 'DELETE', '/indexes/' . $uid . '/documents/' . $did, self::apiKey(), null, self::timeout(), self::sslVerify());
        // 404 = 文档本来就不在,属于正常结果,不算失败。
        $ok = !empty($r['ok']) || ($r['status'] ?? 0) === 404;
        if (!$ok) {
            // 删除失败比新增失败更危险:下架/删除的片子会继续留在搜索结果里。
            self::logSearchFailure($r, 'write');
        }
        return ['ok' => $ok, 'status' => $r['status'] ?? 0];
    }

    /**
     * @return array{ok:bool,hits:array<int,array>,estimatedTotalHits:int}
     */
    public static function search($q, $filter, $limit, $offset, $sort = [])
    {
        if (!self::enabled()) {
            return ['ok' => false, 'hits' => [], 'estimatedTotalHits' => 0];
        }
        if (is_string($sort) && trim($sort) !== '') {
            $sort = [trim($sort)];
        }
        $sort = is_array($sort) ? array_values(array_filter(array_map('strval', $sort))) : [];
        $memoKey = md5((string)$q . "\x1e" . (string)$filter . "\x1e" . (int)$limit . "\x1e" . (int)$offset . "\x1e" . implode(',', $sort), true);
        $memoKey = 'ms1:' . base64_encode($memoKey);
        if (isset(self::$searchMemo[$memoKey])) {
            return self::$searchMemo[$memoKey];
        }
        $uid = rawurlencode(self::indexUid());
        $baseBody = [
            'limit' => max(1, min(1000, (int)$limit)),
            'offset' => max(0, (int)$offset),
            'attributesToRetrieve' => ['id', 'kind'],
            'matchingStrategy' => 'last',
        ];
        if ($filter !== '') {
            $baseBody['filter'] = $filter;
        }
        if (!empty($sort)) {
            $baseBody['sort'] = $sort;
        }

        // 索引侧 title_t2s/title_s2t + 查询侧 OpenCC 变体，双端保证繁简互通。
        $queries = OpenccConverter::searchVariants((string)$q);
        if (empty($queries)) {
            $queries = [(string)$q];
        }

        $searchPath = '/indexes/' . $uid . '/search';
        $jobs = [];
        foreach ($queries as $queryText) {
            $body = $baseBody;
            $body['q'] = $queryText;
            $jobs[] = ['method' => 'POST', 'path' => $searchPath, 'body' => $body];
        }
        $responses = MeilisearchHttp::requestParallel(self::host(), $jobs, self::apiKey(), self::timeout(), self::sslVerify());

        $lastFailed = null;
        $lastQuery = $queries[count($queries) - 1];
        foreach ($queries as $idx => $queryText) {
            $r = isset($responses[$idx]) && is_array($responses[$idx]) ? $responses[$idx] : ['ok' => false];
            if (empty($r['ok']) || !is_array($r['data'] ?? null)) {
                $lastFailed = $r;
                continue;
            }
            $hits = isset($r['data']['hits']) && is_array($r['data']['hits']) ? $r['data']['hits'] : [];
            $est = isset($r['data']['estimatedTotalHits']) ? (int)$r['data']['estimatedTotalHits'] : count($hits);
            if (!empty($hits) || $queryText === $lastQuery) {
                $out = ['ok' => true, 'hits' => $hits, 'estimatedTotalHits' => $est];
                self::$searchMemo[$memoKey] = $out;

                return $out;
            }
        }

        if ($lastFailed !== null) {
            // 这里过去是「静默失败」:Meili 一挂就返回 ok=false,上层 Bridge 收到 null
            // 就无声回落到 MySQL,全站没有任何告警。2026-08-26 的事故正是如此 ——
            // api_key 失效 + index_uid 指向不存在的索引,Meili 100% 403,
            // 于是所有列表/搜索全量砸向 MySQL 的 filesort 路径,mysqld 打满 55 核、
            // load 冲到 298,而日志里一行错都没有。失败必须留痕。
            self::logSearchFailure($lastFailed);
            $out = ['ok' => false, 'hits' => [], 'estimatedTotalHits' => 0];
            self::$searchMemo[$memoKey] = $out;

            return $out;
        }        $out = ['ok' => true, 'hits' => [], 'estimatedTotalHits' => 0];
        self::$searchMemo[$memoKey] = $out;

        return $out;
    }

    /**
     * Meili 调用失败时留痕。按 (场景+host+index+status+错误码) signature 每 60 秒最多写一条,
     * 避免高 QPS 下把磁盘写满 —— 事故当天是 24 req/s,不限流会瞬间刷爆日志。
     *
     * $scene: 'search' = 查询侧(失败会静默回落 MySQL);
     *         'write'  = 写入侧(失败会让索引与数据库永久漂移,直到全量重建)。
     */
    private static function logSearchFailure(array $failed, string $scene = 'search'): void
    {
        try {
            $status = (int)($failed['status'] ?? 0);
            $err    = (string)($failed['error'] ?? '');
            $body   = $failed['data'] ?? null;
            $code   = is_array($body) ? (string)($body['code'] ?? '') : '';
            $msg    = is_array($body) ? (string)($body['message'] ?? '') : '';

            $sig  = md5($scene . '|' . self::host() . '|' . self::indexUid() . '|' . $status . '|' . $code);
            $stamp = sys_get_temp_dir() . '/maccms_meili_alert_' . $sig . '.ts';
            $now  = time();
            if (is_file($stamp) && ($now - (int)@filemtime($stamp)) < 60) {
                return;
            }
            @touch($stamp);
            @chmod($stamp, 0666);

            $hint = '';
            if ($status === 403 || $code === 'invalid_api_key') {
                $hint = ' | HINT: api_key 失效,后台「Meilisearch 配置」重填 key';
            } elseif ($status === 404 || $code === 'index_not_found') {
                $hint = ' | HINT: index_uid 指向的索引不存在,核对索引名或重建索引';
            } elseif ($status === 0) {
                $hint = ' | HINT: 连不上 Meili,检查 systemctl status meilisearch';
            }

            \think\facade\Log::error(
                '[MEILI-DOWN] '
                . ($scene === 'write'
                    ? 'document write failed —— 索引将与数据库漂移,修好后需全量重建'
                    : 'search failed, falling back to MySQL')
                . ' host=' . self::host()
                . ' index=' . self::indexUid()
                . ' status=' . $status
                . ($code !== '' ? ' code=' . $code : '')
                . ($msg !== '' ? ' msg=' . $msg : '')
                . ($err !== '' ? ' curl=' . $err : '')
                . $hint
            );
        } catch (\Throwable $e) {
            // 告警本身绝不能影响请求
        }
    }
}
