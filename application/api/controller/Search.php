<?php

namespace app\api\controller;

use think\facade\Request;
use think\facade\Db;
use think\facade\Cache;
use app\common\util\ApiMeilisearchSuggest;
use app\common\util\MeilisearchService;

/**
 * 统一搜索 API
 * 支持跨模块搜索（视频、文章、漫画等）
 *
 * 路径：GET /api.php/search/index
 * 参数：
 *   wd     - string 必填，搜索关键字（trim 后不可为空，最长 50 字）
 *   module - string 可选，搜索范围 all|vod|art|manga（默认 all，搜索所有模块）
 *   limit  - number 可选，每个模块返回数量 1~50 默认 10
 *   page   - number 可选，页码 默认 1（用于分页）
 *
 * 返回结构：
 *   code=1 成功时 info 含 wd, module, page, limit,
 *   以及 vod/art/manga 各含 total 和 list 数组
 *
 * 数据来源：优先 Meilisearch，命中 ID 必须在数据库 writer 上确认已发布、未回收。
 *   index 保留成功空命中；suggest 空命中回退 LIKE。未启用或搜索服务失败均回退 LIKE。
 *   本控制器的 writer 保证不延伸到其他单模块 suggest 入口。
 */
class Search extends Base
{
    use PublicApi;

    /**
     * index() 使用的"富字段"对照表，与单模块 search 接口一致。
     * Meili 命中后依此字段拉 DB 行，MySQL 回退时也用此投影 + LIKE 字段。
     *
     * @var array<string, array<string, mixed>>
     */
    private static $kindRichMeta = [
        'vod' => [
            'table'       => 'vod',
            'pk'          => 'vod_id',
            'status'      => 'vod_status',
            'recycle'     => 'vod_recycle_time',
            'like'        => 'vod_name|vod_en|vod_actor|vod_director',
            'order'       => 'vod_time desc',
            'field'       => 'vod_id,vod_name,vod_en,vod_sub,vod_pic,vod_actor,vod_director,vod_remarks,vod_score,vod_area,vod_year,vod_class,vod_blurb,vod_time,vod_hits,type_id,type_id_1',
            'lang_key'    => 'vod',
        ],
        'art' => [
            'table'       => 'art',
            'pk'          => 'art_id',
            'status'      => 'art_status',
            'recycle'     => 'art_recycle_time',
            'like'        => 'art_name|art_sub|art_tag',
            'order'       => 'art_time desc',
            'field'       => 'art_id,art_name,art_sub,art_pic,art_tag,art_class,art_blurb,art_time,art_hits,art_score,type_id,type_id_1',
            'lang_key'    => 'art',
        ],
        'manga' => [
            'table'       => 'manga',
            'pk'          => 'manga_id',
            'status'      => 'manga_status',
            'recycle'     => 'manga_recycle_time',
            'like'        => 'manga_name|manga_en|manga_tag',
            'order'       => 'manga_time desc',
            'field'       => 'manga_id,manga_name,manga_en,manga_sub,manga_pic,manga_tag,manga_class,manga_blurb,manga_time,manga_hits,manga_score,manga_remarks,type_id,type_id_1',
            'lang_key'    => 'manga',
        ],
    ];

    /** 限流：每 IP 在 RATE_WINDOW 秒内最多 RATE_MAX 次（index/suggest 共享配额） */
    const RATE_WINDOW = 60;
    const RATE_MAX    = 30;

    /** 结果缓存 TTL（秒）；同 wd/module/page/limit 复用以削峰，避免 LIKE 全表扫被刷 */
    const RESULT_CACHE_TTL = 300;

    public function __construct()
    {
        parent::__construct();
        $this->check_config();
    }

    /**
     * 公开搜索接口的 IP 限流（滑动/固定窗口，Redis 后端原子 INCR，其它后端回退到 has+set）。
     * 返回 true 表示允许；false 表示已超限。
     *
     * 与 application/common/model/Chatroom.php::_atomicRateCheck 同理，区别是这里需要计数（不是 0/1）。
     *
     * @return bool
     */
    private function checkRateLimit()
    {
        $ip = function_exists('mac_get_client_ip') ? mac_get_client_ip() : ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
        if ($ip === '') {
            $ip = '0.0.0.0';
        }
        $key = 'api_search_rl_' . md5($ip);

        // 优先走 Redis 原子 INCR（用法与 application/common/model/Chatroom.php::_atomicRateCheck 对齐）
        try {
            $handler = app('cache')->store()->handler();
            if (class_exists('\Redis', false) && $handler instanceof \Redis) {
                $cnt = (int)$handler->incr($key);
                if ($cnt === 1) {
                    $handler->expire($key, self::RATE_WINDOW);
                }
                return $cnt <= self::RATE_MAX;
            }
        } catch (\Throwable $e) {
            // handler 不可用：fallthrough 到通用方案
        }

        // 通用回退：has + 读 + 写（非严格原子，但足以削峰）
        $cnt = (int)Cache::get($key, 0);
        if ($cnt >= self::RATE_MAX) {
            return false;
        }
        Cache::set($key, $cnt + 1, self::RATE_WINDOW);
        return true;
    }

    /**
     * 生成结果缓存 key（不含 IP，跨用户共享同关键字的命中）。
     *
     * @param string $endpoint  'index' | 'suggest'
     * @param array  $params    影响结果的归一化参数
     *
     * @return string
     */
    private function resultCacheKey($endpoint, array $params)
    {
        ksort($params);
        return 'api_search_v2_' . $endpoint . '_' . md5(json_encode($params, JSON_UNESCAPED_UNICODE));
    }

    /** Request-local schema evidence, scoped to the actual connection and table. */
    private ?\WeakMap $publicationSchemas = null;
    private ?object $schemaRequest = null;

    private function normalizedParameters(array $param, bool $index): ?array
    {
        $raw = $param['wd'] ?? null;
        if ((!is_string($raw) && !is_int($raw)) || strlen((string)$raw) > 4096
            || preg_match('//u', (string)$raw) !== 1 || preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', (string)$raw)) {
            return null;
        }
        $wd = trim((string)$raw);
        if ($wd === '') { return null; }
        $wd = mb_substr($wd, 0, 50, 'UTF-8');
        $limit = $this->paginationInteger($param['limit'] ?? null, $index ? 10 : 5);
        if ($limit === null) { return null; }
        $limit = max(1, min($index ? 50 : 10, $limit));
        $out = ['wd'=>$wd, 'limit'=>$limit];
        if (!$index) { return $out; }
        $module = $param['module'] ?? 'all';
        if ((!is_string($module) && !is_int($module)) || strlen((string)$module) > 32) { return null; }
        $module = strtolower(trim((string)$module));
        if (!in_array($module, ['all','vod','art','manga'], true)) { $module = 'all'; }
        $page = $this->paginationInteger($param['page'] ?? null, 1);
        if ($page === null) { return null; }
        $page = max(1, $page);
        if ($page - 1 > intdiv(PHP_INT_MAX, $limit)) { return null; }
        return $out + ['module'=>$module, 'page'=>$page, 'offset'=>($page - 1) * $limit];
    }

    private function paginationInteger(mixed $raw, int $default): ?int
    {
        if ($raw === null) { return $default; }
        if ((!is_int($raw) && !is_string($raw)) || strlen((string)$raw) > 32) { return null; }
        $raw = trim((string)$raw);
        if (!preg_match('/^[+-]?[0-9]{1,10}$/D', $raw)) { return null; }
        $value = (int)$raw;
        if (PHP_INT_SIZE < 8 || $value < -4294967295 || $value > 4294967295) { return null; }
        return $value;
    }

    /** Like PublicContentQuery, omit recycle only when read-only schema discovery proves it absent. */
    private function publishedQuery(string $kind): \think\db\Query
    {
        if (!isset(self::$kindRichMeta[$kind])) { throw new \InvalidArgumentException('Unsupported search kind'); }
        $request = request();
        if ($this->schemaRequest !== $request) { $this->schemaRequest = $request; $this->publicationSchemas = new \WeakMap(); }
        $query = Db::name($kind)->master();
        $connection = $query->getConnection();
        $table = $query->getTable();
        $schemas = $this->publicationSchemas[$connection] ?? [];
        if (!isset($schemas[$table])) {
            if (!$connection->getPdo() instanceof \PDO) { $connection->query('SELECT 1', [], true); }
            $driver = $connection->getPdo()->getAttribute(\PDO::ATTR_DRIVER_NAME);
            if ($driver === 'mysql') {
                $rows = $connection->query('SELECT COLUMN_NAME AS field FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?', [$table], true);
            } elseif ($driver === 'sqlite') {
                $rows = $connection->query('SELECT name AS field FROM pragma_table_info(?)', [$table], true);
            } else { throw new \RuntimeException('Unsupported search schema driver'); }
            $fields = array_column($rows, 'field');
            if (!in_array($kind.'_id', $fields, true) || !in_array($kind.'_status', $fields, true)) {
                throw new \RuntimeException('Public search schema could not be confirmed');
            }
            $conditions = [[$kind.'_status', '=', 1]];
            if (in_array($kind.'_recycle_time', $fields, true)) { $conditions[] = [$kind.'_recycle_time', '=', 0]; }
            $schemas[$table] = $conditions;
            $this->publicationSchemas[$connection] = $schemas;
        }
        return $query->where($schemas[$table]);
    }

    private function resultIds(array $rows, string $kind, int $maximum): ?array
    {
        if (!array_is_list($rows) || count($rows) > $maximum) { return null; }
        $ids = [];
        foreach ($rows as $row) {
            if (!is_array($row) || ($row['module'] ?? null) !== $kind) { return null; }
            $id = $row['id'] ?? null;
            if ((!is_int($id) && !is_string($id)) || !preg_match('/^[1-9][0-9]{0,9}$/D', (string)$id)
                || (int)$id > 4294967295 || isset($ids[(int)$id])) { return null; }
            $ids[(int)$id] = (int)$id;
        }
        return array_values($ids);
    }

    private function allVisible(string $kind, array $ids): bool
    {
        $query = $this->publishedQuery($kind);
        return $ids === [] || (int)$query->whereIn($kind.'_id', $ids)->count() === count($ids);
    }

    private function cachedIndexVisible(array $cached, array $param): bool
    {
        $info = $cached['info'] ?? null;
        $kinds = $param['module'] === 'all' ? ['vod','art','manga'] : [$param['module']];
        if (($cached['code'] ?? null) !== 1 || !is_string($cached['msg'] ?? null) || !is_array($info)
            || array_diff(array_keys($cached), ['code','msg','info'])
            || array_diff(array_keys($info), array_merge(['wd','module','page','limit'], $kinds))) { return false; }
        foreach (['module','page','limit'] as $key) { if (($info[$key] ?? null) !== $param[$key]) { return false; } }
        foreach ($kinds as $kind) {
            $part = $info[$kind] ?? null;
            if (!is_array($part) || array_diff(array_keys($part), ['total','list']) || !is_int($part['total'] ?? null)
                || $part['total'] < 0 || !is_array($part['list'] ?? null)) { return false; }
            $ids = $this->resultIds($part['list'], $kind, $param['limit']);
            if ($ids === null || count($ids) > $part['total']) { return false; }
            foreach ($part['list'] as $row) {
                if (count($row) !== 22 || array_diff(array_keys($row), ['id','name','en','sub','pic','actor','director','remarks','score','area','year','class','tag','blurb','time','hits','link','type_id','type_id_1','type_is_vip_exclusive','module','module_name'])) { return false; }
                foreach (['id','time','hits','type_id','type_id_1','type_is_vip_exclusive'] as $field) { if (!is_int($row[$field] ?? null)) { return false; } }
                foreach (['name','en','sub','pic','actor','director','remarks','area','year','class','tag','blurb','link','module','module_name'] as $field) { if (!is_string($row[$field] ?? null)) { return false; } }
                if (!is_string($row['score']) && !is_int($row['score']) && !is_float($row['score'])) { return false; }
            }
            if (!$this->allVisible($kind, $ids)) { return false; }
        }
        return true;
    }

    private function cachedSuggestVisible(array $cached, int $limit): bool
    {
        $info = $cached['info'] ?? null;
        if (($cached['code'] ?? null) !== 1 || !is_string($cached['msg'] ?? null) || !is_array($info)
            || array_diff(array_keys($cached), ['code','msg','info']) || array_diff(array_keys($info), ['wd','total','list'])
            || !is_array($info['list'] ?? null) || !array_is_list($info['list']) || count($info['list']) > 3 * $limit
            || ($info['total'] ?? null) !== count($info['list'])) { return false; }
        $groups = ['vod'=>[], 'art'=>[], 'manga'=>[]];
        foreach ($info['list'] as $row) {
            if (!is_array($row) || count($row) !== 7 || !is_int($row['id'] ?? null) || !is_string($row['module'] ?? null) || !isset($groups[$row['module']])
                || array_diff(array_keys($row), ['id','name','en','pic','link','module','module_name'])) { return false; }
            foreach (['name','en','pic','link','module_name'] as $field) { if (!is_string($row[$field] ?? null)) { return false; } }
            $groups[$row['module']][] = $row;
        }
        foreach ($groups as $kind=>$rows) {
            $ids = $this->resultIds($rows, $kind, $limit);
            if ($ids === null || !$this->allVisible($kind, $ids)) { return false; }
        }
        return true;
    }

    private function unavailable(string $endpoint, \Throwable $error)
    {
        try {
            \think\facade\Log::error('Unified Search '.$endpoint.' failed: '.get_class($error).' at '.basename($error->getFile()).':'.$error->getLine());
        } catch (\Throwable $loggingError) {}
        return json(['code'=>1002, 'msg'=>'搜索暂不可用，请稍后再试']);
    }

    /**
     * 统一搜索入口
     */
    public function index(\think\Request $request)
    {
        try { return $this->indexResult($request); }
        catch (\Throwable $error) { return $this->unavailable('index', $error); }
    }

    private function indexResult(\think\Request $request)
    {
        $param = $this->normalizedParameters($request->param(), true);
        if ($param === null) { return json(['code'=>1001, 'msg'=>'参数错误']); }
        ['wd'=>$wd, 'module'=>$module, 'limit'=>$limit, 'page'=>$page, 'offset'=>$offset] = $param;
        if (($GLOBALS['config']['app']['search'] ?? '0') != '1') {
            return json(['code'=>999, 'msg'=>'搜索功能已关闭']);
        }

        // SQL 安全过滤（保留 CJK 字符；走 trait 上的统一方法）
        $safeWd = $this->format_sql_string($wd);
        if ($safeWd === '') {
            return json(['code' => 1001, 'msg' => '参数错误: 关键字无效']);
        }

        // 1) 缓存仅在 writer 再次核验全部源 ID 后复用，省掉 LIKE 与 Meili 调用
        $cacheKey = $this->resultCacheKey('index', [
            'wd'     => $safeWd,
            'module' => $module,
            'page'   => $page,
            'limit'  => $limit,
        ]);
        $cached = Cache::get($cacheKey);
        if (is_array($cached) && $this->cachedIndexVisible($cached, $param)) {
            // 缓存命中也保留 wd 原文用于回显
            if (isset($cached['info']) && is_array($cached['info'])) {
                $cached['info']['wd'] = $wd;
            }
            return json($cached);
        }

        // 2) 未命中缓存才计入限流配额（避免误伤静态命中场景）
        if (!$this->checkRateLimit()) {
            return json(['code' => 1004, 'msg' => '请求过于频繁，请稍后再试']);
        }

        $result = [
            'wd'     => $wd,
            'module' => $module,
            'page'   => $page,
            'limit'  => $limit,
        ];

        $kinds = $module === 'all' ? ['vod', 'art', 'manga'] : [$module];
        foreach ($kinds as $kind) {
            $result[$kind] = $this->searchKindRich($kind, $safeWd, $offset, $limit);
        }

        $resp = [
            'code' => 1,
            'msg'  => '搜索成功',
            'info' => $result,
        ];
        Cache::set($cacheKey, $resp, self::RESULT_CACHE_TTL);

        return json($resp);
    }

    /**
     * 单一模块搜索（含 Meilisearch 路径 + MySQL LIKE 回退），输出富字段 list。
     *
     * @param string $kind   vod|art|manga
     * @param string $wd     已 SQL 安全化的关键字
     * @param int    $offset 偏移
     * @param int    $limit  每页
     *
     * @return array{total:int,list:array}
     */
    private function searchKindRich($kind, $wd, $offset, $limit)
    {
        $meta = self::$kindRichMeta[$kind];
        if (MeilisearchService::enabled()) {
            $filter = MeilisearchService::filterPublishedKind($kind);
            $sr = MeilisearchService::search($wd, $filter, $limit, $offset);
            if (!empty($sr['ok'])) {
                $ids = $this->hitIds($kind, $sr['hits'] ?? null, $limit);
                $rows = $this->loadRowsByIdsRich($kind, $ids, $meta);
                $list = $this->rowsToRichItems($kind, $rows, $meta);
                $estimate = max(0, (int)($sr['estimatedTotalHits'] ?? 0));
                return ['total'=>$list === [] ? $estimate : max($estimate, count($list) + $offset), 'list'=>$list];
            }
        }
        $query = $this->publishedQuery($kind)->where([[$meta['like'], 'like', '%'.$wd.'%']]);
        $total = (int)(clone $query)->count();
        if ($offset >= $total) { return ['total'=>$total, 'list'=>[]]; }
        $rows = $query->field($meta['field'])->order($meta['order'])->limit($offset, $limit)->select()->toArray();
        return ['total'=>$total, 'list'=>$this->rowsToRichItems($kind, $rows, $meta)];
    }

    private function hitIds(string $kind, mixed $hits, int $limit): array
    {
        $ids = [];
        foreach (array_slice(is_array($hits) ? $hits : [], 0, $limit) as $hit) {
            if (is_array($hit) && is_string($hit['id'] ?? null)
                && preg_match('/^'.preg_quote($kind, '/').'_([1-9][0-9]{0,9})$/D', $hit['id'], $match)
                && (int)$match[1] <= 4294967295) { $ids[] = (int)$match[1]; }
        }
        return array_values(array_unique($ids));
    }

    /** Preserve the suggestion service's projection, rank order and fallback semantics with writer visibility. */
    private function suggestKind(string $kind, string $wd, int $limit): array
    {
        $meta = [
            'pk'=>$kind.'_id',
            'field'=>$kind.'_id,'.$kind.'_name,'.$kind.'_en,'.$kind.'_pic,'.$kind.'_time,type_id,type_id_1',
        ];
        $like = $kind.'_name|'.$kind.'_en';
        if ($kind === 'manga') { $meta['field'] .= ',manga_sub'; $like .= '|manga_sub'; }
        $rows = [];
        if (MeilisearchService::enabled()) {
            $result = MeilisearchService::search($wd, MeilisearchService::filterPublishedKind($kind), $limit, 0);
            if (!empty($result['ok'])) {
                $rows = $this->loadRowsByIdsRich($kind, $this->hitIds($kind, $result['hits'] ?? null, $limit), $meta);
            }
        }
        if ($rows === []) {
            $rows = $this->publishedQuery($kind)->field($meta['field'])
                ->where([[$like, 'like', '%'.addcslashes($wd, '%_\\').'%']])
                ->order($meta['pk'].' desc')->limit($limit)->select()->toArray();
        }
        return array_map(static fn(array $row)=>ApiMeilisearchSuggest::toSlimItem($kind, $row), $rows);
    }

    /** Real public database rows in Meili rank order; an exception never relaxes the publication guard. */
    private function loadRowsByIdsRich($kind, array $ids, array $meta)
    {
        $ids = array_values(array_unique($ids));
        $query = $this->publishedQuery($kind);
        if ($ids === []) { return []; }
        $rows = $query->field($meta['field'])->whereIn($meta['pk'], $ids)->select()->toArray();
        $map = [];
        foreach ($rows as $row) { $map[(int)$row[$meta['pk']]] = $row; }
        $ordered = [];
        foreach ($ids as $id) { if (isset($map[$id])) { $ordered[] = $map[$id]; } }
        return $ordered;
    }

    /**
     * 将 DB 行转换为对外的"富字段"格式（保留原 PR 结构）。
     *
     * @param string              $kind
     * @param array               $rows
     * @param array<string,mixed> $meta
     *
     * @return array
     */
    private function rowsToRichItems($kind, $rows, array $meta)
    {
        if (!is_array($rows) || $rows === []) {
            return [];
        }
        $list = [];
        if ($kind === 'vod') {
            // 追加 VIP 标识
            mac_append_type_is_vip_exclusive_for_rows($rows);
            foreach ($rows as $v) {
                $list[] = [
                    'id'                    => (int)$v['vod_id'],
                    'name'                  => $v['vod_name'] ?? '',
                    'en'                    => $v['vod_en'] ?? '',
                    'sub'                   => $v['vod_sub'] ?? '',
                    'pic'                   => mac_url_img($v['vod_pic'] ?? ''),
                    'actor'                 => $v['vod_actor'] ?? '',
                    'director'              => $v['vod_director'] ?? '',
                    'remarks'               => $v['vod_remarks'] ?? '',
                    'score'                 => $v['vod_score'] ?? '0.0',
                    'area'                  => $v['vod_area'] ?? '',
                    'year'                  => $v['vod_year'] ?? '',
                    'class'                 => $v['vod_class'] ?? '',
                    'tag'                   => '',
                    'blurb'                 => $v['vod_blurb'] ?? '',
                    'time'                  => (int)($v['vod_time'] ?? 0),
                    'hits'                  => (int)($v['vod_hits'] ?? 0),
                    'link'                  => mac_url_vod_detail($v),
                    'type_id'               => (int)($v['type_id'] ?? 0),
                    'type_id_1'             => (int)($v['type_id_1'] ?? 0),
                    'type_is_vip_exclusive' => (int)($v['type_is_vip_exclusive'] ?? 0),
                    'module'                => 'vod',
                    'module_name'           => lang($meta['lang_key']),
                ];
            }
            return $list;
        }
        if ($kind === 'art') {
            foreach ($rows as $v) {
                $list[] = [
                    'id'                    => (int)$v['art_id'],
                    'name'                  => $v['art_name'] ?? '',
                    'en'                    => '',
                    'sub'                   => $v['art_sub'] ?? '',
                    'pic'                   => mac_url_img($v['art_pic'] ?? ''),
                    'actor'                 => '',
                    'director'               => '',
                    'remarks'               => '',
                    'score'                 => $v['art_score'] ?? '0.0',
                    'area'                  => '',
                    'year'                  => '',
                    'class'                 => $v['art_class'] ?? '',
                    'tag'                   => $v['art_tag'] ?? '',
                    'blurb'                 => $v['art_blurb'] ?? '',
                    'time'                  => (int)($v['art_time'] ?? 0),
                    'hits'                  => (int)($v['art_hits'] ?? 0),
                    'link'                  => mac_url_art_detail($v),
                    'type_id'               => (int)($v['type_id'] ?? 0),
                    'type_id_1'             => (int)($v['type_id_1'] ?? 0),
                    'type_is_vip_exclusive' => 0,
                    'module'                => 'art',
                    'module_name'           => lang($meta['lang_key']),
                ];
            }
            return $list;
        }
        if ($kind === 'manga') {
            foreach ($rows as $v) {
                $list[] = [
                    'id'                    => (int)$v['manga_id'],
                    'name'                  => $v['manga_name'] ?? '',
                    'en'                    => $v['manga_en'] ?? '',
                    'sub'                   => $v['manga_sub'] ?? '',
                    'pic'                   => mac_url_img($v['manga_pic'] ?? ''),
                    'actor'                 => '',
                    'director'               => '',
                    'remarks'               => $v['manga_remarks'] ?? '',
                    'score'                 => $v['manga_score'] ?? '0.0',
                    'area'                  => '',
                    'year'                  => '',
                    'class'                 => $v['manga_class'] ?? '',
                    'tag'                   => $v['manga_tag'] ?? '',
                    'blurb'                 => $v['manga_blurb'] ?? '',
                    'time'                  => (int)($v['manga_time'] ?? 0),
                    'hits'                  => (int)($v['manga_hits'] ?? 0),
                    'link'                  => mac_url_manga_detail($v),
                    'type_id'               => (int)($v['type_id'] ?? 0),
                    'type_id_1'             => (int)($v['type_id_1'] ?? 0),
                    'type_is_vip_exclusive' => 0,
                    'module'                => 'manga',
                    'module_name'           => lang($meta['lang_key']),
                ];
            }
            return $list;
        }
        return $list;
    }

    /**
     * 搜索联想（自动完成）
     * 跨模块快速联想，适合搜索框下拉提示
     *
     * 路径：GET /api.php/search/suggest
     * 参数：
     *   wd    - string 必填，关键字
     *   limit - number 可选，每个模块返回数量，1~10，默认 5
     *
     * 数据来源：复用 MeilisearchService 和固定 slim DTO；此公开入口独立读取 writer 发布状态。
     */
    public function suggest(\think\Request $request)
    {
        try { return $this->suggestResult($request); }
        catch (\Throwable $error) { return $this->unavailable('suggest', $error); }
    }

    private function suggestResult(\think\Request $request)
    {
        $param = $this->normalizedParameters($request->param(), false);
        if ($param === null) { return json(['code'=>1001, 'msg'=>'参数错误']); }
        ['wd'=>$wd, 'limit'=>$limit] = $param;
        if (($GLOBALS['config']['app']['search'] ?? '0') != '1') {
            return json(['code'=>999, 'msg'=>'搜索功能已关闭']);
        }

        // XSS 过滤交给 mac_filter_xss；Meili / 固定字段查询
        // 自带 PDO 预处理，这里无需再做 SQL 关键字剥离（且会破坏中文检索）。
        $wdFilter = function_exists('mac_filter_xss') ? mac_filter_xss($wd) : $wd;
        if ($wdFilter === '') {
            return json(['code' => 1001, 'msg' => '参数错误: 关键字无效']);
        }

        // 1) 缓存仅在 writer 再次核验全部源 ID 后复用
        $cacheKey = $this->resultCacheKey('suggest', [
            'wd'    => $wdFilter,
            'limit' => $limit,
        ]);
        $cached = Cache::get($cacheKey);
        if (is_array($cached) && $this->cachedSuggestVisible($cached, $limit)) {
            if (isset($cached['info']) && is_array($cached['info'])) {
                $cached['info']['wd'] = $wd;
            }
            return json($cached);
        }

        // 2) 未命中缓存才计入限流配额
        if (!$this->checkRateLimit()) {
            return json(['code' => 1004, 'msg' => '请求过于频繁，请稍后再试']);
        }

        $moduleNames = [
            'vod'   => lang('vod'),
            'art'   => lang('art'),
            'manga' => lang('manga'),
        ];

        $suggestions = [];

        foreach (['vod', 'art', 'manga'] as $kind) {
            foreach ($this->suggestKind($kind, $wdFilter, $limit) as $it) {
                // 固定 slim DTO（含 *_link）映射为跨模块统一 shape。
                $linkKey = $kind . '_link';
                $suggestions[] = [
                    'id'          => (int)($it['id'] ?? 0),
                    'name'        => (string)($it['name'] ?? ''),
                    'en'          => (string)($it['en'] ?? ''),
                    'pic'         => (string)($it['pic'] ?? ''),
                    'link'        => (string)($it[$linkKey] ?? ''),
                    'module'      => $kind,
                    'module_name' => $moduleNames[$kind],
                ];
            }
        }

        $resp = [
            'code' => 1,
            'msg'  => '获取成功',
            'info' => [
                'wd'    => $wd,
                'total' => count($suggestions),
                'list'  => $suggestions,
            ],
        ];
        Cache::set($cacheKey, $resp, self::RESULT_CACHE_TTL);

        return json($resp);
    }
}
