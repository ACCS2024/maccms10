<?php

namespace app\admin\controller;

use app\common\util\MeilisearchService;
use app\common\util\MeilisearchSync;
use app\common\util\MeilisearchHttp;
use app\common\util\OpenccConverter;

class Meilisearch extends Base
{
    public function __construct()
    {
        parent::__construct();
        if ((string)$this->_admin['admin_id'] !== '1') {
            $this->error(lang('admin/meilisearch/super_admin_only'));
        }
    }

    public function index()
    {
        $cfg = MeilisearchService::cfg();
        if (!is_array($cfg)) {
            $cfg = [];
        }
        $cfg = array_merge([
            'enabled' => '0',
            'host' => '',
            'api_key' => '',
            'index_uid' => MeilisearchService::defaultIndexUid(),
            'timeout' => '8',
            'ssl_verify' => '1',
            'sync_on_save' => '1',
            'search_only_wd' => '1',
        ], $cfg);
        $h = MeilisearchService::health();
        $stats = ['numberOfDocuments' => 0];
        if ((string)$cfg['enabled'] === '1') {
            $uid = rawurlencode((string)$cfg['index_uid']);
            $statsRes = MeilisearchHttp::request(
                rtrim((string)$cfg['host'], '/'),
                'GET',
                '/indexes/' . $uid . '/stats',
                (string)$cfg['api_key'],
                null,
                max(1, (int)$cfg['timeout']),
                (string)$cfg['ssl_verify'] !== '0'
            );
            if (!empty($statsRes['ok']) && is_array($statsRes['data'] ?? null)) {
                $stats['numberOfDocuments'] = (int)($statsRes['data']['numberOfDocuments'] ?? 0);
            }
        }
        $this->assign('health', $h);
        $this->assign('stats', $stats);
        $this->assign('opencc_available', OpenccConverter::available());
        $settingsCheck = ['ok' => true, 'filterableAttributes' => [], 'searchableAttributes' => []];
        if ((string)$cfg['enabled'] === '1' && !empty($h['ok'])) {
            $gs = MeilisearchService::getSettings();
            if (!empty($gs['ok']) && is_array($gs['data'])) {
                $settingsCheck = MeilisearchService::verifyIndexSettings($gs['data']);
            } else {
                $settingsCheck = ['ok' => false, 'filterableAttributes' => [], 'searchableAttributes' => [], 'missing_filterable' => ['kind', 'recycle', 'status'], 'missing_searchable' => ['title', 'title_t2s', 'title_s2t']];
            }
        }
        $this->assign('settings_check', $settingsCheck);
        $this->assign('cfg', $cfg);
        $this->assign('shared_uid_warn', MeilisearchService::isLegacySharedUid() ? 1 : 0);
        $this->assign('suggested_uid', MeilisearchService::defaultIndexUid());
        $this->assign('meili_key_saved', trim((string)$cfg['api_key']) !== '' ? 1 : 0);
        $this->assign('meili_key_tail', trim((string)$cfg['api_key']) !== '' ? substr((string)$cfg['api_key'], -6) : '');
        $this->assign('title', 'Meilisearch 全文检索');
        return $this->fetch('admin@meilisearch/index');
    }

    public function status()
    {
        return json(MeilisearchService::health());
    }

    /**
     * 保存 Meilisearch 配置到 maccms.php。
     */
    public function save()
    {
        if (!request()->isPost()) {
            return json(['code' => 0, 'msg' => lang('param_err')]);
        }
        $post = \think\facade\Request::post();
        $meili = isset($post['meilisearch']) && is_array($post['meilisearch']) ? $post['meilisearch'] : [];
        $sanitize = function ($v) {
            return trim(strip_tags((string)$v));
        };
        $cfgOld = config('maccms');
        $cfgNew = $cfgOld;
        $row = [
            'enabled' => isset($meili['enabled']) && (string)$meili['enabled'] === '1' ? '1' : '0',
            'host' => rtrim($sanitize(isset($meili['host']) ? $meili['host'] : ''), '/'),
            'index_uid' => $sanitize(isset($meili['index_uid']) ? $meili['index_uid'] : 'maccms_contents'),
            'timeout' => (string)max(1, intval(isset($meili['timeout']) ? $meili['timeout'] : 8)),
            'ssl_verify' => isset($meili['ssl_verify']) && (string)$meili['ssl_verify'] === '0' ? '0' : '1',
            'sync_on_save' => isset($meili['sync_on_save']) && (string)$meili['sync_on_save'] === '0' ? '0' : '1',
            'search_only_wd' => isset($meili['search_only_wd']) && (string)$meili['search_only_wd'] === '0' ? '0' : '1',
        ];
        if ($row['index_uid'] === '') {
            // 清空时派生本站唯一名，绝不回落到会串库的共享默认名
            $row['index_uid'] = MeilisearchService::defaultIndexUid();
        }
        $newKey = isset($meili['api_key']) ? trim((string)$meili['api_key']) : '';
        if ($newKey !== '') {
            $row['api_key'] = $newKey;
        } else {
            $latest = is_file(APP_PATH . 'extra/maccms.php') ? include APP_PATH . 'extra/maccms.php' : [];
            if (isset($latest['meilisearch']['api_key']) && trim((string)$latest['meilisearch']['api_key']) !== '') {
                $row['api_key'] = (string)$latest['meilisearch']['api_key'];
            } else {
                $row['api_key'] = isset($cfgOld['meilisearch']['api_key']) ? (string)$cfgOld['meilisearch']['api_key'] : '';
            }
        }
        $cfgNew['meilisearch'] = $row;
        $res = mac_arr2file(APP_PATH . 'extra/maccms.php', $cfgNew);
        if ($res === false) {
            return json(['code' => 0, 'msg' => lang('save_err')]);
        }
        return json(['code' => 1, 'msg' => lang('save_ok')]);
    }

    /**
     * 一键自检：Meilisearch 健康、索引统计、OpenCC 可用性、示例查询。
     */
    public function selfcheck()
    {
        $cfg = MeilisearchService::cfg();
        $health = MeilisearchService::health();
        $enabled = MeilisearchService::enabled();
        $opencc = OpenccConverter::available();
        $sampleQuery = trim((string)\think\facade\Request::param("wd", ""));
        if ($sampleQuery === '') {
            $rawHot = (string)($GLOBALS['config']['app']['search_hot'] ?? '');
            $rawHot = str_replace('，', ',', $rawHot);
            $first = trim((string)strtok($rawHot, ','));
            $sampleQuery = $first !== '' ? $first : '测试';
        }

        $stats = ['ok' => false, 'status' => 0, 'data' => null];
        $sampleSearch = ['ok' => false, 'status' => 0, 'data' => null];
        $settingsCheck = ['ok' => false, 'filterableAttributes' => [], 'searchableAttributes' => []];
        $filteredSearch = ['ok' => false, 'status' => 0, 'data' => null];
        if ($enabled) {
            $gs = MeilisearchService::getSettings();
            if (!empty($gs['ok']) && is_array($gs['data'])) {
                $settingsCheck = MeilisearchService::verifyIndexSettings($gs['data']);
            }
            $uid = rawurlencode(MeilisearchService::indexUid());
            $stats = MeilisearchHttp::request(
                MeilisearchService::host(),
                'GET',
                '/indexes/' . $uid . '/stats',
                MeilisearchService::apiKey(),
                null,
                MeilisearchService::timeout(),
                MeilisearchService::sslVerify()
            );
            $sampleSearch = MeilisearchHttp::request(
                MeilisearchService::host(),
                'POST',
                '/indexes/' . $uid . '/search',
                MeilisearchService::apiKey(),
                ['q' => $sampleQuery, 'limit' => 5],
                MeilisearchService::timeout(),
                MeilisearchService::sslVerify()
            );
            $filteredSearch = MeilisearchService::search(
                $sampleQuery,
                MeilisearchService::filterPublishedKind('vod'),
                5,
                0
            );
        }

        return json([
            'code' => 1,
            'msg' => 'ok',
            'data' => [
                'cfg' => [
                    'enabled' => !empty($cfg['enabled']) ? 1 : 0,
                    'host' => (string)($cfg['host'] ?? ''),
                    'index_uid' => (string)($cfg['index_uid'] ?? ''),
                    'timeout' => (int)($cfg['timeout'] ?? 0),
                    'ssl_verify' => isset($cfg['ssl_verify']) && (string)$cfg['ssl_verify'] === '0' ? 0 : 1,
                ],
                'health' => $health,
                'settings_check' => $settingsCheck,
                'index_stats' => [
                    'ok' => !empty($stats['ok']),
                    'status' => (int)($stats['status'] ?? 0),
                    'data' => $stats['data'] ?? null,
                    'error' => (string)($stats['error'] ?? ''),
                ],
                'opencc' => [
                    'available' => $opencc ? 1 : 0,
                    'sample_s2t' => OpenccConverter::s2t('软件'),
                    'sample_t2s' => OpenccConverter::t2s('軟件'),
                ],
                'sample_query' => $sampleQuery,
                'sample_search' => [
                    'ok' => !empty($sampleSearch['ok']),
                    'status' => (int)($sampleSearch['status'] ?? 0),
                    'data' => $sampleSearch['data'] ?? null,
                    'error' => (string)($sampleSearch['error'] ?? ''),
                ],
                'filtered_search' => [
                    'ok' => !empty($filteredSearch['ok']),
                    'filter' => MeilisearchService::filterPublishedKind('vod'),
                    'estimatedTotalHits' => (int)($filteredSearch['estimatedTotalHits'] ?? 0),
                    'hits' => $filteredSearch['hits'] ?? [],
                ],
            ],
        ]);
    }

    /**
     * 版本检查（只读）：回显 Meili 当前运行版本 + GitHub 最新稳定版 + 该在服务器上执行的升级命令。
     * 不从网站执行任何系统级升级（升级请在服务器跑 deploy/meilisearch/meilisearch.sh upgrade）。
     */
    public function versioncheck()
    {
        $current = '';
        if (MeilisearchService::enabled()) {
            $uid = MeilisearchService::indexUid();
            $r = MeilisearchHttp::request(
                MeilisearchService::host(),
                'GET',
                '/version',
                MeilisearchService::apiKey(),
                null,
                MeilisearchService::timeout(),
                MeilisearchService::sslVerify()
            );
            if (!empty($r['ok']) && is_array($r['data'] ?? null)) {
                $current = (string)($r['data']['pkgVersion'] ?? '');
            }
        }
        $latest = $this->fetchLatestMeiliVersion();
        $upgrade = $current !== '' && $latest !== '' && version_compare(ltrim($current, 'v'), ltrim($latest, 'v'), '<');
        $cmdDefault = 'cd deploy/meilisearch && sudo bash meilisearch.sh upgrade';
        $cmdLatest = $latest !== ''
            ? 'cd deploy/meilisearch && sudo MEILI_VERSION=v' . ltrim($latest, 'v') . ' bash meilisearch.sh upgrade'
            : '';

        return json([
            'code' => 1,
            'msg' => 'ok',
            'data' => [
                'enabled' => MeilisearchService::enabled() ? 1 : 0,
                'current' => $current,
                'latest' => $latest,
                'upgrade_available' => $upgrade ? 1 : 0,
                'command_pinned' => $cmdDefault,
                'command_latest' => $cmdLatest,
                'note' => $latest === ''
                    ? '无法连接 GitHub 获取最新版本（可能网络受限）。可在服务器上运行：cd deploy/meilisearch && sudo bash meilisearch.sh status'
                    : '升级为系统级操作，请在服务器上执行上述命令（脚本会自动 dump 老数据并迁移）。',
            ],
        ]);
    }

    /**
     * 取 Meilisearch GitHub 最新稳定版 tag（短超时 + 缓存 1 小时 + 失败返回空，绝不阻塞后台）。
     */
    private function fetchLatestMeiliVersion()
    {
        $cacheKey = 'meili_latest_release';
        $cached = cache($cacheKey);
        if (is_string($cached) && $cached !== '') {
            return $cached;
        }
        $raw = '';
        if (function_exists('curl_init')) {
            $ch = curl_init('https://api.github.com/repos/meilisearch/meilisearch/releases/latest');
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
            curl_setopt($ch, CURLOPT_TIMEOUT, 8);
            curl_setopt($ch, CURLOPT_USERAGENT, 'maccms-meili-version-check');
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/vnd.github+json']);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
            $raw = (string)@curl_exec($ch);
            curl_close($ch);
        }
        $ver = '';
        if ($raw !== '') {
            $j = json_decode($raw, true);
            if (is_array($j) && !empty($j['tag_name'])) {
                $ver = ltrim((string)$j['tag_name'], 'v');
                $ver = preg_replace('/[^0-9.]/', '', $ver);
            }
        }
        if ($ver !== '') {
            cache($cacheKey, $ver, 3600);
        }
        return (string)$ver;
    }

    /**
     * 一键初始化索引：建索引 + PATCH filterable/searchable 等 settings（无需全量同步）。
     */
    public function setup()
    {
        if (!request()->isPost() && !request()->isAjax()) {
            return json(['code' => 0, 'msg' => lang('param_err')]);
        }
        if (!MeilisearchService::enabled()) {
            return json(['code' => 0, 'msg' => lang('admin/meilisearch/setup_disabled')]);
        }
        $r = MeilisearchService::bootstrapIndex();
        return json([
            'code' => !empty($r['ok']) ? 1 : 0,
            'msg' => !empty($r['ok']) ? lang('admin/meilisearch/setup_ok') : ((string)($r['msg'] ?? lang('admin/meilisearch/setup_failed'))),
            'data' => $r,
        ]);
    }

    /**
     * 全量重建索引（视频、文章、漫画、专题、演员、角色、网址等已发布且未进回收站；含回收站字段的模块按字段过滤）。
     */
    public function sync()
    {
        if (request()->isPost() || request()->isAjax()) {
            $r = MeilisearchSync::fullReindex();
            return json($r);
        }
        $this->assign('tip', lang('admin/meilisearch/sync_tip'));
        return $this->fetch('admin@meilisearch/sync');
    }
}
