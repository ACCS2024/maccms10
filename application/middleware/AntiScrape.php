<?php
namespace app\middleware;

use app\common\util\SlidingWindowIpLimiter;
use think\exception\HttpResponseException;

class AntiScrape
{
    public function handle($request, \Closure $next)
    {
        if (PHP_SAPI === 'cli') {
            return $next($request);
        }
        $app = isset($GLOBALS['config']['app']) && is_array($GLOBALS['config']['app'])
            ? $GLOBALS['config']['app']
            : [];

        if (defined('ENTRANCE') && ENTRANCE === 'index') {
            $this->runIndexAjax($request, $app);
        }
        if (defined('ENTRANCE') && ENTRANCE === 'api') {
            $this->runApi($request, $app);
        }

        return $next($request);
    }

    private function runIndexAjax($request, array $app): void
    {
        if (empty($app['anti_scrape_index_enabled']) || (string)$app['anti_scrape_index_enabled'] !== '1') {
            return;
        }
        $pi = strtolower(trim((string)$request->pathinfo(), '/'));
        if ($pi !== '' && strpos($pi, 'install') === 0) {
            return;
        }
        [$c, $a] = $this->pathControllerAction($request);
        if ($c !== 'ajax') {
            return;
        }
        $hits = ['suggest', 'data', 'search_hot', 'search_history'];
        if (!in_array($a, $hits, true)) {
            return;
        }
        $window = isset($app['anti_scrape_index_window_sec']) ? (int)$app['anti_scrape_index_window_sec'] : 60;
        $max    = isset($app['anti_scrape_index_max'])        ? (int)$app['anti_scrape_index_max']        : 90;
        $ip     = (string)mac_get_client_ip();
        $r      = SlidingWindowIpLimiter::checkHit($ip, 'ix_' . $a, $window, $max);
        if (!$r['allowed']) {
            $this->denyIndex($r['retry_after']);
        }
    }

    private function runApi($request, array $app): void
    {
        if (empty($app['anti_scrape_api_enabled']) || (string)$app['anti_scrape_api_enabled'] !== '1') {
            return;
        }
        [$c, $a] = $this->pathControllerAction($request);
        $route = $c . '/' . $a;
        if ($route === '/' || $c === '') {
            return;
        }

        $exempt     = ['timming/index'];
        $extra      = isset($app['anti_scrape_api_exempt']) ? trim((string)$app['anti_scrape_api_exempt']) : '';
        if ($extra !== '') {
            foreach (explode(',', $extra) as $one) {
                $one = strtolower(trim(str_replace('\\', '/', $one)));
                if ($one !== '') {
                    $exempt[] = $one;
                }
            }
        }
        $exemptCtrl = ['provide', 'receive'];
        if (in_array($route, array_unique($exempt), true) || in_array($c, $exemptCtrl, true)) {
            return;
        }

        $ip  = (string)mac_get_client_ip();
        $gw  = isset($app['anti_scrape_api_window_sec']) ? (int)$app['anti_scrape_api_window_sec'] : 60;
        $gm  = isset($app['anti_scrape_api_max'])        ? (int)$app['anti_scrape_api_max']        : 120;
        $r1  = SlidingWindowIpLimiter::checkHit($ip, 'api_all', $gw, $gm);
        if (!$r1['allowed']) {
            $this->denyApi($r1['retry_after']);
        }

        if ($this->apiSearchHeavy($request)) {
            $sw = isset($app['anti_scrape_api_search_window_sec']) ? (int)$app['anti_scrape_api_search_window_sec'] : 60;
            $sm = isset($app['anti_scrape_api_search_max'])        ? (int)$app['anti_scrape_api_search_max']        : 30;
            $r2 = SlidingWindowIpLimiter::checkHit($ip, 'api_search', $sw, $sm);
            if (!$r2['allowed']) {
                $this->denyApi($r2['retry_after']);
            }
        }
    }

    private function pathControllerAction($request): array
    {
        $pi    = strtolower(trim((string)$request->pathinfo(), '/'));
        $pi    = (string)preg_replace('/\.(html|htm)$/i', '', $pi);
        $parts = array_values(array_filter(explode('/', $pi), static fn($p) => $p !== ''));
        if (count($parts) >= 2) {
            return [strtolower($parts[0]), strtolower($parts[1])];
        }
        if (count($parts) === 1) {
            return [strtolower($parts[0]), 'index'];
        }
        return ['', ''];
    }

    private function apiSearchHeavy($request): bool
    {
        if (trim((string)$request->param('wd', '')) !== '') {
            return true;
        }
        $keys = [
            'vod_name', 'art_name', 'actor_name', 'website_name', 'manga_name', 'topic_name',
            'vod_actor', 'vod_director', 'vod_blurb', 'art_tag', 'vod_tag',
        ];
        foreach ($keys as $k) {
            if (trim((string)$request->param($k, '')) !== '') {
                return true;
            }
        }
        return false;
    }

    private function denyApi(int $retryAfter): void
    {
        $retryAfter = max(1, $retryAfter);
        $msg = function_exists('lang')
            ? sprintf(lang('anti_scrape/rate_limited'), $retryAfter)
            : ('Too many requests, retry after ' . $retryAfter . ' seconds');
        throw new HttpResponseException(json([
            'code' => 100429,
            'msg'  => $msg,
            'data' => ['retry_after' => $retryAfter],
        ], 429, ['Retry-After' => (string)$retryAfter]));
    }

    private function denyIndex(int $retryAfter): void
    {
        $retryAfter = max(1, $retryAfter);
        $msg = function_exists('lang')
            ? sprintf(lang('anti_scrape/rate_limited'), $retryAfter)
            : ('Too many requests, retry after ' . $retryAfter . ' seconds');
        throw new HttpResponseException(json([
            'code' => 100429,
            'msg'  => $msg,
            'data' => ['retry_after' => $retryAfter],
        ], 429, ['Retry-After' => (string)$retryAfter]));
    }
}
