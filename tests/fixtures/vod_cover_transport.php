<?php
/** Ordinary provider replies; curl still runs the real public HTTP policy, without an external request. */
namespace app\common\util {
    function curl_setopt_array($handle, $options) {
        if (!isset($GLOBALS['cover_http_response'])) { return \curl_setopt_array($handle, $options); }
        $GLOBALS['cover_http_options'] = $options;
        return true;
    }
    function curl_exec($handle) {
        if (!isset($GLOBALS['cover_http_response'])) { return \curl_exec($handle); }
        \check(!\think\facade\Db::connect()->getPdo()->inTransaction(), 'Image generation held a DB transaction');
        $GLOBALS['cover_http_calls']++;
        if (isset($GLOBALS['cover_http_hook'])) { ($GLOBALS['cover_http_hook'])(); }
        $options = $GLOBALS['cover_http_options'];
        $options[CURLOPT_HEADERFUNCTION]($handle, "HTTP/1.1 200 OK\r\n");
        $body = $GLOBALS['cover_http_response'];
        return $options[CURLOPT_WRITEFUNCTION]($handle, $body) === strlen($body);
    }
    function curl_getinfo($handle, $option = null) {
        if (!isset($GLOBALS['cover_http_response'])) { return \curl_getinfo($handle, $option); }
        return $option === CURLINFO_PRIMARY_IP ? '1.1.1.1' : 200;
    }
    class MeilisearchSync {
        public static function afterVodSave($id): void {
            \check(!\think\facade\Db::connect()->getPdo()->inTransaction(), 'Search sync ran before commit');
            if (!empty($GLOBALS['cover_maintenance_fail'])) { throw new \RuntimeException('fixture private index credential'); }
        }
    }
}
