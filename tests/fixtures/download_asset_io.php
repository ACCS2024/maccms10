<?php
/** Only ordinary download bytes and a provider's ordinary JSON reply are substituted. */
namespace app\common\model {
    function mac_is_safe_remote_url($url) { return \app\common\util\PublicHttpClient::resolve($url)!==null; }
    function mac_curl_get($url) {
        if (!array_key_exists($url,$GLOBALS['download_asset_bytes'])) { throw new \RuntimeException('Unexpected fixture download'); }
        $GLOBALS['download_asset_calls']++;
        return $GLOBALS['download_asset_bytes'][$url];
    }
}
namespace app\common\extend\upload {
    function json_decode($json,$associative=null,$depth=512,$flags=0) {
        $result=\json_decode($json,$associative,$depth,$flags);
        if (isset($GLOBALS['download_asset_image_url']) && is_array($result) && isset($result['imgurl'])) {
            $result['imgurl']=$GLOBALS['download_asset_image_url'];
        }
        return $result;
    }
}
