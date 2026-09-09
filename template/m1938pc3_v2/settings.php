<?php
// Public theme settings. Keep site-specific endpoints together; no credentials belong here.
return [
    'version' => '20260909.5',
    'name' => '杏吧资源站',
    'permanent' => 'www.sex8zy.com',
    'mirrors' => array_map(static fn ($n) => 'sex8zy' . $n . '.com', range(1, 9)),
    'json' => 'https://json.xingba222.com/api.php/provide/vod/',
    'json_backup' => 'https://json.xgbbk8.com/api.php/provide/vod/',
    'xml' => 'https://xingba222.com/api.php/provide/vod/at/xml',
    'xml_backup' => 'https://api.xgbbk8.com/api.php/provide/vod/at/xml',
    'parser' => 'https://xbxbw888.com/?url=',
    'parser_legacy' => 'https://xbww888.com/?url=',
    'art_api' => 'https://sex8zy1.com/api.php/provide/art/?ac=list',
    'player' => 's8m3u8',
    'player_download' => 'https://xingba111.com/template/help/bfq/mac_sex8zy.zip',
    'migration' => 'https://sex8zy1.com/1.html',
    'group' => 'https://t.me/xbxbxbzy',
    'channel' => 'https://t.me/xbww888',
    'play_help' => 'https://p3-tt.byteimg.com/obj/tos-cn-i-jcdsk5yqko/a77e5de21b004c8f9262f53b2482e956',
];
