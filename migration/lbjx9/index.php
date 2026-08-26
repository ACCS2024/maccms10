declare(strict_types=1);

$source = trim((string)($_GET['url'] ?? ''));
$parts = $source !== '' ? parse_url($source) : false;
$scheme = is_array($parts) ? strtolower((string)($parts['scheme'] ?? '')) : '';
$validSource = $source !== '' && filter_var($source, FILTER_VALIDATE_URL) !== false
    && in_array($scheme, ['http', 'https'], true);
$sourceJson = json_encode(
    $validSource ? $source : '',
    JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES
);
?>
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
    <title>播放器</title>
    <link rel="stylesheet" href="https://g.alicdn.com/de/prismplayer/2.9.3/skins/default/aliplayer-min.css">
    <script src="https://g.alicdn.com/de/prismplayer/2.9.3/aliplayer-min.js"></script>
    <script src="https://player.alicdn.com/aliplayer/presentation/js/aliplayercomponents.min.js"></script>
    <style>
        html, body { width: 100%; height: 100%; margin: 0; overflow: hidden; background: #000; }
        #player { width: 100%; height: 100%; }
        #message { color: #fff; font: 16px/1.6 sans-serif; padding: 24px; }
    </style>
</head>
<body>
<div id="player"></div>
<div id="message" hidden>播放地址无效</div>
<script>
const source = <?= $sourceJson ?: '""' ?>;
if (source) {
    new Aliplayer({
        id: 'player',
        source,
        width: '100%',
        height: '100%',
        autoplay: true,
        preload: true,
        rePlay: false,
        playsinline: false,
        useH5Prism: false,
        isLive: false
    });
} else {
    document.getElementById('message').hidden = false;
}
</script>
</body>
</html>
