<?php
// +----------------------------------------------------------------------
// | 路由设置
// +----------------------------------------------------------------------
//
// 本文件【只声明确实需要偏离包内默认值的键】。think\Route::__construct 里做的是
//     $this->config = array_merge($this->config, $config->get('route'));
// (vendor/topthink/framework/src/think/Route.php:158)
// 也就是说这里没写的键一律沿用包内默认值,不会因为新建了这个文件而被重置。
//
// —— 为什么放在配置文件而不是 AppInit 里 Config::set ——
// config/*.php 在 App::load() 期就加载完了,早于 Route 实例化;而中间件跑在
// Route 构造之后,那时再 Config::set('route') 已经晚了(与 session 组是同一类时序问题)。
//
// ⚠ 关于 url_common_param:**故意不在这里声明**,保持包内默认的 true。
// TP5 侧是 false,清单也把"恢复 false"列为待办,但实测证明在 TP8 上恢复它是【有害】的:
//   · 恢复后 mac_url('vod/show', 筛选参数) 产出
//         /vodshow/6/by/time/order/desc/page/2.html
//   · 而 application/index/route/web.php:36 的规则是
//         Route::any('vodshow/<id>','vod/show')->pattern(['id' => '[^-]+'])
//     `[^-]+` 能吃下整串斜杠,叠加 route_complete_match=false(Route.php:64,正则不加 $ 锚),
//     该规则会把整条尾巴吞进 id。实测解析结果:
//         今天(query 形态) /vodshow/6.html?by=time&order=desc&page=2
//                          => {"by":"time","id":"6","order":"desc","page":"2"}   ✅
//         恢复后(路径形态) /vodshow/6/by/time/order/desc/page/2.html
//                          => {"id":"6\/by\/time\/order\/desc\/page\/2"}          ❌ 筛选与分页全丢
// 也就是说:这不是"改 URL 形状要付 SEO 代价"的取舍,而是一个配置开关会把目前
// 唯一还工作的筛选/分页链接直接改坏。真要恢复 TP5 形状,必须连
// application/index/route/web.php 的规则一起重写(给 vodshow/<id> 加完全匹配,
// 或补齐斜杠形态的多变量规则),那是路由表重写,不属于配置层。
// 结论记在这里,免得下次又被人"照清单补上"。

return [
    // TP5 侧是 'html|htm|shtm|shtml|xml'(application/config.php:86),TP8 包内默认只有 'html'。
    //
    // 这个键【只影响入站解析】(Route::path() 在匹配前剥后缀),不影响 URL 生成 ——
    // 生成走 think\route\Url::parseSuffix,取的是 '|' 前的第一项,依然是 'html'。
    // 实测:声明前后 mac_url() / Route::buildUrl() 对全部用例的输出逐字节相同。
    //
    // 不声明它的后果:'.xml' 不被剥离,/rss.xml 的 path 保持 'rss.xml',
    // 自动分发去找控制器 `Rss.xml` → 不存在 → 404。而 /rss.xml 与 /map.xml 正是
    // TP5 时代对外公布、被搜索引擎收录并持续抓取的 feed / sitemap 地址
    // (application/index/controller/Rss.php 构造函数发的就是 Content-Type: text/xml)。
    // 实测:声明后 /rss.xml → rss/index、/map.xml → map/index,恢复 200。
    'url_html_suffix' => 'html|htm|shtm|shtml|xml',
];
