# maccms10 性能优化空间分析(基于真实代码,附 文件:行)

> 立场:本文只做**性能**梳理,所有"问题"均落代码核实并标注证据;按 **影响×风险** 排序,给方案与权衡。
> 已落地的(P1 复合索引 / P2 Meili API / P3 采集同步 / P4 设置自动同步 / P5 InnoDB 按钮 + 清理冗余索引)不再重复,只在相关处引用。

---

## 0. 结论先行(最值得做的三件事)
1. **`update_hits` 每次播放"读-改-写" mac_vod + MyISAM 表锁** → 这是高并发下"卡顿/故障多"的**头号瓶颈**(`api/controller/Vod.php:691,722`)。先转 InnoDB(P5 已提供按钮),再把计数改为**原子自增**,最终用 **Redis 计数缓冲 + 定时落库**彻底移除每播一次写库。
2. **缓存后端用文件(`cache_type='file'`)**(`extra/maccms.php:52`)→ 切 **Redis**(后台可切,无需改码),列表/详情/计数/会话/限流全受益;高 QPS 下文件缓存的 `flock`/`stat` 自身就是瓶颈。
3. **会话用文件存储** → 切 Redis,去除 `session` 文件锁导致的同用户请求串行化。

---

## 1. 写入与并发(对"故障多/锁表"影响最大)

### A1. 播放量更新:每播一次都"读整行→改→写回",且 MyISAM 表级锁 ★★★★★
- **证据**:`api/controller/Vod.php:684-726` — `update_hits()` 先 `infoData()` 读 `vod_hits/_day/_week/_month/_time_hits`(:691),算好后 `model('Vod')->where(...)->update($update)`(:722)。`up/down` 用 `setInc`(:750-751)。
- **问题**:
  1. **MyISAM 表锁**:每次 UPDATE 锁整张 `mac_vod`,阻塞所有读/写;播放高峰期请求排队 → 直接表现为"卡死/故障多"。
  2. **读-改-写非原子**:并发播放会**丢增量**(覆盖写),热门片计数偏低。
  3. **放大写**:`mac_vod` 上 30+ 单列索引(`vod_hits/_day/_week/_month` 都各有索引),每次 UPDATE 要维护多个索引。
- **方案(按代价递增)**:
  1. **转 InnoDB**(P5 按钮):表锁→行锁,立竿见影。**先做这个。**
  2. **改原子自增**:`vod_hits` 用 `setInc('vod_hits')`;日/周/月跨期重置用一条带 `CASE WHEN` 的条件 UPDATE(把"是否同日/同周/同月"判断下推到 SQL),省掉 :691 的 SELECT,并消除竞态。
  3. **Redis 计数缓冲**:播放时 `INCR vod_hits:{id}` 等(O(1) 内存),由定时任务(已有 `Timming`)每 N 分钟批量 `flush` 回库。**彻底移除"每播一次写库"**,QPS 上限提升一个量级。
- **风险**:方案 2/3 需小心日/周/月归零逻辑;Redis 缓冲需容忍"计数延迟几分钟"(对播放量完全可接受)。

### A2. 采集逐条 insert + 索引写放大 ★★★☆☆
- **证据**:`common/model/Collect.php` 各类 `model('X')->insert($v,...)`(vod :946 等);`mac_vod` 35 个单列索引(`install/sql/install.sql`)。
- **问题**:MyISAM 下批量采集 = 大量行锁表 + 每行维护 35 索引;P3 又给每条加了 Meili 同步(Meili 开时)。
- **方案**:① InnoDB(P5);② 已提供"清理冗余索引"按钮删最左前缀重复(P5+);③ Meili 同步在大批量采集时可改"入队批量推送"而非逐条(见 F2);④ 可选 `insertAll` 批量入库(需先解决去重等值查 `vod_name=`,见下)。
- **注意**:采集去重靠 `vod_name=`/`vod_director=` 等值查(`Collect.php:772,796`),这些**单列索引必须保留**(不是冗余),否则去重变全表扫。

---

## 2. 缓存

### B1. 缓存后端 = 文件 → 切 Redis ★★★★☆
- **证据**:`extra/maccms.php:52 'cache_type'=>'file'`;`cache_core=1`(:59)、`cache_time=3600`(:60)。后台「系统配置」可改 `cache_type`(无需改码)。
- **问题**:文件缓存在高并发下 `open/stat/flock/unlink` 自身成为瓶颈,且无法跨机共享(多机部署各存各的)、无原子操作(`api/Search.php` 的限流在非 Redis 时退化为非原子)。
- **方案**:后台把 `cache_type` 切 **Redis**。列表(`listCacheData`)、详情(`infoData`)、类目/用户组 `getCache`、搜索限流、播放计数缓冲全部受益。代码已具备 Redis 路径(`api/Search.php:104-111` 已对 Redis handler 做原子 `INCR`)。
- **风险**:需部署 Redis;键空间与 `cache_flag` 已隔离,切换平滑。

### B2. 会话文件存储 → Redis ★★★★☆
- **问题**:PHP 默认文件 session 有**写锁**:同一用户(同 session)的并发请求会**串行**等待 `session` 文件锁;前台播放页常并行发若干 ajax(计数/弹幕/推荐),会互相阻塞。
- **方案**:`session.save_handler=redis`(php.ini 或框架 session 配置)。登录态、验证码、购物车等都受益。
- **风险**:低;Redis 已为 B1 部署即可复用。

### B3. 缓存击穿/雪崩(同 key 并发回源)★★★☆☆
- **证据**:`listCacheData`(`model/Vod.php:617-635`)`Cache::get` 未命中即直查 DB 再 `Cache::set`,无"单飞/加锁"。
- **问题**:热门列表缓存到期瞬间,大量请求同时回源打 DB(尤其那条 `count(*)`),形成尖刺;大量 key 同时过期则雪崩。
- **方案**:① 缓存 TTL 加随机抖动(防同时过期);② 热点 key 加互斥锁(`Cache::set(lock)` 单飞回源)或逻辑过期(返回旧值后台刷新);③ 配合 B1 的 Redis 更易实现。
- **风险**:中;改 `listCacheData` 公共路径需充分回归。

### B4. 详情页缓存仅对等值查生效,翻页/筛选列表 total 反复算
- **证据**:`infoData`(`model/Vod.php:642-660`)仅当 `vod_id`/`vod_en` 等值才 `data_cache=true` 缓存;`listData` 每次算 `count(*)`(:66)。见 C1。

---

## 3. 查询层

### C1. 深翻页的 `COUNT(*)` ★★★☆☆
- **证据**:`listData`(`model/Vod.php:64-66`)`if($totalshow==1) $total = count()`;`getCountByCond`(`model/Base.php:31-37`)。
- **问题**:带 `WHERE vod_status=1 AND recycle=0 [AND type_id=..]` 的 `COUNT(*)`,InnoDB 下要扫整段索引;深翻页/大库每次都贵。列表结果走 `listCacheData` 缓存可摊薄,但 `cache_core=0`、登录态或筛选组合爆炸时仍直打。
- **方案**:① 列表与 total **分离缓存**,total 单独长 TTL;② 超大库用**近似 total**(`information_schema` 估算或 Meili 的 `estimatedTotalHits`)+ "只显示前 N 页";③ 改**游标分页**(`WHERE vod_id < lastId ORDER BY vod_id DESC LIMIT n`,配合 P1 复合索引)替代 `LIMIT offset,n` 的大 offset 扫描。
- **风险**:游标分页改 UI/路由契约,中等;近似 total 影响分页页码精度。

### C2. `recycle_time=0` 残余过滤未进复合索引 ★☆☆☆☆
- **证据**:`mergeRecycleWhere`(`RecycleBinTrait.php:63-65`)给每个前台查询追加 `vod_recycle_time=0`;P1 复合索引未含该列。
- **问题**:理论上 `recycle_time=0` 是索引外的残余过滤(逐行判断)。但**实际几乎所有行 recycle=0**,过滤几乎不淘汰行 → 代价极低。
- **方案**:可不做。若要极致,可把 `recycle_time` 并入热点复合索引尾列做覆盖;收益很小、不建议优先。

### C3. `tag/class/actor` 仍是 `LIKE '%kw%'` 全表扫 ★★☆☆☆
- **证据**:`api/controller/Vod.php:62-95`(tag/class/actor LIKE)、前台同理。关键词(name)已由 **P2/Meili** 接管,但 tag/class/actor 过滤仍 LIKE。
- **问题**:前导 `%` 通配,B-tree 索引用不上 → 全表扫(大库慢)。
- **方案**:① 高频 `tag` 过滤可改 Meili filterable(把 `tags` 已是 searchable 升级为 filterable + 文档已含 `tags`,需 fullReindex);② 或维护 `vod_tag` 的规范化关联表(tag↔vod)做等值 join。
- **风险**:中;Meili filterable 改动需重建索引(P4 的自动设置同步可覆盖)。

### C4. 列表查询回表(覆盖索引)★★☆☆☆
- **证据**:`listData` 取 `vod_id,vod_name,vod_pic,...` 十余列(`api/Vod.php:107`),P1 复合索引仅含过滤+排序列 → 命中索引后仍需回表取这十几列。
- **方案**:对最热的"首页/分类列表"可建**覆盖索引**(把列表所需列并入索引尾部)。但列多会显著增大索引、加重写放大(与 A2 矛盾)。**建议仅对 1~2 个最热查询、且列裁剪到极简时考虑**,否则得不偿失。
- **风险**:中高(写放大);需 EXPLAIN 实测确认 `Using index`。

---

## 4. 前台渲染与产出

### D1. 静态化(make/generate)vs 动态 ★★★☆☆
- **证据**:后台有"生成"(`make`)模块产出静态 HTML;动态访问走模板标签解析(`taglib/Maccms`)。
- **问题**:动态页每次解析自定义标签 + 多次 `getCache`/查询;高流量站纯动态成本高。
- **方案**:① 高流量首页/列表/详情用**静态生成 + CDN**;② 或开**页面级缓存** `cache_time_page`(:62);③ 模板编译缓存确保开启(TP 默认开)。
- **风险**:静态化有更新延迟;CDN 需回源策略。

### D2. 图片与静态资源 ★★☆☆☆
- **方案**:封面图 **懒加载 + WebP + CDN**;`mac_url_img` 出口接 CDN 域名;开启 HTTP 缓存头(`crossdomain` 已在安全轮收紧,注意别影响 CDN)。
- **风险**:低;纯前端/部署层。

---

## 5. 运行时 / 部署

### E1. OPcache 必开 ★★★★☆
- **问题**:722 个 PHP 文件,未开 OPcache 则每请求重复编译 → CPU 浪费、延迟高。
- **方案**:`opcache.enable=1`、`opcache.validate_timestamps=0`(生产,部署后 reload)、足够 `opcache.memory_consumption`。**几乎零风险、收益巨大**。
- **备注**:docker 镜像(`php:7.4-apache`)默认未必开,部署需显式启用。

### E2. PHP 7.4 → 8.1+ ★★★☆☆
- **问题**:框架 ThinkPHP 5.0.24 较老;PHP 8.x(JIT/性能)比 7.4 快可观,且 7.4 已 EOL(安全)。
- **方案**:评估 TP5.0 在 PHP 8.x 的兼容性(本仓多处已用 `\Throwable`,基本兼容),逐步升 8.1。
- **风险**:中;需全量回归(老框架 + 8.x 的弃用项)。

### E3. DB 连接 ★★☆☆☆
- **方案**:开启持久连接 / 连接池(`database.php` 的 `params` 加 `PDO::ATTR_PERSISTENT`,谨慎);MySQL 侧调 `innodb_buffer_pool_size`(转 InnoDB 后尤其重要,建议物理内存 50–70%)。
- **风险**:持久连接易引入连接状态问题,需评估。

---

## 6. Meilisearch(P2~P4 之后的余量)

### F1. `estimatedTotalHits` 非精确 ★★☆☆☆
- **证据**:`MeilisearchListBridge::applyForVod` 用 `estimatedTotalHits` 作 total(:55)。
- **问题**:深翻页页码可能轻微偏差。
- **方案**:需要精确 total 时回表 `count(命中ID)`(命中集合通常不大);或文档化"搜索结果总数为估算"。

### F2. 采集大批量逐条同步 Meili ★★★☆☆
- **证据**:P3 在每条采集 insert/update 后 `afterXSave`(Meili 开时各发一次 HTTP `addDocuments`)。
- **问题**:首次全站采集(成千上万条)= 成千上万次 HTTP 任务,拖慢采集、压 Meili。
- **方案**:采集期把待同步 ID **入队**(Redis list / 内存累积),按批 `addDocuments([...])` 一次推数百条;或采集大批量时**跳过增量、采后一键全量重建**(`admin/Meilisearch::sync` 已有)。
- **风险**:中;需改 P3 的同步为"可批量"模式。

---

## 7. 优先级建议(投入产出比)
| 优先 | 项 | 影响 | 风险 | 备注 |
|---|---|---|---|---|
| P0 | E1 OPcache | ★★★★ | 极低 | 部署即得 |
| P0 | B1 缓存切 Redis | ★★★★ | 低 | 后台开关 |
| P0 | A1①转 InnoDB | ★★★★★ | 低 | P5 按钮已就绪 |
| P1 | B2 会话切 Redis | ★★★★ | 低 | 并发串行化 |
| P1 | A1②③ 计数原子化/Redis 缓冲 | ★★★★★ | 中 | 头号写瓶颈 |
| P2 | B3 缓存防击穿 | ★★★ | 中 | 改公共路径需回归 |
| P2 | C1 total/分页优化 | ★★★ | 中 | 大库深翻页 |
| P2 | F2 Meili 批量同步 | ★★★ | 中 | 大批量采集 |
| P3 | C3 tag/class 入 Meili | ★★ | 中 | 需重建索引 |
| P3 | D1/D2 静态化/页面缓存 | ★★★ | 中 | 高流量站 |
| P3 | E2 升 PHP 8 | ★★★ | 中 | 需全量回归 |
| 备选 | C4 覆盖索引 / C2 recycle 入索引 | ★★ | 中高 | 与写放大权衡,实测再定 |

> 说明:本分析在 docker(MySQL 5.7 + PHP 7.4)环境核实代码路径;Redis/Meili 因镜像限流未实测,相关项给出方案与代码依据,落地时按阶段 docker 验证。
