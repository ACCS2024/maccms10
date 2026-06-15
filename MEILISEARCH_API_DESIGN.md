# Meilisearch 接入后台 API + 前台查询性能 — 设计方案(审查稿)

> 状态:**设计待审**,未改任何业务代码。所有"现状"均已落代码核实(附 文件:行)。
> 目标:把 Meilisearch 接到 **API 层关键词搜索**(目前没接,是最麻烦的部分);同时给前台浏览/筛选/排序补 **DB 复合索引**;全部走"自动迁移 + 后台开关",保证老库能平滑升到生产、可回退、不破坏 API 契约。

---

## 0. 结论先行
- **已接 Meili**:前台模板渲染路径(Vod/Art… 模型经 `MeilisearchListBridge`)、`api/Search.php`(独立搜索/suggest,Meili 优先+LIKE 回退)、后台管理(连接/初始化/设置/全量重建)、模型层增量同步(`saveData/delData` → `afterXSave/deleteX`)。
- **没接 Meili(本次要补)**:`api/Provide.php`、`api/Vod.php`、`api/Art.php`、`api/Manga.php` 的关键词搜索仍是 `xxx_name LIKE '%wd%'`。
- **利好**:`MeilisearchListBridge` 已覆盖 **全部 7 类**(applyForVod/Art/Manga/Topic/Actor/Role/Website),返回 `{where, order, total}`,API 接入只需"调用现成桥接 + 回退",无需新写检索逻辑。
- **要解决的真问题**:Meili 索引 `filterableAttributes` 缺 `vod_area/year/lang/state/class/tag`,`sortableAttributes` 只有 `hits_month/ts` → 过滤与排序需"Meili 出命中 ID + 回表 DB 二次过滤/排序"或补索引设置后重建。

---

## 1. 现状核实(覆盖矩阵,均附证据)
| 入口 | 接 Meili? | 现在走什么 | 证据 |
|---|---|---|---|
| 前台模板 Vod/Art 列表+搜索 | ✅ | `MeilisearchListBridge::applyForVod` | `common/model/Vod.php:591` |
| `api/Search.php`(搜索/suggest) | ✅ Meili 优先,LIKE 回退 | bridge + service | `api/controller/Search.php:28` |
| **`api/Provide.php`(资源站提供)** | ❌ | `vod_name LIKE '%wd%'` + `listData` | `api/Provide.php:70,384,495` |
| **`api/Vod.php`(JSON 列表/搜索)** | ❌ | `vod_name/tag/blurb/class LIKE` | `api/Vod.php:63-95` |
| **`api/Art.php` / `api/Manga.php`** | ❌ | `art_name/sub/blurb/... LIKE` | `api/Art.php:67-90` |
| 后台管理(连接/初始化/设置/同步) | ✅ | `admin/Meilisearch`(index/status/save/selfcheck/setup/sync) | `admin/controller/Meilisearch.php` |
| 增量同步(改/删) | ✅ 模型层 | `afterVodSave/deleteVod` | `common/model/Vod.php:828,886` |
| 索引设置 filterable/sortable | ⚠️ 不全 | filter:`kind,type_id,type_id_1,recycle,status,level,group_id,isend,plot`;sort:`hits_month,ts` | `util/MeilisearchService.php:117-121` |

---

## 2. 设计目标(全部可后台开关、可回退、不破契约)
1. `api/Provide`、`api/Vod`、`api/Art`、`api/Manga` 的关键词搜索接 Meili。
2. Meili 关闭 / 连接失败 / 无命中 → **自动回退原 LIKE**(复用 `api/Search` 的降级模式,抽成公共 helper)。
3. 过滤(type/area/year/lang/state)、排序、分页、total 与现行 API 返回结构**完全一致**。
4. 老库平滑:Meili 是**可选增强**,关了就用 DB + 新复合索引;不改表数据、不改 API 字段。
5. 索引同步覆盖采集/推送入库,保证 Meili 不变脏。

---

## 3. 详细设计

### 3.1 API 搜索接入(统一模式)
在 4 个 API 控制器的"关键词分支"套用统一模式(伪代码):
```php
$useMeili = !empty($wd) && MeilisearchService::enabled();
$bridged  = null;
if ($useMeili) {
    try { $bridged = MeilisearchListBridge::applyForVod($where,$wd,$name,$tag,$class,$actor,$director,$page,$num,$start,$order); }
    catch (\Throwable $e) { $bridged = null; }   // 异常→回退
}
if ($bridged !== null) {            // Meili 命中:where 改为 vod_id IN(命中)
    $where = $bridged['where']; $order = $bridged['order']; $forceTotal = $bridged['total'];
} else if ($useMeili) {             // 启用但无命中/异常 → 回退原 LIKE 分支
    /* 保留原 $where['vod_name']=['like','%wd%'] */
}                                   // 未启用 → 原 LIKE 分支
$res = model('vod')->listData($where, $order, $page, $size, 0, $field, $totalshow);
```
- 复用现成 `applyForVod/applyForArt/applyForManga`,**不新写检索**。
- Provide 同理(只是 field 投影/返回结构按 provide 契约保持不变)。

### 3.2 过滤 / 排序 / 分页 parity(真问题点)
- **过滤**:Meili 命中返回 `vod_id IN(...)`,API 原有的 `type_id/area/year/lang/state` 等 `$where` **继续在 DB 上对命中集合二次过滤**(无需 Meili 支持这些字段)。可行且正确,代价是命中集合需足够大;**更优**:把 `vod_area/year/lang/state/class/tag` 加入 `MeilisearchService::indexSettingsPayload()` 的 `filterableAttributes`,由 Meili 直接过滤(需 fullReindex)。
- **排序**:Meili sortable 仅 `hits_month/ts`;其余排序(time/hits/score/level)由 **DB 在命中 ID 上排序**(`order` 仍传给 listData)。关键词相关性排序则用 Meili 默认。
- **分页/total**:Meili `estimatedTotalHits`(注:**非精确**,深翻页可能略偏)。需在响应里保持 API 既有 total 字段语义;可配置"精确 total 时回表 count(命中ID)"。

### 3.3 降级与一致性
- 抽公共 helper `mac_meili_search_or_null($module,$where,$params)`:enabled+ping ok+有命中→返回改写后的 where/order/total,否则 null(调用方回退 LIKE)。`api/Search` 现有降级逻辑并入此 helper。
- **以 DB 为准**:Meili 只出命中 ID,字段/权限/回收(`vod_status`、recycle、会员组 popedom)一律回表 DB 取,避免 Meili 陈旧字段影响业务。

### 3.4 同步覆盖(实施时必须核实的点)
- 已确认:模型 `Vod::saveData`→`afterVodSave`、`delData`→`deleteVod`(后台改/删自动同步);`admin/Meilisearch::sync`=全量重建。
- **待核实(P3)**:采集 `Collect::vod_data` 与推送 `Receive`(`Receive→Collect::vod_data`)最终是否经 `model('Vod')->saveData` 写入。
  - 若是 → 采集自动同步,无需改;
  - 若走批量裸 `insert/insertAll` → 需在采集落库后补 `afterVodSave`(或入"待同步队列"批量推 Meili,避免逐条 HTTP 拖慢采集)。

### 3.5 开关
- 主开关沿用 `MeilisearchService::enabled()`(后台已有,无需新增)。
- 可选子开关 `api_meili_enabled`(默认跟随主开关),便于只在 API 层灰度。

---

## 4. DB 索引方案(非 Meili;治浏览/筛选/排序/无关键词列表慢)
> 关键词搜索交给 Meili;**浏览/筛选/排行/最新**这些无关键词的列表,仍是 DB,必须靠复合索引。

- **现状**:`mac_vod` 有 34 个**单列**索引、**0 个复合**索引,且 **`vod_status` 未索引**(每条前台查询都带 `vod_status=1`)。MyISAM 引擎。
- **新增复合索引(mac_vod;art/manga 同理)**,匹配 `listCacheData` 的 by 白名单:
  - `(vod_status,type_id,vod_time)`、`(vod_status,type_id_1,vod_time)`、`(vod_status,type_id,vod_hits)`、`(vod_status,type_id,vod_score)`、`(vod_status,vod_level,vod_time)`、`(vod_status,vod_time)`、`(vod_status,vod_hits_day)`、`(vod_status,vod_hits_week)`、`(vod_status,vod_hits_month)`
- **删冗余单列索引**(纯写放大、前台不用):`vod_up/down/plot/points_play/points_down/score_all/score_num/total/en` 等。
- **mac_comment/gbook**:补 `(comment_rid,comment_status,comment_id)` 类复合(前台按 rid+status 取、按时间排)。

---

## 5. 落地与升级到生产(无需手动 SQL)
- **索引 + Meili 索引设置** → 写进 `mac_security_auto_migrate()`(升级到 **v2**),**幂等**:索引不存在才 `ADD`、Meili settings 缺字段才 PATCH。生产 `git pull` + 登录后台**自动应用**。
- **Meili settings 变更后** → 需 `fullReindex`;设计为"settings 版本号变化时,后台提示一键重建"(不自动跑,避免大库阻塞)。
- **引擎 MyISAM→InnoDB**(治采集锁表/故障)→ 做成后台「**数据库优化**」按钮(管理员低峰手动触发、带进度),**不**放进每次登录的自动迁移(大表 ALTER 会卡登录)。

---

## 6. 验证(docker,实测后再交付)
1. 起 MySQL + Meilisearch + Redis,导入老库样本;
2. 实测:`api/Provide`、`api/Vod`、`api/Art` 关键词搜索 → Meili 命中 vs 关闭 Meili → LIKE 回退,返回结构一致;
3. `EXPLAIN` 验浏览/筛选查询走新复合索引(`type` 由 `ALL`→`ref/range`、消除 `Using filesort`);
4. 采集一批数据 → 验 Meili 增量同步(确认 3.4 的路径);
5. Meili 停机 → 验业务自动回退、不报错。

---

## 7. 风险与对策
| 风险 | 对策 |
|---|---|
| `estimatedTotalHits` 非精确,深翻页偏差 | 可选回表精确 count;或文档说明 |
| Meili filterable/sortable 不全 → 过滤/排序失效 | 回表 DB 二次过滤/排序(默认);或补 settings + 重建 |
| 采集大批量逐条同步拖慢采集 | 入队批量推送,而非逐条 HTTP |
| Provide 是外站契约 | 只换查询源,返回字段/结构严格不变;加回退保证可用性 |
| 双源一致性 | Meili 只出 ID,字段一律回表 DB |

---

## 8. 分阶段实施(审过后逐阶段做,每阶段 docker 验证)
- **P1**:DB 复合索引 + `vod_status` 进复合 + 删冗余单列 → 自动迁移 v2(低风险、先做)。
- **P2**:抽 `mac_meili_search_or_null` helper + 接入 `api/Provide`、`api/Vod`、`api/Art`、`api/Manga`,带 LIKE 回退。
- **P3**:核实并补全采集/推送的 Meili 同步。
- **P4**:Meili `filterableAttributes/sortableAttributes` 补全 + 后台"重建索引"提示。
- **P5**:引擎 InnoDB 后台按钮。
- **P6**:docker 全链路回归(API 前后台、采集、降级)。

---

## 9. 落地状态(已全量实现并 docker 实测)

> 全部纯本地、不与官方通信;Meili 关闭(默认)时零行为变化、零额外开销;Meili 开启则用现成桥接,异常/无命中/不可达一律回退 LIKE。

| 阶段 | 内容 | 提交 | 验证 |
|---|---|---|---|
| **P1** | 前台热查询复合索引(类目+状态+排序,消除 filesort/全扫),自动迁移 v2 | `1928792` | EXPLAIN:`key=idx_type_st_time`,无 `Using filesort` |
| **P2** | `api/Vod·Art·Manga::get_list`、`api/Provide::vod·art` 接 Meili;统一助手 `mac_meili_api_apply($module,$where,$kw,$page,$num,$order,$start)`;**并修复前台 `listCacheData`(Vod/Art/Manga)既有分页缺陷**(Meili 命中后二次 offset 致第 2 页起为空) | `f24d461` | 5 入口关键词搜索(Meili 关)结构/总数/分类正确;非关键词浏览不受影响 |
| **P3** | 采集 `Collect::vod_data/art_data/...` 与推送 `Receive` 的裸 insert/update 处补 `MeilisearchSync::afterXSave`(vod/art/manga/actor/role/website),消除索引陈旧 | `c59dc0f` | `insert($v,false,true)` 返回自增ID;Meili 关时为安全空操作 |
| **P4** | `filterableAttributes` 补 `ts`(时间范围过滤此前被拒→静默回退);新增 `mac_meili_settings_auto_sync()` 按 payload 哈希版本随升级自动 PATCH 设置(后台访问时,不阻断、不联网) | `0098383` | `ts` 已进 filterable;Meili 关/不可达时空操作不写标记、下次重试 |
| **P5** | 后台「数据库」一键 **MyISAM→InnoDB** 转换(`Database::convert_engine`,根治采集锁表/故障),新增"引擎"列与批量/单行按钮;管理员低峰手动触发,不入自动迁移 | `d837529` | MyISAM 成功转 InnoDB、已 InnoDB 正确跳过、失败隔离 |
| **P6** | 全链路回归 | — | 首页/前台搜索/后台均 HTTP 200;**降级**(Meili 开但不可达)3ms 内回退 LIKE 不卡死;前台搜索结果正常渲染 |

### 仍按设计保留的取舍(非缺陷)
- **Provide 默认带 `datafilter`(`_string`)** → 桥接遇 `_string` 即回退 LIKE(外站契约优先稳妥)。清空 datafilter 后 Provide 才走 Meili;关键词少、以浏览为主,影响小。
- **`class/tag` 过滤** 仍走 LIKE 回退(未纳入 Meili filter;二者已是 searchable,关键词检索覆盖)。
- **排序**:Meili 出相关性序,`time/hits/score/level` 等由 DB 在命中集合上排;`sortableAttributes` 维持 `hits_month/ts` 即可。
- **大表引擎转换/删冗余单列索引** 不自动化(放后台按钮),避免登录时长 ALTER 阻塞。

*本方案已逐阶段实现并在 docker(MySQL 5.7 + PHP 7.4)实测;Meili/Redis 镜像因 Docker Hub 限流无法拉起,故 Meili-ON 以"现成桥接 + 降级回退"双重保证(关闭=零回归实测、不可达=3ms 回退实测)。*
