# 搜索建议的 PHP 8 / SQL / 缓存兼容

本批修复搜索建议这条读取链：七类 API（Vod/Art/Manga/Actor/Topic/Role/Website）与现有六类前台 Ajax（不含 Manga 路由）。生产仅修改 `ApiMeilisearchSuggest.php` 和 `index/Ajax.php::suggest`，没有改共享内容模型、关键词桥或正文授权。

## 修复前复现

使用当前安装 DDL、真实 Request/控制器/搜索 Service/ORM 和专用 MySQL；只替换外部 HTTP 传输。PHP 8.3.33、8.4.25 各确认五项：

1. `orderedDbRowsByIds()` 的 `select()` 返回 TP8 Collection，随后 `!is_array($rows)` 将合法结果丢弃。
2. 实际 API 已有 Meili 命中，但上述问题强制进入 MySQL fallback，返回顺序从搜索排序变为主键倒序。
3. Role 建表语句没有 `type_id`，建议元数据却选取此列。正常角色搜索在 fallback 和 Meili 回表中都会出现 SQL 错误。
4. `Topic::listData()` 忽略 `$field` 且以 `topic_id` 为集合键。Ajax fallback 传入 `AS id/name/...` 不生效，返回 `topic_*` 整行和正文，而非客户端需要的建议项。
5. 原 `catch(Throwable)` 会不加区分地移除 recycle 条件重试。在真实 ORM/SQL 日志环节注入一次异常，可以观察第二次查询已经没有回收条件。此项复现证明降权重试本身；原 Collection 错误会掩盖第二次取到的行，不能据此把它标为已完成外部数据泄漏。

复现日志：`search-suggest-repro.log`。使用改动前备份与当前安装结构，没有读取站点数据或执行外部请求。

## 本批合同

- `publishedQuery()` 固定沿用七类建议当前的 `*_status=1` 语义。Vod/Art/Manga 的回收列存在时额外要求 `*_recycle_time=0`；旧表通过只读 schema 查询判断缺列。其它模块、Actor 列表本身的状态语义没有改动。
- Meili 命中在一次 SQL 回表中完成发布/回收过滤，再按原命中 ID 顺序组装 PHP 数组。去掉重复的桥 ID 查询，旧表也不会在那一步先因缺列报错。没有修改 `MeilisearchListBridge`。
- 数据库及其它异常不再触发移除条件的重查。实际未知列错误保留在有发布/回收条件的语句上；没有把数据库错误伪装成成功空列表。Meili 不可用或没有可用命中时，仍按原合同使用 MySQL fallback。
- fallback 同样通过只读 `publishedQuery()` 查询固定字段，没有调用会执行运行时 `ALTER` 的内容模型。Role 移除不存在的列。Topic 从源 SQL 就只取所需字段，最终仍经过固定 DTO 投影；返回列表统一为 JSON 数组。
- API 建议项保持 `id/name/en/pic/<kind>_link`；Ajax 保持 `id/name/en/pic`。图片和站内链接加工保留，不返回正文或其它未选择字段。
- API fallback 保留主键倒序、实际总数和分页大小；Ajax fallback 保留 `popular/id` 排序及原 `totalshow=0` 的总数/页数行为。现有请求入口的数量上限未变，工具内回退另有 1000 行上限。百分号、下划线的 LIKE 字面量转义保持有效。
- Ajax 普通建议缓存与 debounce 缓存两处都先核验固定 DTO、ID 范围、重复 ID、数量上限和当前可见状态。无效时重新读取。有效缓存增加一次最多 50 个 ID 的数据库计数检查，继续保留原 TTL 和请求速率限制。缓存只能在验证时刻确认可见性，不声称跨查询事务快照。
- debounce 缓存 key 补入排序模式，与普通缓存的排序范围一致；切换 `popular/id` 后不会复用另一种排序的短时缓存。旧 Topic 整行缓存缺少规范 ID/字段结构，不能绕过新投影。

## 验证

运行 `python3 tests/run_search_suggest_audit.py`，PHP 8.3.33、8.4.25 各 **947** 项真实 MySQL 检查。覆盖七类 API / 六类 Ajax 的 Meili 命中、空命中、服务故障、搜索关闭、无结果、发布/回收状态、命中顺序、每页数量、API/前台计数合同、字面量 LIKE、固定字段 SQL 和 DTO、两缓存出口与排序变化、真实数据库错误、非数据库异常及旧表两读取路径无 DDL。

兼容回归：双 PHP 各运行公开媒体状态 **265** 项、Request 注入 **147** 项（132 个实际 Request 参数）。数据库采用随机临时专用库、非默认前缀和 Unix socket，Docker 禁用网络；没有读站点配置/密码或修改业务表。

## 独立待办

1. **运行时迁移治理**：`RecycleBinTrait::ensureRecycleColumnExists()` 在网页模型查询中执行 `ALTER TABLE`。本批搜索建议已绕开该副作用；普通 Manga 列表、Ajax 媒体模型及其它共享查询仍会经过它。应在独立迁移批次为升级/安装提供明确 schema 前置条件、缺列受控行为与部署迁移验证，不能直接移除共享 trait 而破坏旧站升级。
2. 搜索入口的全量标量/长度/类型边界、Meili 关键词条件拆分和跨索引分页估算仍需另批审计，不能以本批正常建议结果恢复代替整个搜索系统完成。
3. `static/js/home.js` 的 `MAC.Suggest.formatResult` 读取 `row.text`，而建议合同和同段 `formatItem`/选择回调使用 `row.name`。本批未改 JS；需在独立自动完成组件回归中检查输入补全与选择行为。本批没有声称执行了真实浏览器交互。
4. 历史整页/静态/CDN 内容和 Manga 正文/章节权限不在搜索建议的完成声明内。
