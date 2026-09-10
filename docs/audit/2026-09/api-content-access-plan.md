# API 内容访问控制：合同与后续修复计划

**状态：本文件是审计发现和待实施计划，不是权限修复完成报告。** 表前缀组已提交 `54c41f5`；Collection 兼容问题另有独立变更。下述密码、内容授权、认证上下文和资源地址泄露链尚待分批修复。所有事实来自当前代码只读核查与先前一次性测试库；没有访问真实站点、读取站点秘密配置或运行不可信脚本。

## 现行权限合同

不要混用三套编号：

| 操作 | 分类 group_popedom 权限 | Ulog 购买类型 | 密码会话 |
| --- | --- | --- | --- |
| 视频详情 | 2 | 无 | `1-1-{id}` / vod_pwd |
| 视频播放 | 3；5 是试看 | 4 | `1-4-{id}` / vod_pwd_play |
| 视频下载 | 4 | 5 | `1-5-{id}` / vod_pwd_down |
| 文章详情 | 普通 label 为 2；现行 detail 主入口显式跳过组/积分 | 无 | `2-1-{id}` / art_pwd |
| 文章阅读 | 3 / art_read | 1 | 现有阅读入口未检查访问密码，待闭合 |
| 漫画详情 | 2 | 无 | 存在 manga_pwd 配置但现有入口未检查，待闭合 |
| 漫画阅读 | 3 / manga_play | 1 | 尚无支持 mid=12 的现成密码校验动作 |

依据：`application/common/controller/All.php:481-599,637-674,847-1081`，`application/index/controller/{Vod,Art,Manga}.php`。详情展示与实际内容收费须分离。文章详情 `label_art_detail([],2)` 是现行免费目录入口；不能为了补权限，机械加上正文收费条件而把所有付费文章的封面、简介和目录也隐藏。视频/漫画详情已有各自的分类详情权限合同，应保留。

`check_user_popedom` 基于经过验证的用户组、分类权限和购买记录，**不检查任何密码**。三个视频密码会话互不替代；通过密码也不等于购买成功。`user.status=0` 当前关闭用户组/积分门控，但前台密码仍独立检查。付费组 `max(group_id)>=3` 只有在相关分类权限允许时才按现行规则免积分，不能使用展示旗标 `vip_nav`、`is_member` 或请求传入的 group_id 作为授权凭据。内容表上的 group_id 也不是当前共享函数实际读取的用户授权规则，不能未经核对就额外创造限制。

购买范围必须保持服务端一致：`*_points_type=1` 使用整条价格，Ulog sid/nid 均为 0；否则文章 sid=page、nid=0，漫画/视频为真实 sid/nid。文章/漫画报价使用 `mac_content_read_points_amount()`（每页价为 0 时回退整条价），视频使用 vod_points_play/down 或整条 vod_points。购买动作见 `index/User.php:102-160` 与默认主题 `widget/popedom_upgrade_gate.html:3-24`。现行 Ulog 查询还匹配实际价格；调价是否让旧购买失效是独立合同问题，本组不默默改变它。

## 调用方真正需要的字段

仓库内直接调用这三个详情 API 的默认主题文件均位于 `template/default/asset/js/*-detail-ajax-render.js:1`，使用 `credentials: same-origin`。没有发现仓库内调用 get_play_info/get_down_info/get_read_page/get_chapter 的独立原生客户端；这些动作注释提到 uni-app/SPA，但不能据此宣称已验证仓库外客户端兼容性。根目录 api.md 仅记录部分请求参数，没有完整返回字段合同。

| 响应 | 默认主题实际消费 | 推荐保留/替代 |
| --- | --- | --- |
| vod_play_list | from、player_info.show、urls[].name、数组顺序；主题自行构造站内播放页地址 | 保留原目录结构、名称/序号，增加明确 sid/nid/play_link；移除资源 url 和服务端配置 |
| manga_page_list | 数字组/章节键、sid、from/note、url_count、name、play_link | 保留目录键、数量、标题、站内阅读链接；同时删除组级 url 与章节级 url |
| art_page_list | page/title、总数和文章 ID；构造站内阅读页地址 | 当前已去掉 content，保留目录；不重新放回正文 |
| 普通元数据 | 标题、封面、简介、时间、标签、评分、积分提示、VIP 标志、收藏/点赞状态 | 保持 DTO 字段；积分只是报价，不是授权依据 |

对 vod/manga 详情 JS 逐项核对，没有任何直接 `.url` 资源字段或密码值消费。因此完整删除目录会造成可避免的前台功能回退；保留安全目录即可。Vod 内容介绍 vod_content 与文章的付费 art_content 含义不同，也不能因都叫 content 而一并删掉。敏感字段应使用显式 DTO 白名单，不能仅遍历删除几个顶层列后直接序列化整行。

建议替代字段：`has_password`、`has_play_password`、`has_down_password` 布尔值；若保留现有 get_play_info/get_down_info 的 `vod_pwd_play`/`vod_pwd_down` 字段，应继续只返回 0/1。密码获取地址是管理端配置的引导链接，不是密码本身，若产品需要则以单独、经过协议约束的 `password_help_url` 返回，不暴露 player/server 全配置。目录中的 `play_link`/`read_link` 必须是站内受控入口。

## 实际资源授权边界

API Art::get_read_page 和 Manga::get_chapter 已提供可用模式：`code=1` 的 info 中携带 `can_read`、`deny_code`、`deny_msg`、`points_hint`；拒绝时 content_html 为空或 images 为 []。视频应采用对应 can_play/can_down、password_required 和相同拒绝信息，并保留标题和目录让客户端呈现登录/购买/输入密码引导。

所有原始正文、漫画图片、播放/下载源地址只应在当前资源授权通过后返回。按集购买情况下，只允许获授权的 `current.url`，不能因为当前集通过就把整个 play_list/down_list 的其他集 URL 一并下发。mac_play_list 输出还包含组级 url、server、server_info 和 player_info；这些必须投影为允许的展示字段。Manga 仅 unset 顶层 manga_chapter_url 远远不够：common.php:2615-2623 的组级 url 和 urls[n].url 都保留实际图片内容。

先规范化并确认实际 page/sid/nid 存在，再执行权限查询，再输出该资源。Art 当前在 API:272 用原 page 授权，279 才将超出总数的 page 钳制，授权对象和返回页可能不一致。应修复顺序并验证按页购买记录，不让非法页变成授权别的页的入口。

试看是单独能力：现有 permission=5 和 trysee 秒数不能自动保证原始媒体地址只可观看 N 秒。若没有服务端受限片段/令牌能力，应先返回现有播放器入口和试看状态，不能向未获完整权限的客户端下发完整源 URL 后声称安全限时。转义或 Base64 同样不提供访问控制。版权和锁定行为也不能只靠模板隐藏按钮，需核对现行配置语义后在实际资源出口执行。

## 必须同步审视的其他入口

1. `All::label_user():201` 只有三个登录 cookie 存在才调用 `User::checkLogin()`；后者 `common/model/User.php:848-871` 实际支持 Bearer/JWT。纯 Bearer 的 VIP/购买者会被 API 内容权限当成游客。需统一受验证用户上下文，并保留会员过期/禁用检查；只在 Vod 增加 check_user_popedom 不足以兼容 API 登录合同。
2. `template/default/html/vod/player_pwd.html:34` 在未配置密码获取地址时直接显示保存的播放密码。API 删除密码后，这个前台出口仍泄露。
3. `admin/view/manga/info.html:276-282` 和安装表定义明确提供访问密码，但前台 Manga 控制器未检查；`index/Ajax.php:532` 密码动作只支持 mid 1/2。Art read 也不检查 art_pwd。推荐将文章/漫画“访问密码”统一覆盖详情与正文/图片，同步校验动作和前台/API；这会收紧现有缺口，必须在该子批明确记录，不能伪称原先已经一致。
4. 同一密码通过后的会话作用域、退出登录/密码修改后的失效行为、密码验证动作参数和节流都需专门回归。不能通过为任意操作构造一个不匹配实际授权检查的 session key 来实现表面兼容。
5. Actor status 0/1 是当前控制器明示的采集兼容合同，完全不在本轮 Vod/Art/Manga 权限收口中修改。

## 推荐子批和验收

- 已独立处理表前缀；Collection 小组只修数组加工和 PHP8 返回契约。
- 权限 A：显式公开详情/目录 DTO、禁止所有密码和嵌套资源 URL、修前台直接显示密码出口。必须注明 get_play_info/get_down_info 等仍未授权的出口，不能宣布整条泄露链闭合。
- 权限 B：统一可信登录上下文；实际播放/下载资源按当前集执行分类、积分、密码检查；保留安全目录和拒绝 DTO；回归纯 Bearer 与 cookie、整条/单集购买。
- 权限 C：文章/漫画访问密码、验证动作与前台/API 阅读门控闭合；修实际页授权顺序。已有 group/points 语义尽量复用，契约调整单列。
- 参数/SQL 语义/查询成本/缓存命名空间仍按下附审计建议独立分批，不混入 Collection 或机械 DTO 修复。

隔离 MySQL 验收至少涵盖：游客、普通会员、有效/过期 VIP、多组、禁用账户、纯 Bearer；分类允许/拒绝、关闭会员系统；零积分/整条/单页或单集购买、他人购买、价格变化；未输入/错误/正确密码、三种视频 scope 互不解锁；当前与其他章节、缺省/不存在/非法页；所有拒绝响应递归检索无密码/完整正文/原始URL，完整成功响应只返回获授权资源；实际默认主题消费目录无回退。购买属于显式写操作，资源 GET 不应暗中扣费。真实媒体服务的源地址防盗用能力应另行验证，不把应用内 DTO 收口等同于外部源站权限控制。

## 19 处查询的完整原始只读记录

下面保留先前只读发现，作为可持续审阅证据。其“前缀组待修”描述反映发现时状态，现已由 `54c41f5` 解决；Collection 项跟随独立兼容报告，权限与其他子组仍按本文件顶部状态执行。临时运行日志仅是补充，最终问题说明保留在本文件中。

# 19 API queries: read-only findings before the prefix change

Scope: current application/api/controller/{Actor,Art,Manga,Role,Topic,Vod,Website}.php, real TP8 Request, validators and ORM. No history/site settings/business database. `probe.php` and `run_probe.py` reproduce in network-none disposable MySQL; initial complete dual-version output is `mysql-final-readonly.log` (PHP 8.3.33 and 8.4.25). Presentation/cache/user helpers are isolated; the Collection helper keeps the actual `array &$rows` signature. These are diagnostic observations, not a claim all APIs are fixed.

## Exact hardcoded query inventory

| File:line | Action / normal request | Queries |
| --- | --- | ---: |
| Actor.php:136,189 | get_detail?actor_id=20; get_recommend | 2 |
| Art.php:214,216,424,474 | get_detail?art_id=20 (same-category previous/next); get_hot; get_latest | 4 |
| Manga.php:243,286 | get_hot; get_latest | 2 |
| Role.php:175 | get_detail?role_id=20 | 1 |
| Topic.php:106,120,135,201,267 | get_detail?topic_id=20 with both relation kinds; get_recommend?ids=30,0,20; get_recommend without ids | 5 |
| Vod.php:175,299,347,395 | get_detail?vod_id=20; get_year/get_class/get_area?type_id_1=1 | 4 |
| Website.php:135 | get_detail?website_id=20 | 1 |

19 call sites across 16 action/branch entries. The 4 existing Vod home actions beginning with homeVideoQuery() at line 420 are excluded.

## Recommended separate groups

1. **Configured table prefix: deployment availability and conditional data isolation.** All 19 hardcode `mac_`, bypassing the configured prefix. With both prefixes present the wrong dataset is returned; with no mac tables the requests fail. Art main detail comes from the configured model while neighbors come from mac; Role detail comes from mac while its related Vod uses the configured prefix. Real fixture confirmed both mixed responses. First fix: change only those 19 `table('mac_x')` calls to `name('x')`, with separate regression. No status or parameter changes in this commit.

2. **Collection PHP8 compatibility: normal requests fail or silently lose fields.** Art.php:474-487 and Manga.php:286-299 pass Collection to common.php:4312 `array &$list`: any get_latest request, including an empty result, throws TypeError. Actor.php:194-199, Art.php:429-434, Manga.php:248-253, Topic.php:272-278, Role.php:112-135 and 252-256 mutate the ArrayIterator copy by reference; actual response loses transformed picture/link/time, Topic topic_empty, and Role vod_name. `think-helper/src/Collection.php:636-638` returns `new ArrayIterator($this->items)`. Convert query results to array before mutable transforms, preserving empty JSON arrays and pagination. Topic's explicit-ID recommendation branch already builds arrays and preserves transformations/placeholders; do not change its ordering contract accidentally. Run populated + empty + paged actual JSON responses, assert transformed fields and related titles, plus all prior Vod home checks.

3. **Public data visibility and sensitive fields: high risk, independent of prefix.** Vod.php:175 queries by ID only; 188-250 returns parsed playback/download URLs; 253-254 removes raw URLs but retains parsed URLs and `vod_pwd`, `vod_pwd_play`, `vod_pwd_down` in the unrestricted result. Real anonymous fixture returned three plaintext fixture passwords, URLs, status=0 and recycled rows. Compare verify_pwd at 830-844, which checks those saved passwords, before choosing the public response allowlist/authorization behavior. No assertion here that the exposed source URL alone bypasses a CDN's independent authorization; application-stored passwords are definitely disclosed. Topic.php:106 reads hidden topic; :120/:135 expose hidden and recycled related Vod/Art. Role.php:175/:187-190 exposes hidden Role and related hidden Vod. Art.php:178 lacks status (its model does filter recycled main rows); its neighbors :214/:216 and hot/latest :417/:467 lack recycle checks. Manga.php:241/:284 hot/latest lack recycle checks. Vod metadata :302/:350/:398 include recycled values; fixture returned the unique RECYCLED year. Adjacent Art/Vod/Website list methods using Base::getCountByCond/getListByCond need separate review because Base does not merge RecycleBinTrait constraints. Actor status 0/1 is explicitly documented as a current product compatibility choice at Actor.php:42-44 and :138, so do not silently equate its status 0 with forbidden draft data in this mechanical prefix group. Website detail correctly requires status=1; Manga detail correctly requires status=1 and model recycle conditions.

4. **Strict scalar and query budget boundaries: PHP8 500s / query cost.** Recommendations do not call validators: Actor.php:172/175 (`ids`, `by`), Art.php:409 (`by`), Manga.php:233 (`by`), Role.php:228/230 (`by`, `level`), Topic.php:179/257 (`ids`, `by`) accept arrays then trim/cast. Each was reproduced as TypeError or E_ALL Array-to-string error. Actor/Art/Manga/Role `num` has no positive/max bound; num=-1 causes MySQL1064, huge num emits a huge LIMIT, and num=0/start=3 becomes LIMIT3 rather than offset3/count0. In TP8 BaseQuery.php:683-687, zero length is omitted; start=0,num=0 can suppress LIMIT entirely. Negative start also reaches invalid SQL in Art and Manga hot; other recommendations clamp it, but deep positive offsets remain unbounded. Topic already caps num to 1..20; preserve this distinction. Additionally max:length rules in validators allow arrays by counting their elements (think-validate Validate.php:1750-1760): `get_list?name[]=x` fails strlen in Actor:66, Art:71, Role:71, Website:57; `vod_name[]=x` fails Vod:67; `wd[]=x` fails Manga:45 trim. Scalar rules plus field-specific validation must precede casting/string operations. IDs validated as number also accept fractions/scientific notation; Actor/Role/Website id=1.9 returned ID1 after cast. Manga get_detail id=0 passes require|number then skips its empty id condition (:92-94), potentially returning the first visible row. Test each field with missing/empty/string zero/array/nested array/null/bool/fraction/overflow/negative plus normal UTF-8 values, assert error envelopes before SQL and enforce row/offset caps on >cap fixture rows. Do not call bound value inputs SQL injection: the audited queries use ORM values and existing sort allowlists.

5. **SQL semantics and query count / cache correctness.** Art.php:58/60 still assigns legacy associative operator arrays (`['<=',t]`, `['>=',t]`), which TP8 treats as IN values. Actual MySQL time_start=200 returned only time=200 instead of 200/300/400; time_end=300 returned only300 instead of100/200/300. The two-ended `between` at :56 works. Use explicit three-element conditions, test inclusive boundaries separately. Topic.php:118-143 performs 1+N+M queries, preserving relation order and duplicates but imposing no bound; replace with validated/bounded batched IDs and reconstruct documented order, test absent/duplicate/invalid IDs plus a real query-count assertion. Vod metadata cache keys :296/:344/:392 omit configured cache flag, connection and table prefix; shared cache namespace can mix installations even after table names are corrected. A distinct cache namespace and bounded typed cached list validation belongs in its own cache/metadata change. Do not claim this conditional shared-cache case is proven as a deployed multi-tenant configuration.

## Runnable verification approach

`python3 /tmp/maccms-audit-20260910/api19-readonly/run_probe.py` provisions its own MySQL and runs the diagnostic fixture on both PHP images. Diagnostic code prints observed outputs, not pass/fail judgments. After code changes it naturally observes the new behavior; the original pre-change output is retained separately.

For permanent regression, reuse the dedicated network-none MySQL runner, construct real Request with controller/action and invoke actual controller methods without loading site bootstrap. Seed both configured tables and mac decoys with identical IDs but different fields, configured-only and decoy-only IDs; assert exact selected rows, related data, missing rows, both topic recommendation branches, previous/next and metadata cache misses. Repeat after dropping all decoy tables. Keep actual helper type signatures. If the prefix commit precedes the Collection fix, explicitly observe the pre-existing two latest-list TypeErrors after verifying the real SQL/rows selected; do not substitute an untyped helper and claim full endpoint success. Then remove that known-failure allowance in the independent Collection group and require complete valid JSON.
