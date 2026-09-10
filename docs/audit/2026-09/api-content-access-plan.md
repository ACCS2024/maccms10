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

## A1 之后的扩查与实施边界（2026-09-10，仍是待完成计划）

A1 的公开 DTO 与六个模板明文出口修复见 `api-public-content-dto.md`；该组不包含资源授权闭环。以下发现由当前代码只读核查确认，必须进入后续验收，不能因为四个 API 加了检查就宣称完成。

| 当前路径 | 正常功能触发与实际缺口 | 后续边界 |
| --- | --- | --- |
| `All.php:188-235`、`User.php:900-960` | `label_user()` 只有三项 Cookie 齐全才调用真正的 `checkLogin()`；有效纯 Bearer 因而仍是游客。模型已支持有效 Bearer 优先、无效已启用 Bearer 不回退 Cookie；`is_member` Cookie 还可自行点亮展示徽标 | A2a：复用模型验证结果，统一可信用户和展示组，不改认证模型 |
| `common.php:1110-1128`、`SecurityHeaders.php:38-40` | 整页缓存资格只看 `user_id` Cookie。无该 Cookie 的 Bearer 用户、通过密码的游客会话仍可被标为匿名；旧 `_mac_page_cacheable` 又会覆盖响应缓存头 | A2a：保守允许确定匿名的公开目录页；认证、密码、正文/资源入口明确 `private, no-store`，不得命中或写入共享整页缓存 |
| `All.php:763-803` | 当前集获准时还生成 `player_info.url_next`；该下一集可能没有购买记录。其余来源/章节的原址也留在传给模板的完整内容行中 | A2b：先解析真实资源坐标再授权；未逐项授权的相邻/其他资源只留站内链接和目录 |
| `template/default/html/vod/down.html:62-82` | 下载页遍历所有来源/集的 `vo2.url` 并输出到复选框和文本框。只检查 URL 中一个 sid/nid 不能授权整个下载表 | A2b：完整目录保留，每个下载资源必须单独获准才有原址；未获准项提供获取/购买入口，不能用一个授权结果覆盖全表 |
| `All.php:665-688,812-824`、两个主题 `vod/player.html` | 试看模式可能把完整源地址交给播放器，再用浏览器计时器限制播放；直接请求 player 路径使用另一权限编号 | A2b：缺少服务器可验证的预览资源时，不向仅试看用户下发完整源地址，也不能用 iframe/player 旁路；保留试看提示，不谎称客户端计时是资源限制 |
| `api/Art.php:272-290`、`template/default/html/art/read.html:11-24` | API 与前台模板在权限检查之后将过大 page 收敛到最后一页，授权/购买键和最终正文可能不同；伪静态名称/编码 ID 也不能直接用作 Ulog rid | A2b/A3：先依据服务端解析行确定实际数值 rid、page/sid/nid，再查相同购买键，之后投影当前正文 |
| `index/Art.php:57-90`、`template/m1938pc3_v2/html9/art/detail.html:6`、该主题 `art/rss.html` | 免费详情入口可被旧主题当作正文入口；RSS 也输出 art_content 摘要/分页内容。只拦 read/get_read_page 不覆盖这些出口 | A2b/A3：保留免费标题/简介/目录；实际正文使用同一阅读授权，RSS 公共描述改用公开简介；需真实旧主题渲染验收 |
| `index/Art.php:87-90`、`index/Manga.php:29-38`、`api/Manga.php:170-210`、`index/Ajax.php:525-582` | 文章阅读和漫画正文只组合积分权限；漫画密码没有 mid=12 验证入口。现有密码会话值仅为字符串 1，还不能随内容密码变更自动失效 | A2b/A3：资源授权必须合并对应密码；共享验证器支持文章/漫画，保留视频三种独立作用域；验证成功不替代积分购买 |
| `template/default/asset/js/vod-detail-ajax-render.js:1` | 当前 JS 按压缩后的数组 index+1 构造播放链接，原始来源/集有空段时可能指向另一集。A1 DTO 已给出实际 sid/nid/play_link | A2b：使用服务端生成链接/实际坐标；用空段、非连续键及多来源夹具验收，禁止按重编号目录查询购买记录 |

### A2a：可信身份与缓存（独立提交）

本组实现及验证现见 `content-identity-cache.md`，等待独立提交验收；A2b/A3 仍未完成。生产文件为 `application/common/controller/All.php` 的 label_user/共享缓存键/直接命中出口、`application/common.php::mac_page_cache_eligible()`、`application/middleware/SecurityHeaders.php`、`application/middleware.php` 及新增 `application/common/util/ContentCachePolicy.php`。不修改 `common/model/User.php`、`JwtService.php` 或资源动作。

统一调用既有 `User::checkLogin()`，游客初始化包含实际权限代码使用的 `user_points`；既有成功用户信息、Cookie 编码兼容、过期组处理及模板秘密字段剥离都保留。无凭据游客不能每次触发清 Cookie/Set-Cookie。有效纯 Bearer、错误 Bearer 加有效 Cookie、数组 Cookie、过期/撤销令牌、失效账户、伪造 `is_member`/group_id 均经过真实 Request、User/JWT 和隔离 MySQL 验证。模板徽标只依赖验证后的组，不能拿徽标决定权限。

整页缓存保守排除资源/正文/密码/用户入口和携带身份的请求；只允许确定匿名的公开目录动作。私有响应头必须在安全头中间件中优先于历史公共缓存标记，包括拒绝响应。用两个独立 Request/会话模拟先授权用户、后游客，检查缓存读写、响应头及串行请求状态残留；无身份公开首页/分类页仍应可缓存。缓存资格修复不意味着 CDN 已有缓存会自动失效，上线需清除此前相关内容 URL 的缓存。

运输层补充：SecurityHeaders 已移到 SessionInit 外层以看见最终 Cookie 队列；任何 Set-Cookie 都不允许 public 响应。原生 SessionInit 对空会话也排队 Cookie，因此 PHP 页面保守 private/no-store，内部匿名目录缓存仍保留。旧缓存命中 echo/exit 绕过中间件，已单独发出同样的私有头，且共享缓存使用新版本键避开旧污染副本。未改 vendor 或会话初始化逻辑。

### A2b/A3：资源定位、组合授权与所有当前出口（有依赖的闭合批次）

建议新增 `ContentResource` 负责类型化参数与实际资源选择，新增 `ContentPassword` 负责服务端密码作用域/验证记录；All 提供组合授权入口并复用现有 `check_user_popedom()` 的业务规则。候选文件为 All、API Vod/Art/Manga 的四个资源动作及密码动作、index Vod/Art/Manga/Ajax、上述两个主题的正文/下载/密码模板与默认 Vod 详情 JS。A1 的 PublicContentView 继续负责安全目录，不能承担权限判定。

执行顺序固定为：检查标量边界 → 按已发布且未回收行读取 → 解析现存章节及实际数值 ID → 归一/校验 sid/nid/page → 对同一坐标计算服务器价格/购买范围 → 检查用户组与对应密码 → 只构建获准资源响应。不存在的资源在授权和任何扣费前受控返回；正常缺省为首个合法坐标，已有文章超末页行为如保留，必须先收敛再授权。所有 GET 只读，不隐式购买或扣积分。

现有组与积分合同须逐分支保持：关闭会员系统只关闭组/积分检查，不取消密码；多组按实际分类权限合并；普通会员按服务端价格查询本人 Ulog；整条 sid/nid=0，按页/集记录使用真实坐标；价格仍参与记录匹配。**文章/漫画当前代码在组阅读权限不满足但有付费记录时也可放行**（All:915-939），与视频的严格组限制存在差别；不可借机械统一服务将其悄悄改变。是否调整这条业务规则须独立说明。

视频访问、播放、下载密码依然独立：访问密码不能解锁播放或下载，播放密码不能解锁下载；会员/VIP/购买均不能跳过对应密码。文章使用 `2-1-{id}`，漫画使用新的明确 `12-1-{id}` 作用域，并覆盖前台和 API 正文。建议验证记录绑定当前密码指纹，旧值 1 在安全迁移后要求重新验证，避免改密码后旧授权永久有效。沿用真实 PHP 会话持有内容密码验证状态；纯 Bearer 只代表账户身份，客户端仍需保留密码验证会话 Cookie，不能把内容密码写进 JWT 或响应。

API 拒绝继续提供目录和 `can_read/can_play/can_down`、`deny_code/deny_msg`、`points_hint`、`password_required` 等引导；拒绝时 `current` 不含资源 URL，正文为空，图片为空数组。成功仅给获准当前资源和必要播放来源标识，目录/相邻项只有站内链接。试看未提供专门预览源时明确不可提供预览资源，不用 base64/转义或客户端计时隐藏完整地址。

必须运行真实 MySQL/Request/User/JWT/Ulog 的游客、会员、VIP、多组、禁用账户、Cookie/Bearer矩阵；覆盖跨用户/跨类型/跨视频/跨集购买记录、整条与单项、调价、缺省/空洞/越界坐标，检查读取不写入余额或日志。密码验证采用真实 Session 的跨请求保存与恢复，覆盖错误、正确、字符串 0、数组、三种视频 scope、文章/漫画 scope、改密码使既有授权失效。拒绝和成功响应递归检查所有原始/转义/编码资源哨兵；真实当前/旧主题 HTML 与默认 JS 不能输出其他未授权集、完整付费文章或隐藏资源。

### 购买写入的独立依赖（交根代理与 User 组，尚未修复）

`application/index/controller/User.php::ajax_buy_popedom()`（102-199）按请求 sid/nid 构造购买键，未先验证实际页面/章节，mid/type 组合也未映射成固定的三个业务组合；资源读方的坐标修复不会自动让购买写入正确。`application/common/model/Ulog.php::saveData()`（151-179）又以未经验证的 `cookie('user_id')` 覆盖调用方传入的已验证 user_id。于是有效纯 Bearer 购买可能在用户扣费后写入失败或写向不同 Cookie 指定的用户；当前事务并未对所有嵌套返回码统一回滚。`api/User.php::add_ulog()`（503-528）也会经过此覆盖。以上是代码路径发现，尚未在该组运行扣费复现；须用专用 MySQL 独立验证，不能报告为已修复或已实际扣错。

这两个文件需由相应所有者另组衔接：以真正验证用户写入，服务端统一资源坐标/价格，拒绝不合法业务组合，验证每一步失败时余额、Plog、Ulog 原子回滚及重试幂等。读取授权的小组不得擅改现有购买存储合同，也不能因为 API 读取已认出 Bearer 就宣称购买链已兼容 Bearer。

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
