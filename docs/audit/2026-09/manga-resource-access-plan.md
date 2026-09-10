# Manga 资源授权：未修复证据与后续分批计划

日期：2026-09-10。范围仅当前源码；不读取 Git 历史、站点秘密配置或业务数据。本文是**未完成的修复计划**，不是漫画授权审计通过报告。此前 Vod、Art 的授权修复不能覆盖本模块。

## 验证方法与结论

诊断使用安装 SQL 原样建立专用 MySQL 表、真实 TP8 Request/ORM/User/All 身份与权限方法、真实 API/前台/购买动作、实际默认模板与 `config/view.php` 输出配置。MySQL/PHP 容器均 `--network none`，通过临时 Unix socket 连接；图片仅为 `fixture.invalid` 字符串，未抓取、未执行脚本载荷。会员 JWT 使用与服务端行一致的 32 位 nonce。

先在原始安装表复现正常漫画章节读取报错；后续只在临时表添加两个旧站可能存在的字段，并明确提供非空服务器/备注占位值，才能继续验证被首个异常遮住的授权链。这个测试安排不是生产补表方案，也不能把临时扩展表描述为当前安装 DDL。

PHP 8.3.33 / 8.4.25 各完成 46 项真实 MySQL/模板证据检查，实际默认 JS 启动另各 2 项；19 条现象按下表合并根因。源码行号按诊断基线记录。诊断脚本断言的是旧行为证据，**不能挂入正常 CI 作为安全通过测试**；模型及授权修复后应使用各批新增的正向回归。基线副本、哈希和日志交付于 `/tmp/maccms-audit-20260910/manga-resource-diagnostics-frozen`。生产代码在诊断阶段没有修改。

## 可复现问题

| 根因/风险 | 具体入口与源码 | 正常或边界触发 / 证据 | 修复归属 |
|---|---|---|---|
| PHP 8 可用性：读取不存在字段 | `application/common/model/Manga.php:493`；安装 `application/install/sql/install.sql:187` | 原安装 DDL 没有 `manga_play_server`/`manga_play_note`；任意非空 `manga_chapter_url` 使 API `get_chapter` 抛 Undefined array key（M01） | 最小模型兼容批 |
| PHP 8 可用性：可选分组未补缺省 | `application/common.php:2520` `mac_manga_list` | server/note 为空时直接读数组键；from/url 分组长度不一致也有同类错误。不能仅在模型加 `?? ''` 后声称正常章节可读（M02） | 最小模型兼容批 |
| 密码未执行 | API `Manga.php:145`；前台 `Manga.php:36`；`All.php:580`；Ajax `pwd():534` | 存了 `manga_pwd` 的免费漫画，游客 API 返回图片，默认阅读模板输出图片；Ajax 的 `mid=12,type=1` 密码验证却受控拒绝。无密码验证接口或 grant 链（M03/M04/M05/M09） | 完整读取授权批 |
| 受保护对象泄漏给模板 | `All.php:602,615`；默认 `manga/play.html:12` | 付费拒绝后 `obj` 仍含明文密码、所有源/所有章节原址。默认模板目前会隐藏拒绝的图片，不能因此把所有模板/后续分支当作安全。公开 API 目录已由 A1 递归过滤，不重复报已修的出口（M10 及对照） | 完整读取授权批 |
| 实际坐标与授权、购买目录不一致 | API `Manga.php:156-196`；`api/validate/Manga.php:26`；`common.php:2674`；默认 `manga/play.html:20-27` | API 验证场景只校验 id，sid/nid 的数组、`1junk`、负数、浮点被强制转 1。真实章键 1/3 时 next 走 2；前台省略坐标用 0/0 查凭证，模板却显示 1/1；rewrite slug 已查到作品但仍用于 `ulog_rid` 查询（M07/M08/M11/M12） | 完整读取授权批；购买共用纯解析结果 |
| 详情非正 ID 返回其他作品 | API `Manga.php:91-101` | `id=0` 通过 number 验证但被 empty 分支跳过，返回第一条已发布作品的安全元信息（M06）。属于接口正确性，不能描述为原址泄漏 | 完整读取授权批 |
| 旧核心详情缓存越过新授权状态 | `common.php:4069-4084`；模型 `Manga.php:478-489` | 前台 cache=1 缓存免费行后，把 DB 改为付费/下架/回收，前台仍读出资源；同请求 API cache=0 按新状态拒绝（M13/M14）。这是模型缓存，区别于已排除 reader 的共享页面缓存 | 完整读取授权批 |
| 存储型 HTML 属性注入 | 默认 `manga/play.html:86`；`config/view.php:35` | URL 的双引号打断 `data-original` 并创建额外属性，真实 ThinkTemplate 按仓库空 default_filter 输出（M15）。仅插入惰性 `data-audit-injected` 属性证明上下文突破，没有执行载荷 | 完整读取授权批：URL 策略及 HTML/JS 分别编码 |
| 购买可为无效资源收费 | `index/User.php:111-151` | 真实 Bearer 身份通过 MemberWrite 后，mid12/nid222（不存在）照常扣 3 点并写凭证；status0 且有密码的作品也能扣费写凭证（M16/M17）。事务/余额精确写入已经有效，缺的是资源锁内报价与授权前提 | 后续 Manga 锁内购买批，另代理负责 |
| 首个可读链接与 rewrite 客户端失败 | `common.php:3863`；默认 `manga/detail.html` body；`manga-detail-ajax-render.js` 的 `Y()` | 第一源空、第二源有章时 `mac_url_manga_play(...,'first')` 返回空。真实 slug 被写到 data-detail-id，默认 JS 仅 parseInt，因此不请求详情；数字 ID 对照正常（M19/M20） | 完整读取授权批 |

## 已有效的防线和应保持的合同

- A2a `All::label_user` 已采用服务端用户；禁止回退信任原始 user_id/group/积分 Cookie。购买入口的 MemberWrite、CSRF/Bearer 校验和 ContentPurchase 原子扣费不属于本轮新漏洞。
- 公共 API `get_detail`、`get_list` 的 PublicContentView 已移除密码、chapter_url 与嵌套原址；有真实递归结果对照。元信息中的 `manga_content` 是漫画简介，不能机械照搬 Art 正文语义全部删除。
- API `get_chapter` 已按发布/回收条件 fresh 查询，并在积分拒绝时返回空 images。默认模板在积分拒绝时也不输出图片。修复必须保持这些正常行为。
- 既有业务：允许阅读的免费分类可读；普通会员对正价单章需精确当前价格的凭证；VIP 仍需分类/组权限；现有收费分类无组权限时，精确已购章有付费回退；整条作品配置使用 `ulog_sid=0,nid=0` 和作品价格。本次不另造会员规则。
- 现有 `ContentPurchase::parameters` 已拒绝 sid>255、nid>65535，并把 mid12 限为 type1。不能把前台历史冗余的 type4/5 判断误报为有效购买入口。
- API `Payment::buy_popedom` 明确拒绝 mid12；它没有“漫画 API 购买”的既有兼容合同。前台会员购买才是当前有效入口。

## 安装字段和建议共享解析合同

实际 DDL：`manga_id` 为 UINT32；`manga_points`/`manga_points_detail` 为 SMALLINT UNSIGNED（0..65535）；`manga_pwd` VARCHAR(10)，只有一个漫画密码；章节是 `manga_chapter_from` 与 `manga_chapter_url`。Ulog 的 sid 为 TINYINT UNSIGNED（0..255），nid/points 为 SMALLINT UNSIGNED（0..65535）。原址按源 `$$$`、章节 `#`、标题/地址 `$`、图片 `,` 分隔。

拟新增 `ContentResource::mangaContext(array $freshRow, array $parameters): array`，只解析调用方刚读取的行，不自行缓存、不读取身份、不写数据库。输入 sid/nid 仅正 UINT32 字符串或整数；缺省 1/1 保留现有规范链接合同，非法类型受控 1001，缺少该实际章受控 1002，不把任意非法/缺章请求重定向成另一个付费章。

成功返回内部 `id,sid,nid,current,source,previous_nid,next_nid,points,whole,ulog_mid=12,ulog_type=1,ulog_rid,ulog_sid,ulog_nid,purchase_supported,purchase_sid,purchase_nid`。原数组键保留；previous/next 从真实可读章键计算，不用 url_count 当最后章编号。价格精确解析且允许 0；单章优先正 `manga_points_detail`，否则保持现有回退 `manga_points`；整条取 `manga_points`。

`current/source` 含原始图片，只限内部授权使用，严禁直接序列化。空图片章可显示“暂无图片”，但不能收费。sid>255 或 nid>65535 时保留真实阅读坐标，单章购买不支持且按钮不得触发；免费/VIP读取无需削短目录。整条模式选择一个真实、非空、可存储的购买入口坐标，再由服务端形成 0/0 凭证；如果没有可表示的实际入口，应明确不可购买，不截断。无需运行时扩 DDL。

推荐读取响应继续保持 `code=1,info`、现有 can_read/deny_code/deny_msg/points_hint/manga_id/name/sid/nid/episode_name/episode_total/images；新增 `previous_nid,next_nid,previous_link,next_link,password_required,password_verified,password_help_url,purchase_supported,purchase_sid,purchase_nid`。拒绝 images=[]；只有**当前获准章**出现图片；目录保留实际 sid/nid/标题/站内链接，原址/服务器/真实密码从所有模板变量与 JSON 分支去除。

密码使用独立 Manga scope（拟 `mid12/type1/id`）、游客 Session grant，并绑定当前密码指纹以使修改密码后的旧 grant 失效。密码、会员/分类、积分三个条件都满足才返回图片。无试读片段实现时不允许以 trysee 标志交付全章图片。详情继续提供公开简介和目录；其是否另需组权限按既有前台/API合同分别保持，不把目录当付费图片。

## 最小分批与验收

1. **模型解析兼容批**：只改 Manga::infoData 可选字段默认值、mac_manga_list 空值/分组补齐。实际原始 DDL 不新增列；正常源/章键、空源、缺少 server/note、合法多源、分组数量不一致、空章节原序号有回归。API 请求参数、密码/付费/模板均留给下一批。该批只能声明可用性修复；上线需与紧接的授权批协调，因为原 500 被解除后密码旁路仍在。
2. **完整 Manga 读取授权批**：共享工具只新增 Manga 方法；Fresh 状态/实际坐标→独立密码/组/积分→当前图片 DTO。接 API、前台 detail/play、Ajax pwd、默认模板/目录/JS、缺模板时独立本地兜底。模型 cache 不参与资源授权；递归拒绝、当前章独占、密码变更、重写、非连续章、默认坐标、VIP/普通/游客、whole/单章、超存储范围、有效 URL/属性/JS 输出、真实默认模板和表单 token→POST→回读均验证。
3. **Manga 锁内购买批**：后续专组接 fresh mangaContext 与服务端可信用户，在用户锁之后锁资源/组并复核章节、价格、密码/权限和购买范围；不存在/空/下架/回收/密码未过/无需收费不得扣款。沿用现有幂等凭证、精确扣费/账本/奖励同事务，新增并发涨价/下架/双购买回归。此批完成前不得声称漫画付费闭环。

## 静态与未定业务语义

`mac_url` 有漫画 detail view2、play view2/3 静态 URL 分支，但实际 `Make::info` 只处理 Art 与 Vod，未找到 Manga 生成调用。`label_manga_detail(view>=2)` 跳过检查是潜在危险接口；没有现存调用证据时不能声称“实际漫画静态文件已经复现泄漏”。后续读取批可保证目录不含原址；新增漫画静态生成能力应独立设计成安全动态入口壳，不能直接写鉴权后的图片。已有站点 HTML 不能自动删除。

公共页面缓存资格已排除 Manga detail/play/get_chapter，PHP 动态响应已有 private/no-store；保留此策略。根此前记录的“不同对象静态 path 缺少唯一标识导致文件碰撞”仍是全站配置风险，不纳入本次漫画解析修复。

`manga_is_vip`、`manga_age_rating`、`manga_lock` 在实际表有字段，但未找到相应阅读策略；当前明确的付费/分类约束来自 points 和组权限。不能单凭字段名称发明新的访问规则，须独立确认产品语义。RecycleBinTrait 运行时 ALTER 的全站迁移治理待办继续引用搜索/公共列表报告，本组不修改共享 trait。
