# Manga 当前章节读取、密码和模板授权

日期：2026-09-10。本批接在模型解析兼容 `7967fe99` 之后；仅修漫画读取链。购买服务由另一批提交，本文不把读取通过等同于扣费链已经通过。

## 问题与结果

原入口同时存在密码未执行、默认坐标/重写 ID 与凭证坐标不一致、拒绝后模板仍收到整部原址、旧详情缓存继续使用已下架或已改价内容的问题。原安装表又没有 `manga_play_server`/`manga_play_note`，此前解析批只解除该 PHP 8 异常。

当前 API、前台和密码接口先读取主库作品，再按实际源和章键解析，使用可信服务端用户、主库启用组与主库购买凭证判断权限。密码作为独立条件；只有获准的当前章返回图片。目录与模板 `obj` 保留名称、实际坐标、简介和数字 ID 动态链接，递归移除密码原文、所有章原址及服务器配置；当前图片单独放在 `manga_images`。前台与 API 不再调用核心详情缓存，也不经 Manga 模型的运行时补列逻辑。

## 入口和共享合同

| 入口/内部方法 | 本批行为 |
|---|---|
| API `Manga::get_detail` | 正整数 ID，主库发布/回收状态，安全公开目录；维持 API 公开元信息合同，不增加前台详情组校验 |
| API `Manga::get_chapter` | 保持 `code=1,info` 与 `can_read/deny_code/deny_msg/points_hint` 形状；严格实际 `sid/nid`，拒绝时 `images=[]` |
| API `Manga::verify_pwd`；前台 `Ajax::pwd` | 独立 `mid=12,type=1` 密码验证，游客 Session 支持，密码字节不因表单编码改变 |
| 前台 `Manga::detail/play`；`All::label_manga_detail` | 详情保留原组权限合同；读取页同时满足密码、组/分类、积分条件；数字、slug、编码 ID 先还原真实数字作品 ID；目录与当前图片分离 |
| `MangaResourceReader::find(array $selection)` | 单一 ID/slug 精确查询；主库 `information_schema` 确认回收列，旧表无列时只读兼容，不执行 DDL；作品业务读取强制主库 |
| `ContentResource::mangaContext(array $freshRow,array $parameters)` | 纯行解析，不读取身份、不写库；返回实际 `id/sid/nid`、当前图片、真实前后章、价格、整部标志、购买入口与凭证坐标；`current/source` 只供内部使用 |
| `All::check_manga_resource_access(array $row,array $coordinates)` | 返回内部 `can_access/password_required/password_verified/password_help_url/purchase_supported/purchase_sid/purchase_nid/code/confirm/points_hint`；API 映射既有 `can_read` |

新增 API 返回 `previous_nid/next_nid/previous_link/next_link`、密码提示和可购买入口坐标。下一章只给站内动态授权链接，不附带下一章图片。`trysee` 不能作为整章图片的许可。

输入缺省 `sid/nid=1/1`；显式非法、数组、小数、非数字尾缀或 UINT32 越界受控拒绝，不改成其他章。目录键 1/3 的下一章是 3；缺章保持缺章。显式 `Two$` 和 `0$` 保留标题和空图片地址，不能被通用播放解析器误当作可出售的站内图片路径。空章可以展示暂无图片；单章购买按钮禁用。

密码 scope 为 `12-1-作品ID`，grant 包含版本和当前密码指纹；改密码立即使旧 grant 无效，其他作品/媒体、旧布尔 grant 不通用。密码不替代积分或会员条件。会员系统关闭仍沿用原免费读取合同，但内容密码继续有效。

主库 Group 必须启用且未删除，权限 JSON 必须有效。每组解码后仅保留本次实际分类的权限子数组，避免把 32 份完整权限树同时带入读取结果。仅漫画读取规范化 `02`、`2,02` 等合法成员组表示，Group ID 按安装 signed SMALLINT 上限 32767 校验；不修改 Vod/Art 的共享业务行为。启用组的现有精确已购付费回退保持，已停用/删除组不靠旧缓存继续放行。类型名称等展示元信息可沿用缓存，实际读取权限使用作品 `type_id` 和主库组权限。业务读取是各条查询时的主库状态；不声称一次普通读取请求构成跨表锁定快照。

## 价格、购买范围与容量

计费模式只接受 0/1。单章使用正 `manga_points_detail`，否则回退 `manga_points`；整部使用 `manga_points`。合法免费价格 0 保持有效；价格必须精确可表示为 0..65535。整部凭证固定 `sid=0,nid=0`，单章凭证使用实际坐标。

Ulog 的 sid 上限 255、nid 上限 65535，不截断后写入。旧扩展目录可能出现源 256；该源免费/VIP读取仍可用，单章不支持购买。整部按钮可以指向另外一个实际非空、可存储的章：此时当前空章仍是当前空章，**购买服务必须拒绝直接提交空章扣费**。购买代理的独立服务负责锁内重读、校验实际非空图片和价格、原子扣费/账本/凭证；本批只冻结共享接口。由于本批全目录最多 20000 章，正常接受目录已不可能出现 nid>65535，早期计划中的该阅读情形不再适用。

| 解析预算 | 上限 | 处理 |
|---|---:|---|
| `manga_chapter_url` 原始字段 | 8 MiB | 超限整部受控拒绝，解析前先检查 |
| `manga_content` 简介 | 1 MiB | 防止 MEDIUMTEXT 简介与最大目录叠加超出读取内存预算；超限受控拒绝 |
| from/server/note 每个可选字段 | 4096 字节 | 超限拒绝；当前安装表仍不添加 server/note |
| 源槽 | 256 | 包括空槽，保留原键；实际安装 from VARCHAR(255) 通常先受列容量限制，源 256 为旧扩展数据兼容测试 |
| 全部章节槽 | 20000 | 包含 `#` 空槽；先计数再展开，超限不截短为另一章 |
| 单章图片槽 | 1024 | 包括空逗号槽；超限整目录拒绝 |
| 单个图片地址 | 8192 字节 | 解析前和映射后均校验 |

这些是明确的保守运行上限，不是安装列容量等同于可安全展开容量。超过上限返回受控错误并禁止收费；不静默截断。PHP 8.3.33 / 8.4.25 均用 `memory_limit=128M` 实测：8MiB/1024 图片 API 峰值 94.02MiB；20000 章、8MiB 原址及 1MiB 简介组合，目录约 79MiB、末章 API 102.01MiB。执行耗时约 0.2–0.8 秒，属于隔离测试机数据，不是线上 SLA。另将 32 个组、每组 3920 分类权限叠加最大目录独立验证：在相同 16MiB 初始分配基线下，仅保留当前分类权限使峰值从 116MiB 降至 PHP 8.3 的 84MiB、PHP 8.4 的 86MiB；详见 [普通权限容量复核](manga-permission-capacity-followup.md)。最终完整矩阵的大权限样本峰值 106.01MiB（该连续进程初始分配 80MiB）。这些探针隔离了旧 User 身份入口的完整 Group cache，不构成全站所有请求 128M 的保证。

## 图片与模板

图片地址只接受 HTTP(S)、协议相对地址和既有站内路径/`mac:` 映射；校验映射后的结果。控制字符、反斜线、带用户名密码的 URL、其他 scheme、无效端口/主机受控拒绝。一个非空坏地址使该章图片整体无效，不把恶意地址逗号后的残段当成另一个站内图片收费；真正空图片槽允许跳过。测试从未请求这些图片。

默认模板使用授权后的图片列表；图片属性、标题和导航分别按 HTML 编码，历史记录内联 JavaScript 使用 JSON HEX 编码。密码单独显示验证表单；付费时保留原购买/充值/升级组件。缺少漫画模板的主题使用本地独立详情/阅读页，购买按实际可买坐标先取新 token 再 POST；密码提交成功后重新读取页面。

数字动态链接不依赖不受支持的漫画静态路径。现存 `Make` 只找到 Art/Vod 生成，未臆造 Manga 静态生成器；`view>=2` 只给安全目录，不输出授权图片。未读取或自动删除站点旧 HTML。全站静态路径缺唯一标识的碰撞风险仍在独立待办中。

## 验证和范围

运行 `python3 tests/run_manga_resource_audit.py`：网络隔离 MySQL、安装 DDL、真实 TP8 Request/ORM/User/Session/JWT、All 权限和实际 ThinkTemplate；PHP 8.3/8.4 各验证根目录和子目录，每组合 561 项真实 PHP/MySQL 检查和 41 项模板 JS 检查。覆盖主从作品/回收 schema/凭证差异、旧详情缓存、主库组撤权、游客/会员/VIP、密码变更、实际坐标、空章/预算、递归出口和模板属性/JS 编码。`tests/manga_resource_frontend.js` 对真实生成 HTML 运行发布的 JS，以受控 DOM/fetch 验证 41 项表单合同；它不是完整浏览器网络测试，独立购买批另有 Chromium HTTP 回归。

既有兼容回归：`tests/run_manga_parser_audit.py` 每 PHP 50 项；`tests/run_api_content_view_audit.py` 每 PHP 601 项及默认 JS 13 项；`tests/run_api_prefix_audit.py` 每 PHP 400 项。既有 parser fixture 新增实际启用 Group 行，与原缓存展示数据一致，以验证现在的主库权限合同；没有调整断言来接受拒绝结果。

本批不修改其他媒体方法、Manga 锁内购买实现、采集导出信任边界、共享 RecycleBinTrait 或图片下载资产生命周期。`manga_is_vip/age_rating/lock` 没有已确认的读取策略，继续记录产品语义待定。全站 Group 缓存与运行时 DDL 治理不因漫画专用主库读取修复而被宣布完成。
