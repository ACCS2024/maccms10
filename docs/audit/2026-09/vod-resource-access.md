# Vod 资源与密码授权（A2b / A3 视频子批）

本批收口普通视频 API、前台播放/下载、目录模板与密码验证链。它依赖已提交的 A2a 可信身份与缓存策略；不代表文章、漫画、采集导出或购买写入整体已完成。没有读取真实站点配置、备份或业务库，没有访问媒体地址、发送外部请求或删除站点文件。

## 真实触发与根因

1. `api/Vod::get_play_info/get_down_info` 在正常匿名请求时直接返回当前资源及完整解析目录，没有调用用户组、积分或内容密码检查。只删除顶层原始地址仍会通过 `*.urls.*.url`、源 `url`、播放器/服务器配置泄露。
2. `All::label_vod_play` 的 `player` 分支使用另一权限编号，试看也把完整媒体地址交给浏览器；`url_next` 和整个下载目录可能包含未获准集。前台 `play/down` 与 `player/downer` 的密码检查入口不一致。
3. 三个视频密码原本各有独立 session scope，旧值 `1` 不绑定当前密码。修改密码后，已有授权仍然有效。API 与前台对字符串 `0`、数组、精确密码值的处理不同。
4. `index/Ajax::data(mid=1)` 删除原始媒体地址后仍返回三种原始密码；`label_vod_role` 仍把整条视频记录赋给模板。旧主题的复制框、第三方解析链接也直接引用目录原址。
5. `mac_param_url` 会先强制转换坐标、对字符串字段 trim；数组输入能在前台构造阶段触发 PHP 8 错误。目录排序或空集造成的实际 sid/nid 与前端压缩数组下标也可能不同。
6. 后台 Make 的 view 2/3/4 跳过访问检查，将播放/下载资源写成公开静态文件。静态文件无法按访问者重新检查购买凭证和密码。

## 本批响应与业务合同

- `ContentResource::vodContext(array $freshRow, string $operation, array $parameters): array` 是纯解析工具。调用方先以 `infoData(..., '*', 0)` 获取新鲜、完整并已解析目录的行；`operation` 仅为 `play/down`。工具校验发布/回收状态、真实目录坐标和服务器价格，缺省 sid/nid 为 1；显式零、数组、浮点、科学计数、溢出及不存在的集不会映射成其他资源。
- 成功返回 `code=1, id, sid, nid, previous_nid, next_nid, points, whole, ulog_mid, ulog_type, ulog_rid, ulog_sid, ulog_nid`，以及仅供服务端使用的 `source/current`。整条内容计费使用 `vod_points` 和凭证坐标 0/0；否则使用对应 play/down 价格与实际 sid/nid。`0` 是合法免费价格。
- **工具返回值不得整包序列化。** 两个 API 保留原 `code/msg/info`、显示字段及 1-based 目录；目录只包含名字、来源显示名、实际坐标和 `play_link/down_link`。`current` 只有获准时才包含 `name/nid/from/url`，否则为 `null`。
- 新提示为 `can_play/can_down`、`deny_code/deny_msg`、`points_hint`、`password_required/password_verified/password_help_url`、`preview_available`。畸形坐标返回 1001，不存在资源返回 1002；权限拒绝仍返回可展示目录，密码未通过的 `deny_code=6001`。正确密码不能替代购买，VIP 不能绕过内容密码。现有禁用会员系统时的用户组/积分语义保留，但密码仍有效。
- 授权只读取 A2a `label_user()` 验证后的服务器用户。保留既有 `check_user_popedom` 对用户组、VIP、积分、单集/整条购买的业务解释。凭证匹配用户、媒体、操作、真实资源、实际坐标和当前精确价格；访问请求不扣费、不创建凭证。
- 三个密码继续独立：详情 `1-1-id`、播放 `1-4-id`、下载 `1-5-id`。新 session grant 包含版本与当前 scope+密码摘要，换密码立即失效；旧裸 `1` 需要重新验证。游客可建立内容密码 session，之后仍需要独立用户/购买授权。四份实际浏览器密码发送器编码密码值，保留 `&/+/#/中文/0`。
- 前台 `play/player` 只交付获准当前媒体；所有 `url_next` 为空，前后集是重新授权的页面链接。完整媒体地址不能作为安全试看，本批不提供这种试看资源，API 明确 `preview_available=false`。
- 下载页保留所有目录项，逐项判断是否可以输出真实地址；未获准项显示获取权限链接。160 集只读取一批精确凭证，1200 集分为三批，每批最多 500 个坐标；不会每集查询，也不会反复解析整个目录。API 当前资源检查仅查询当前凭证。
- 默认主题及 m1938、demo、stui、vozy 的目录复制/跳转使用受控页面链接，保留集名、来源、复制和播放入口。默认 AJAX 视频目录使用 DTO 返回的真实 `play_link`，不按压缩下标重新编号。密码帮助链接做 HTML 输出编码。

## 静态生成的临时受控行为与下一组

本批暂时拒绝静态播放/下载 view 2、3、4。`Make::info()` 在任何页面写入、进度更新之前返回明确失败；不会继续 `buildHtml` 或报告成功。把播放和下载配置为动态后，静态详情的安全目录生成仍可继续。共享标签入口也拒绝静态资源输出，防止其他调用方绕过 Make。

**这不是永久功能删除方案。下一独立子批必须优先恢复安全静态链接：生成跳转到动态授权入口的页面或安全页面外壳，验证路由、原静态链接兼容和空集目录；之后再判断确定匿名公开内容是否可直接生成。** 文章、漫画完整权限链在此子批之后继续。

本改动不会清除既有静态 HTML。部署时必须识别并重新生成/移除旧播放与下载 HTML，清理其 CDN 缓存；否则旧文件仍可能包含媒体地址。这里没有执行任何线上删除或缓存清理。

## 验证与实际界限

`python3 tests/run_vod_access_audit.py`：专用随机 MySQL 数据库，网络关闭，仅 Unix socket；按当前安装 SQL 建表，前缀 `audit_resource_`。实际 Request、API 构造、ORM/User/JWT/Session/Cookie/权限方法/模板引擎均参与。隔离的是站点展示配置、SEO、收藏/标签展示及路由输出；不加载真实站点引导。前台以实际资源方法捕获 view，再渲染仓库实际目录和密码模板；畸形输入另直接调用真实前台构造函数。

- PHP 8.3.33 / 8.4.25：各 3,030 项实际模型/权限/模板检查。
- 实际四份密码发送器和默认视频目录 JS：38 项。
- 同期回归：公开 DTO 600 + 实际默认 JS 13 / PHP；A2a index 244 + api 188 / PHP；19 查询前缀/Collection 400 / PHP。
- 覆盖免费两计费模式、Cookie/Bearer、游客/普通会员/VIP/组拒绝、他人/其他视频/其他集/其他操作/旧价凭证、整条凭证、密码 scope/变更/旧 grant/游客 session、改写 ID、空集和下一集、缓存旧行后的状态变更、试看与直接 player、单集下载和长目录查询上界、实际模板、Make 失败与静态详情安全目录。

当前安装 DDL 中 `ulog_sid` 为 TINYINT UNSIGNED（255），`ulog_nid/ulog_points` 为 SMALLINT UNSIGNED（65535）；工具的 UINT32 目录坐标不代表凭证一定可写。购买层必须在写前拒绝当前 schema 无法精确保存的坐标/价格，不能依赖 MySQL 截断；扩容需要独立迁移。工具不承担扣费、事务、CSRF 或凭证持久化。

仍待后续：Art 正文/rss/页码/相邻页/密码链，Manga 当前章节与其他章节/密码链，index/User、api/User、api/Payment 与 Ulog 的购买身份/真实坐标/CSRF整合，采集导出接口的配置授权，公开元数据的发布/回收可见性策略。`vod_lock` 的采集更新锁与主题禁播语义冲突，以及 copyright_status 不同入口的策略不一致，需另行统一，未在本批改为全局封禁。自定义主题直接通过模型或自定义标签另查原始数据也不属于本批已验证模板合同。
