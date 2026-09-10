# API 内容访问控制 A1：公开数据与密码明文出口

**本组仅收口公开详情/目录 DTO 与六个密码模板的明文输出，不是整条内容授权链的完成报告。** 播放、下载资源接口和文章/漫画访问密码校验仍需 A2/A3，见文末。

## 变更

新增 `PublicContentView` 明确投影允许公开的标量元数据与嵌套目录。Vod/Art/Manga 的 get_detail，以及使用 `listData('*')` 的 Manga::get_list，在返回 JSON 前应用投影。未知数据库列、整个分类/会员组配置、播放器/服务器配置不会自动随整行输出。

公开元数据保留标题、封面、简介、时间、标签、评分、积分提示、分类显示字段、VIP 标记、收藏状态和站内链接。视频 vod_content、漫画 manga_content 是介绍字段，仍保留；文章 art_content 是正文，不能作为免费介绍返回。图片封面 URL 和站内详情/播放/阅读链接仍公开，不能将“删除资源原址”误解为删除所有链接。

| 入口 | 不再输出的直接字段 | 不再输出的嵌套数据 | 保留/替代 |
| --- | --- | --- | --- |
| Vod::get_detail | vod_pwd、vod_pwd_play、vod_pwd_down，以及密码获取地址原列、play/down 原始 URL/server/note 等内部列 | vod_play_list/vod_down_list 的资源 url；player/server 配置仅投影必要显示名 | has_password、has_play_password、has_down_password 布尔值；来源、显示名、剧集名称、sid/nid、站内 play_link/down_link |
| Art::get_detail | art_pwd、art_pwd_url、art_content、未知内部列 | art_page_list 不含正文；type/type_1/group 不含内部配置 | has_password；page/title/note 目录、总数、前后篇和站内详情链接 |
| Manga::get_detail | manga_pwd、manga_pwd_url、manga_chapter_url/from、manga_play_server/note、未知内部列 | manga_page_list[sid].url/server 等原址或配置；urls[nid].url 及其他内部属性 | has_password；保留一基 source/episode 键、sid、from/note、url_count、name/nid、站内 play_link |
| Manga::get_list | 同样去掉 pwd/chapter_url 等整行内部列 | 分类/会员组只返回显示字段；若出现目录也使用同一投影 | 原 code/page/pagecount/limit/total/list 外层保持，记录增加布尔密码提示 |

布尔密码提示仅表示“配置了密码”，不表示用户已经通过校验。裸媒体地址没有标题分隔符时，视频目录使用“第 N 集”或“下载 N”，避免把原地址换个 `name` 字段继续泄露。没有删除目录：默认主题的视频目录只消费来源显示名和剧集名称并构造站内播放页链接；漫画目录消费名称、计数、键和站内阅读链接；文章目录消费页码和标题。

六个模板仅删除“无获取链接时直接显示保存密码”的 else 分支，保留输入框、验证按钮及原 mid/type/id，保留现有获取密码链接：

- template/default/html/vod/player_pwd.html
- template/default/html/vod/detail_pwd.html
- template/m1938pc3_v2/html9/vod/player_pwd.html
- template/m1938pc3_v2/html9/vod/detail_pwd.html
- template/m1938pc3_v2/html9/vod/downer_pwd.html
- template/m1938pc3_v2/html9/art/detail_pwd.html

m1938pc3_v2 的 player/downer 模板原先按操作密码获取地址判断、链接却读取 vod_pwd_url；本组没有更改这个旧链接选择行为，需在后续密码合同组单独核对。没有修改任何密码会话作用域、身份、分类授权、积分或扣费规则。

## 验证

```sh
python3 tests/run_api_content_view_audit.py
python3 tests/run_api_prefix_audit.py
```

新 runner 依赖 Python、Docker 及 Node.js，创建一次性 MySQL，容器禁网、代码只读挂载，通过 socket 连接。只使用合成配置和数据；没有站点配置或业务数据库访问。

- 使用真实 Request、控制器、模型/ORM、common.php 中的文章/漫画目录解析器和 VIP 附加函数；URL 格式器与分类缓存由 fixture 隔离。
- 密码、正文、每层资源地址、播放器/服务器/分类/会员组私有字段及新增未知列使用不同私有标记，递归核对 JSON 不含这些标记或敏感字段；同时检查免费显示信息和目录结构。
- 有/无密码、有/无目录、多个来源、多章、一基漫画目录键、裸媒体地址、漫画列表和关联显示字段均有实际响应检查。
- 通过真实 TP8 模板引擎渲染上述六个当前密码模板，各覆盖有/无获取链接；仅隔离独立的全局 JS include，密码条件及表单保持实际源码，确认不打印密码且仍可输入、提交和获取密码。
- 把 PHP 实际输出的 DTO 交给仓库当前的三个默认详情 JavaScript，在隔离 DOM/fetch 下执行；检查实际来源标签、章节 HTML 和站内链接，不发送外部请求。
- PHP 8.3.33 / MySQL：600 项 DTO/模板检查 + 13 项实际 JavaScript 检查通过。
- PHP 8.4.25 / MySQL：600 项 DTO/模板检查 + 13 项实际 JavaScript 检查通过。
- 原前缀/Collection 回归两版均保持 400 项通过；未修改其 fixture 或期待。

这是当前仓库默认主题的兼容证据。仓库外客户端如果依赖原始密码或直接媒体地址，必须迁移到布尔提示、安全目录与授权后的资源接口；没有宣称外部客户端全部无需调整。

## 尚未闭合的访问链

1. **A2 优先：Vod::get_play_info / get_down_info 仍返回原始 current 和完整 play_list/down_list，未执行完整身份、分类、积分、密码授权。** 本组没有把它们当作公开目录直接清空，避免在未实现授权替代接口前暗中破坏其资源用途；也不因此声称资源访问已安全。
2. All::label_user 与纯 Bearer 用户上下文、单集/整条购买、当前集资源投影和试看能力，仍按 [访问控制计划](api-content-access-plan.md) 单独修复。买一集不能获得未购买集的原址。
3. Art/Manga 的访问密码、前台与 API 阅读门控、缺失的漫画密码验证动作、文章先授权后钳制页码等仍待 A3。A1 的 has_password 是提示，不是门控。
4. 发布/回收状态、严格参数、旧 SQL 时间条件、查询上限、缓存命名空间等继续分批处理。Actor 既有 status 0/1 合同没有改动。
