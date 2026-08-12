# 播放器注入面治理方案（player.js 链路）

> 状态：**已全量落地并在生产验证**（Phase 0–3）。Phase 4（内置 H5 直连替代外部解析）保留为可选。
> 落地记录见文末第九节。
> 触发：迁移中发现 `static/player/155m3u8.js` 漏迁导致全站播放 404，站长判断"这是 maccms 早期
> 故意留的病毒注入点"，要求审计链路、出商业级落地方案。
> 目标形态（站长原话）：**后台只需设置「播放器名 + 解析接口地址」，或直接用系统自带播放器渲染**。

---

## 一、结论先行

站长的判断成立。maccms 的播放器体系有一个**架构级注入面**：后台"添加播放器"本质是
**把一段任意 JS 写成 `static/player/<名字>.js`**，这段 JS 会在**每一个播放页**被加载并
`innerHTML` 进页面。一个拥有后台权限的人（包括被入侵后混进来的管理员——正是本站
`155palyer` 事件里的角色），**不需要 shell、不需要传木马，光靠后台正常 UI 就能给全站每个
播放页注入跳转/挂马**。这也是为什么这类站的木马经常"删了文件还在、关了 API 还发"——
入口是播放器体系本身，不是某个孤立的 webshell。

同时它也是**迁移负债**：这些自定义 JS 不在代码仓库里、散落在服务器磁盘上，换机极易漏迁
（本次 `155m3u8.js` 就是这么丢的，导致 182,511 条视频全部播不了）。

方案把播放器从"可写任意 JS 的文件"改造成"**纯配置 + 一组固定的、已审计的内置渲染器**"，
既堵死注入面，又让播放器变成可版本化、可迁移、后台可编辑的配置项。

---

## 二、链路审计（当前实现）

### 2.1 数据从哪来

播放页（主题 `vodplay` 模板）在页面里渲染一个 `player_aaaa` JSON，字段直接来自 DB：

```json
{"flag":"play","encrypt":0,"url":"https://2607.v155p.com/.../index.m3u8",
 "from":"155m3u8","id":"184392", ...}
```

- `url`   = `mac_vod.vod_play_url` 里当前集的地址
- `from`  = `mac_vod.vod_play_from`（**采集入库时写入，采集源可控**）

### 2.2 player.js 怎么渲染（`static/js/player.js`，核心在 `Init()` / `Play()` / `Show()`）

```
Init():
  读 player_aaaa → this.PlayFrom = a.from            // 例如 "155m3u8"
  查 MacPlayerConfig.player_list[PlayFrom]:
    若该播放器 ps=="1"  → this.Parse = 配置的 parse 地址; this.PlayFrom = 'parse'
    若查不到（未注册） → PlayFrom 原样保留            // ← 155m3u8 走的就是这条
  this.Path = maccms.path + '/static/player/'
  → Play()

Play():
  document.write('<div class="MacPlayer">…<td id="playleft">…')
  document.write('<scr'+'ipt src="'+this.Path+this.PlayFrom+'.js"></scr'+'ipt>')   // ★注入点①
                                        ↑ 按 from 名字动态加载任意同名 JS 文件

<被加载的 static/player/<from>.js 里>:
  MacPlayer.Html = '<iframe src="……"></iframe>'      // 该文件决定播放页长什么样
  MacPlayer.Show()

Show():
  $("#playleft").get(0).innerHTML = this.Html + ''    // ★注入汇聚点②：任意 HTML 进页面
```

**两个要害：**
- **注入点①**：加载哪个 JS，由 `from`（DB 字段，采集可控）拼出文件名决定。谁能在
  `static/player/` 放一个 `.js`，谁就能让它在播放页执行。
- **汇聚点②**：被加载的 JS 把 `MacPlayer.Html` 设成什么，就 `innerHTML` 什么——iframe 指向
  任意域名、插入任意脚本节点、`location` 跳转，全都可以。

### 2.3 后台"添加播放器"就是写这个 JS 文件（`application/admin/controller/Vodplayer.php`）

```php
// info() 保存播放器：
$code = $param['code'];                                             // 后台一个文本框，原始 JS
...
$res = mac_arr2file(APP_PATH.'extra/vodplayer.php', $list);         // ① 存配置（name/ps/parse/…）
$res = fwrite(fopen('./static/player/'.$param['from'].'.js','wb'), $code);   // ② ★把 JS 落盘
```

`import()`（line 161）同理，从上传的 `.txt` 里 base64 解出 `code` 再落盘。
`export()` 把「配置 + code」打包 base64 导出——这就是采集圈"播放器分享"的流通方式，
也是这套机制存在的历史原因。

**现有的部分加固**（本 fork 已加）：`from` 不允许含 `.` `/` `\`（line 38/147），挡住了
路径穿越。但**"写任意 JS 内容并在全站执行"这个核心面没动**。

### 2.4 两种渲染范式已经并存

| 范式 | 配置 | 加载的文件 | 说明 |
|---|---|---|---|
| **解析播放器** | `ps=1, parse=<地址>` | 内置 `parse.js` | iframe 指向 `parse+url`，**带 sandbox**。`modum3u8` 就是这么配的 |
| **内置 H5 播放器** | `ps=0, from=dplayer` | 内置 `dplayer.js`→`dplayer.html` | 同源页面用 hls.js **直接播 m3u8**，无外链 |
| **野播放器（问题所在）** | 未注册 | 自定义 `<from>.js` | `155m3u8` 走这条：硬编码 iframe 到 155jx，靠裸文件 |

**关键事实**：`155m3u8`（DB 里 182,511 条在用）**根本没注册进配置**，`Init()` 查不到它，
才掉进"加载裸文件"的兜底。而配置里的 `modum3u8`（`ps=1, parse=https://jiexi.moduzyjx.com/?url=`）
**正是站长想要的形态**——纯配置、走内置 `parse.js`、零自定义文件。

也就是说：**目标能力框架里本来就有，`155m3u8` 只是当年没按正规方式配。**

---

## 三、威胁模型

| # | 攻击者能力 | 现状下的后果 | 谁受影响 |
|---|---|---|---|
| T1 | 拿到后台（弱口令/脱库/混进的 rogue admin） | 后台加个播放器＝往全站每个播放页注入任意 HTML/跳转，不碰 shell | **全站访客** |
| T2 | 能写 `static/player/` 目录（上传漏洞/投毒/供应链） | 放 `<常用from名>.js`，采集数据一旦命中该 from 即全站生效 | 全站访客 |
| T3 | 控制采集源 | 把 `vod_play_from` 设成某个已存在的恶意 `.js` 名，借道①执行 | 采集了该源的站 |
| T4 | 换机迁移 | 自定义 JS 不在仓库，漏迁→功能坏（本次已发生）；或带毒迁移 | 站长自己 |

T1 是最现实的——它把"后台权限"直接放大成了"全站 XSS/挂马"，且**看起来是正常功能操作**，
审计日志里毫不起眼。

---

## 四、目标架构

播放器 = **纯配置对象**，没有任何可执行文件伴随：

```
{ from, show, ps, parse, target, sort, status }   // 就这些，全是数据，无 code
```

渲染只走**一组固定的、随仓库版本化、经过审计的内置渲染器**（白名单）：

```
parse    ps=1 + parse=<地址>  → 内置 parse.js，sandbox iframe 到 解析服务   （站长要的「名字+解析地址」）
dplayer  ps=0                 → 内置 H5，hls.js 同源直接播 m3u8            （站长要的「自带播放器渲染」）
videojs  / iva                → 内置 H5
flv / swf / link / iframe     → 内置固定渲染
```

- **加播放器** = 后台填「名字 + 类型/解析地址」，写的是**配置**，不是文件。
- **static/player/ 下只允许存在白名单内的内置文件**，多一个都视为异常（见 5.3 自检门禁）。
- `vod_play_from` 只能解析到白名单渲染器；命不中就显示"不支持的播放来源"，**绝不 document.write 任意文件**。

---

## 五、落地方案（分阶段，每阶段可独立验证、可回滚）

### Phase 0 —— 把 155m3u8 从"裸文件"迁成"配置驱动"（立即，先解现网 + 消除现存唯一自定义文件）

**动机**：现网就这一个自定义播放器文件在用；先把它正规化，既验证目标形态可行，又为后续
删除机制扫清障碍。**不改任何代码，只改配置**，风险最低。

1. 在 `application/extra/vodplayer.php`（服务器 extra 覆盖层）注册 `155m3u8`，对齐 `modum3u8`：
   ```php
   '155m3u8' => [
     'status'=>'1','from'=>'155m3u8','show'=>'155解析','des'=>'','target'=>'_self',
     'ps'=>'1','parse'=>'https://www.155jx.com/?url=','sort'=>'9','tip'=>'',
   ],
   ```
2. 重生成 `static/js/playerconfig.js`（后台清缓存即触发 `Base.php:206` / `System.php:999`
   从配置重写该 JS）。
3. 此时 `Init()` 命中 `player_list['155m3u8'].ps==1` → 走内置 `parse.js`（带 sandbox），
   iframe 仍指向 `https://www.155jx.com/?url=<m3u8>`——**行为与现在完全一致，但不再依赖裸文件**。
4. 验证：`vodplay/184392-1-1.html` 播放正常、iframe 目标不变。
5. 删除 `static/player/155m3u8.js`（仓库两处 + 各服务器）。

**产出**：全站零自定义播放器文件；`155m3u8` 变成后台可编辑的配置项；`parse.js` 的 sandbox
反而比原裸文件更安全（原文件没有 sandbox）。**完全可逆**（把文件放回即恢复）。

### Phase 1 —— 关掉后台的"写 JS 文件"能力（`Vodplayer.php`）

- `info()` 删除 line 54 的 `fwrite(... '<from>.js' ...)`；保存只写配置。
- `info()` 表单去掉 `code` 文本框（`admin@vodplayer/info.html`），保留 `from/show/ps/parse/target/sort`。
- `import()` 删除 line 161 的落盘；导入时**忽略** `data['code']`（老的分享包仍能导入，只是丢弃 JS）。
- `export()` 只导出配置（去掉 `code`）。
- 兼容旧数据：`info()` 保存时校验——`from` 若不是白名单内置渲染器，则**必须** `ps=1 且 parse 非空`
  （即强制走解析范式），否则报错拒绝。杜绝再造"未注册野播放器"。

**产出**：后台再也无法产生可执行文件；播放器彻底变成纯配置。

### Phase 2 —— 加固 player.js（把动态加载收敛到白名单）

`static/js/player.js` 的 `Play()`：

```js
// 白名单：只有这些内置渲染器允许被加载
var ALLOW = {parse:1,dplayer:1,videojs:1,iva:1,iframe:1,link:1,swf:1,flv:1};
if (!ALLOW[this.PlayFrom]) {
    $("#playleft").get(0).innerHTML =
        '<div style="color:#fff;padding:20px">不支持的播放来源，请在后台配置解析接口</div>';
    return;                         // 绝不 document.write 任意文件名
}
document.write('<scr'+'ipt src="'+this.Path+this.PlayFrom+'.js"></scr'+'ipt>');
```

- 效果：即便有人往 `static/player/` 丢了 `evil.js`、并把某视频 `vod_play_from` 设成 `evil`，
  **不在白名单就不加载**，注入点①被彻底堵死。
- `from` 未注册也不会再掉进"加载裸文件"兜底——它会命不中白名单，显示提示。
- 纵深防御（可选）：把 `Show()` 的 `innerHTML` 换成构造已知 `<iframe>` 元素并只 set `src`，
  但白名单在上游已是主闸，此项为加分项。

**产出**：DB 里的 `from` 字段再也无法指名加载任意文件；采集投毒（T3）失效。

### Phase 3 —— 自检门禁 + 制度（防回归 + 兼作迁移完整性检查）

- `mac:selfcheck` 增加一项：枚举 `static/player/*.js`，凡不在白名单
  （`dplayer/videojs/iva/iframe/link/swf/flv/parse/mac-play-child-bridge`）者一律 **FAIL**。
  - 它同时是**安全绊线**（未来谁再往这目录丢 JS，部署自检即红）
  - 也是**迁移完整性检查**（任何"服务器上有、仓库没有"的播放器文件会被立刻发现——正是本次
    `155m3u8.js` 漏迁那类问题的通用兜底）。
- 文档化制度（本文件即制度载体）：**播放器一律配置化**。新增播放器＝后台填"名字 + 解析地址"，
  或选内置 H5 类型；**禁止**向 `static/player/` 投放 JS；违者 selfcheck 拦截。

### Phase 4（可选）—— 用内置 H5 直连替代外部解析

对能直连的源（如 `*.v155p.com/*.m3u8`），评估内置 `dplayer`（hls.js，同源）能否直接播放。
可行则把 `155m3u8` 从 `ps=1` 改为内置 H5（`ps=0`），**播放页彻底不再嵌任何第三方 iframe**，
外部依赖（155jx.com）也随之消失，安全性最高。

**须逐源实测**：很多源有防盗链/Referer 校验/加密，直连播不了才用外部解析——所以这一步保留
解析范式作兜底，不强推。

---

## 六、灰度与回滚

| 阶段 | 改动性质 | 灰度 | 回滚 |
|---|---|---|---|
| Phase 0 | 仅配置 | 先 155api 后主站 | 放回 155m3u8.js 即恢复 |
| Phase 1 | 后台控制器 | 金丝雀 155api → 主站 | git revert |
| Phase 2 | 前端 player.js | 金丝雀 → 主站，实测播放 | git revert；player.js 带 `?t=` 版本号，回滚即时生效 |
| Phase 3 | selfcheck | 部署即生效 | git revert |

- DB 里 182,511 条 `from=155m3u8` **全程不动**——变的只是这个 `from` 如何被**渲染**（配置而非文件）。
- 每阶段以 `vodplay` 真实页 + 解析出流作为验收，金丝雀绿了再上主站。

---

## 七、改动清单（供实施对照）

| 文件 | 改动 | 阶段 |
|---|---|---|
| `application/extra/vodplayer.php`（服务器） | 注册 `155m3u8`（ps=1,parse=155jx） | 0 |
| `static/player/155m3u8.js`（仓库+服务器） | 删除 | 0 |
| `application/admin/controller/Vodplayer.php` | `info()`/`import()` 去掉写 JS；导出只配置；保存校验强制 parse/内置 | 1 |
| `application/admin/view/vodplayer/info.html` | 去掉 `code` 文本框 | 1 |
| `static/js/player.js` `static_new/js/player.js` | `Play()` 加白名单闸门 | 2 |
| `application/command/SelfCheck.php` | 新增 `static/player/*.js` 白名单检查 | 3 |
| `docs/security/player-injection-hardening.md` | 本文件（制度载体） | 3 |

---

## 八、一句话总结

播放器体系当前是"**后台可写、全站执行的任意 JS**"——这既是站长指出的注入点，也是迁移丢文件的
根源。方案把它收敛成"**纯配置 + 固定白名单渲染器**"：后台只填名字和解析地址（或选自带 H5 播放器），
`static/player/` 只允许存在版本化的内置文件，自检门禁兜底。改造对现网播放行为无感，DB 数据零改动，
分阶段可回滚。

---

## 九、落地记录（2026-08-12，Phase 0–3 全量上线并生产验证）

**Phase 0 — 155m3u8 迁成配置驱动**
- `application/extra/vodplayer.php` 注册 `155m3u8`（`ps=1, parse=https://www.155jx.com/?url=`，对齐 modum3u8）。
- `static/js/playerconfig.js`、`static_new/js/playerconfig.js` 的 player_list 缓存段按 Base.php
  同款逻辑重生成（含 155m3u8+modum3u8，转义格式与框架一致，消除了原仓库该文件的陈旧问题）。
- 删除 `static/player/155m3u8.js`（仓库两处 + 两服务器经 REMOVED_PATHS 传播删除）。

**Phase 1 — 关掉后台写 JS 的能力**
- `Vodplayer.php`：`info()`/`import()` 移除向 `static/player/<from>.js` 落盘；`export()` 只导配置；
  保存/导入新增校验——非内置类型必须 `ps=1 且 parse 非空`，否则拒绝。
- `admin/view/vodplayer/info.html`：删除「播放器代码」标签页与 `code` 文本框。

**Phase 2 — player.js 白名单闸门**
- `static/js/player.js`、`static_new/js/player.js` 的 `Play()` 在动态加载前加白名单
  `{parse,dplayer,videojs,iva,iframe,link,swf,flv}`；不在名单一律不加载，显示提示。

**Phase 3 — 自检门禁 + 孤儿清理**
- `SelfCheck.php` 新增 `checkPlayerFiles()`：`static/player`、`static_new/player` 下非白名单
  `.js` 一律 FAIL。
- 删除孤儿 `static_new/player/wjyun.js`（未注册、0 视频使用）。
- `bin/deploy-155.sh` 的 `REMOVED_PATHS` 加入 155m3u8.js / wjyun.js（两目录）。

**验证（生产实跑）**
- 部署后两站 `mac:selfcheck` **FAIL 0**（含新增 player 检查），冒烟 200。
- `static/player/155m3u8.js` → 404（已删）；`parse.js` → 200。
- **端到端等价性**：用部署后真实 `playerconfig.js` + Init/parse 逻辑在 node 复算，
  `from=155m3u8` → `PlayFrom=parse` → iframe src =
  `https://www.155jx.com/?url=<m3u8>`，与旧裸文件**逐字节一致**。
- **拦截验证**：`from=evil` / `../../x` / `155m3u8_hack` 全部被白名单拦下，不加载任何文件；
  `155m3u8` / `modum3u8` / `dplayer` 正常放行。
- 线上 `vodplay/184392-1-1.html` HTTP 200，player.js 已含白名单，155jx 解析服务在线。

**结果**：后台不再能产生可执行的播放器文件；DB 的 `vod_play_from` 无法再指名加载任意
JS；`static/player/` 由自检守死为「只有内置渲染器」。全站 182,511 条 `from=155m3u8`
播放行为无变化，DB 零改动。
