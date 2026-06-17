# P6 · 助手 / 会话 / 缓存 / Cookie / 路由 / common.php

## 目标

收口剩余的 TP5.0 助手与门面:**Cache 265 / Cookie 118 / Session 54 / input 371 / url 277 / Request 43**,迁移 **`common.php` 174 个 `mac_` helper** 内部的 TP API,拆分路由到 `route/`。

## 前置依赖

P1–P5(框架/配置/数据/视图就绪)。

## 改动清单

| 项 | 计数 | 处置 |
|---|---|---|
| `Cache::`/`cache()` | 265 | `use think\facade\Cache;` / 助手 |
| `Cookie::`/`cookie()` | 118 | `use think\facade\Cookie;` / 助手 |
| `Session::`/`session()` | 54 | `use think\facade\Session;` / 助手;**set/get API 微调需验** |
| `input()` | 371 | think-helper 基本兼容,**逐类型签名验**(`input('post.x')` 等) |
| `url()` | 277 | think-helper / `Route::buildUrl`,**行为/签名验**(参数拼接、域名) |
| `Request::instance()`/`request()` | 43 | 优先注入 `Request $request`;`request()` 助手保留 |
| `common.php` 174 `mac_` helper | — | 函数体内的 `config/cache/Db/url/...` 调用随上面一起迁 |
| `application/route.php`(7.5K) | — | 拆 `route/index.php` `admin.php` `api.php` |

## 设计要点

- 门面替换(Cache/Cookie/Session)机械、低风险,Rector 批量。
- **Session 重点验**:TP8 Session 不再自动 `start`,读写时机/API 与 TP5 有别——登录态、验证码、购物流程都依赖,**按 🔴 验**(关联 INV-7)。
- **`url()` 重点验**:SEO 伪静态、播放/分页链接大量用 `url()`,行为差异会导致链接错乱——黄金 diff 重点看 `href`。
- **common.php 安全不变量**:`mac_arr2file()` 用 `var_export()`(防配置闭合注入)、`mac_curl_get` 的 SSRF 防护态势——**保留**(见 `security-invariants.md` 非行为类项)。
- `cookie()` 安全:登录态 cookie 的常量时间比较(`hash_equals`)、HttpOnly/SameSite——保留。

## 切片建议(每轮先分析)

- ROUND:Cache/Cookie 门面批量(低风险)
- ROUND:Session 迁移 + 登录态/验证码/购物流程冒烟(🔴)
- ROUND:input 签名核对(分 get/post/param/request)
- ROUND:url 行为核对 + 链接黄金 diff
- ROUND:Request 注入收口
- ROUND:common.php 174 helper 内部 API 迁移 + 路由拆分

## 风险 & 安全不变量

🟠 中,**Session 轮 + common.php 轮按 🔴**:触碰 INV-7(会话)、INV-8/非行为类(common.php 安全函数)。

## 验证

```bash
find app -name '*.php' -print0 | xargs -0 -n1 php -l >/dev/null && echo lint-ok
php -S 127.0.0.1:8800 -t public public/router.php
bash tests/golden/diff.sh                          # 链接/页面等价
bash tests/security/check_invariants.sh INV-7      # 会话
```
冒烟行:#6 #8 #15 #26 + 全前台链接抽查。

## 退出标准(DoD)

- [ ] Cache/Cookie/Session/input/url/Request 全部收口,`php -l` 绿
- [ ] 登录/验证码/会话流程等价(INV-7 绿)
- [ ] url 链接黄金 diff 全绿
- [ ] common.php helper 迁移完成,**mac_arr2file/var_export、SSRF 防护、cookie 常量比较保留**
- [ ] 路由拆分到 `route/`
- [ ] tag `tp8-p6-done`

## 回滚

按 helper 类别分批,可逐类 revert;Session/common.php 单独成轮便于隔离。
