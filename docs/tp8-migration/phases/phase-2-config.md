# P2 · 配置体系 → `config/` + `.env`

## 目标

把 TP5.0 的**扁平配置**(`config.php` 251 行 + `extra/` 10 个文件)迁成 TP8 的**分组 `config/` 目录 + `.env`**,并改写 **341 处 `config()`** 调用的 key 路径。

## 前置依赖

P1(目录/框架就绪)。

## 改动清单

| 现状 | 目标 | 备注 |
|---|---|---|
| `application/config.php`(251) | `config/app.php` `database.php` `cache.php` `session.php` `cookie.php` `view.php` `route.php` `log.php` … | 按 TP8 分组拆 |
| `application/extra/addons.php` | `config/addons.php` | |
| `extra/bind.php` | 多应用路由(P1) | 不再用 bind |
| `extra/blacks.php` `domain.php` `captcha.php` `maccms.php` `mctheme.php` `queue.php` `quickmenu.php` `timming.php` | `config/<同名>.php` | maccms 业务配置整体迁 |
| 敏感项(库密码/密钥/各云密钥) | `.env`(不入仓库)+ `config` 读 `env()` | |
| 341 处 `config('x')` | `config('group.x')` | 按映射表改写 |

## 设计要点

- **先产出"旧 key → 新 key"映射表**(P2 第一轮),再用映射驱动改写——**禁止纯正则**(否则改错组)。
- `config('maccms.xxx')` 这类 maccms 自有配置:整组迁到 `config/maccms.php`,key 路径尽量保持 `maccms.xxx` 以**减少调用点改动**。
- **保留安全相关配置不变量**:`var_method=''`(禁 `_method` 伪装)、`show_error_msg` 关闭(生产不回显)、cookie/session 安全项 —— 见 `security-invariants.md`。
- 多语言 `lang/`、路由 `route.php` 在 P5/P6 处理,本阶段只搬配置。

## 切片建议(每轮先分析)

- ROUND:生成旧→新 key 映射表(`docs/tp8-migration/config-key-map.md`)
- ROUND:框架级配置(app/database/cache/session/cookie/view)+ `.env`
- ROUND:maccms 业务配置(maccms/mctheme/addons/captcha/...)
- ROUND:341 处 `config()` 按映射改写 + 删旧 `config.php`/`extra/*`

## 风险 & 安全不变量

🟠 中。**触碰 INV-2/7/8**(var_method、cookie/session 安全、Init 相关配置)。改写后逐项确认安全配置值未变。

## 验证

```bash
# 映射改写后:确认无遗留扁平 key 读取报错
php -S 127.0.0.1:8800 -t public public/router.php
# 抽查关键配置在 8.4 下读出值与 baseline 一致
php think_test_config.php   # P2 临时脚本:打印关键安全配置项做对照
```

冒烟行:#18(系统配置保存)、#27(install 写配置)。

## 退出标准(DoD)

- [ ] `config/` 分组完整,旧 `config.php`/`extra/*` 已删
- [ ] key 映射表归档,341 处调用改写完成,无"undefined config"
- [ ] 安全配置项值与 baseline 逐项一致(var_method/show_error_msg/cookie/session)
- [ ] `.env` 接管敏感项且不入仓库
- [ ] tag `tp8-p2-done`

## 回滚

阶段 tag 回滚;配置与调用点改写集中,可整阶段 revert。
