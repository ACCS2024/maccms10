# P8 · 三方库收口 & PHP 8.4 → 8.5

> 本阶段直接落地 `PHP85_UPGRADE_AUDIT.md` 的结论。迁到 TP8 后,**用 composer 正经管理三方库**,清掉死重量,弃用清零,然后从 8.4 抬到 8.5。

## 目标

1. 按审计执行**低成本移除**与**升级**。
2. PHP 8.4 弃用日志**清零**。
3. 切 PHP 8.5,弃用**复零**。

## 前置依赖

P1–P7(TP8 业务跑通)。

## 改动清单(对照 PHP85_UPGRADE_AUDIT.md)

| 动作 | 对象 | 依据 |
|---|---|---|
| 🗑️ 移除 | `think-queue`(0引用)、`think-installer`(构建期)、`extend/aws`(aws.phar 缺失,S3 已坏) | 审计 §3 |
| 🗑️ 移除(按配置) | `extend/upyun`(裹 Guzzle6)、`extend/qiniu` | 审计 §3,**需确认线上未启用** |
| ⬆️ 升级 | PHPMailer 6.0.3 → 6.9.x(支持 8.5) | 审计 §5 |
| ⬆️ 升级(如保留) | Qiniu 7.2.2→7.14、Upyun→Guzzle7 | 审计 §5 |
| ♻️ 替换 | `PclZip`(197K,含 ereg)→ 内置 `ZipArchive`(已在用) | 审计 §4-K |
| 🧹 清理 | `Alipay.php:119` 的 `get_magic_quotes` 死分支 | 审计 §4 |
| ⬆️ composer 化 | 能 composer 管的三方转 require(PHPMailer/Qiniu/Guzzle) | 审计 P0-1 |

## 设计要点

- TP8 已是 composer 项目(P1),此时**把可托管的三方库从手工 vendored 转 composer require**,留下账本。
- **弃用清零方法**(对照 PHP85 审计 §6):`error_reporting=E_ALL`、`display_errors=Off`、`log_errors=On`,跑全冒烟矩阵,收集 `E_DEPRECATED` → 逐条收口。注意 **3250 处 `@` 抑制**会掩盖弃用,排查期临时去抑制。
- TP8 框架本身对 PHP 8.x 友好,P2-P6 已消化大部分;本阶段主要是**三方库 + 残余业务弃用**(隐式可空参、null 传非空等)。

## 切片建议(每轮先分析)

- ROUND:低成本移除(think-queue/installer/aws + 按配置 upyun/qiniu)+ 冒烟无回归
- ROUND:PHPMailer 升级 + 邮件冒烟;Qiniu/Upyun 视保留升级
- ROUND:PclZip → ZipArchive(在线更新解压)+ 清死分支
- ROUND:PHP 8.4 弃用日志清零(去 `@` 抑制跑基线 → 收口)
- ROUND:切 docker `target-8.5`,弃用复零 + 全冒烟

## 风险 & 安全不变量

🟠 中。移除存储驱动前**必须确认线上未启用**(否则断上传)。在线更新(PclZip→ZipArchive)按 🟠 验。

## 验证

```bash
# 8.4 弃用清零
cd docker && docker compose -f docker-compose.yml -f docker-compose.84.yml up -d --build
# 跑全冒烟,扫 runtime 日志里的 Deprecated
grep -ri "Deprecated" runtime/log/ | head    # 期望:清零
# 8.5 前瞻
docker compose -f docker-compose.yml -f docker-compose.85.yml up -d --build
```
冒烟行:#7(三方登录)、#10/#25(二维码/支付)、#21/#23(上传/更新解压)、邮件发送。

## 退出标准(DoD)

- [ ] 低成本移除完成,无功能回归(确认存储配置)
- [ ] PHPMailer 升级,邮件正常;PclZip→ZipArchive,在线更新正常
- [ ] composer 账本覆盖可托管三方库
- [ ] **PHP 8.4 弃用日志清零**(去 `@` 抑制后复核)
- [ ] **PHP 8.5 全冒烟通过,弃用复零**
- [ ] tag `tp8-p8-done`

## 回滚

移除/升级分轮提交可逐项 revert;8.5 切换仅换镜像,回 8.4 即可。
