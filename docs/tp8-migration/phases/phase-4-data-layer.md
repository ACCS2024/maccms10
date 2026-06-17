# P4 · 数据层(Db 门面 / 模型 / 查询)

## 目标

迁移数据库访问:**459 处 `Db::`** 转门面、**~60 个模型**迁基类、**820 处 `model()`** 调用收口,且 SQL 语义与查询结果**逐项等价**(黄金 diff 守护)。

## 前置依赖

P1–P2(框架/配置/数据库连接配置已迁)。

## 改动清单

| 项 | 计数 | 处置 |
|---|---|---|
| `use think\Db; Db::...` | 459 | → `use think\facade\Db;`(调用不变) |
| `class X extends Model` / 自有 Base 模型 | ~60 | → `extends think\Model`;事件/软删/关联核对 |
| `model('Xxx')` / `Loader::model` | 820 | → 注入或 `\app\common\model\Xxx`(`model()` 助手 TP8 不默认有) |
| DB 连接配置 | — | TP5 数组 → TP8 `config/database.php` 格式 |

## 设计要点

- **门面替换**可用 Rector 批量(`use think\Db` → `use think\facade\Db`),但**每批 `php -l` + 黄金 diff**。
- `model()` 助手:在 TP8 默认不存在。两条路:① 在 `app/common.php` 提供一个兼容 `model()` 垫片(改动面最小,820 处零改);② 逐处换显式类(更干净但量大)。**建议先垫片保等价,P 收尾再视情况清理**(记入债务区)。
- **模型差异重点验**:`getXxxAttr/setXxxAttr` 访问器、`scope`、软删除、关联预载、自动时间戳、`getLastSql`。
- **保留既有 SQL 安全加固**(`security-invariants.md` 非行为类项):列表 `order/by` 白名单、`Database` 控制台 `isValidTable/isValidField` + 参数化 + 审计留痕——P4 触碰这些文件时**不得弱化**。

## 切片建议(每轮先分析)

- ROUND:DB 连接配置迁移 + 1 个只读列表页打通(验证连接/分页)
- ROUND:`Db::` 门面批量替换(按模块分批:common → index → admin → api)
- ROUND:模型基类迁移 + 访问器/关联/软删核对
- ROUND:`model()` 垫片或显式化 + 全量数据冒烟 + 黄金 diff

## 风险 & 安全不变量

🟠 中(个别 🔴):**触碰 INV(非行为类)的 order/by 白名单、SQL 控制台校验**。这些轮按 🔴 验。

## 验证

```bash
find app -name '*.php' -print0 | xargs -0 -n1 php -l >/dev/null && echo lint-ok
php -S 127.0.0.1:8800 -t public public/router.php
bash tests/golden/capture.sh target && bash tests/golden/diff.sh   # 列表/详情/搜索结果等价
```
冒烟行:#2 #3 #4 #5 #17 #20 #24。

## 退出标准(DoD)

- [ ] 459 `Db::` 全部门面化,`php -l` 绿
- [ ] 模型行为(访问器/关联/软删/时间戳)与 baseline 等价
- [ ] 820 `model()` 收口(垫片或显式),无"未定义函数/类"
- [ ] 列表/详情/搜索/API 黄金 diff 全绿;**order/by 注入防线、SQL 控制台校验保留**
- [ ] tag `tp8-p4-done`

## 回滚

分批提交,可按模块 revert;阶段 tag 兜底。
