# P7 · 插件系统(fastadmin-addons)迁移 🔴(部分)

## 目标

把 `karsonzhang/fastadmin-addons`(TP5.1,1.1.11)的插件加载机制迁到 TP8,适配 `addons/` 内现有插件,并明确**对第三方插件的破坏性变更**。

## 前置依赖

P1–P6(框架/配置/中间件/数据/视图/助手就绪)。插件加载依赖 `addon_begin` 钩子——已在 P3 处理。

## 改动清单

| 项 | 处置 |
|---|---|
| `vendor/karsonzhang/fastadmin-addons` | 换 TP8 兼容版(其 TP6+ 分支)或自维护一份最小加载器 |
| `addon_begin` 钩子 | 已在 P3 → 中间件/事件 |
| `config/addons.php`(原 extra/addons.php) | P2 已迁,核对加载配置 |
| `addons/` 内现有插件 | 逐个适配(控制器/视图/钩子写法) |
| 插件的 install/uninstall/enable/disable | 适配 TP8 服务/迁移 |

## 设计要点

- **加载器是关键**:fastadmin-addons 在 TP5.1 用 `Hook` + 服务注册;TP8 要改用中间件/事件 + 容器服务注册。优先用社区 TP6+ 版本,差异太大则**自维护一个最小加载器**(只覆盖 maccms 实际用到的钩子点)。
- **插件视图目录**:历史上有 `view_new→view` 半迁移破页教训(`debt(A3)`)。本阶段务必**统一插件视图目录**,避免再次半迁移。
- **插件安全**:插件可注入路由/控制器——确认插件路由**也经过 P3 的安全中间件**(无旁路,关联 INV-1..8)。
- **兼容契约**:TP8 插件 API 与 TP5.1 不兼容 → 现有第三方插件**需作者适配**。本阶段产出《插件迁移指南》+ 破坏性变更公告。

## 切片建议(每轮先分析)

- ROUND:加载器迁移(能发现/加载/路由一个内置插件)
- ROUND:install/uninstall/enable/disable 生命周期适配
- ROUND:`addons/` 内现有插件逐个适配 + 视图目录统一
- ROUND:插件路由安全校验(经过安全中间件)+ 破坏性变更公告

## 风险 & 安全不变量

🔴(加载/路由轮):插件是**外部代码注入点**,迁移不当会绕过安全中间件或重开模板/上传洞。关联 INV-1/2/5 + 模板白名单。

## 验证

```bash
cd docker && docker compose -f docker-compose.yml -f docker-compose.84.yml up -d --build
bash tests/smoke/addons.sh             # 安装→启用→访问→停用→卸载一个测试插件
bash tests/security/check_invariants.sh   # 确认插件路径不旁路安全中间件
```
冒烟行:#22(插件管理)、#19(模板,若插件带模板)。

## 退出标准(DoD)

- [ ] 加载器迁移完成,内置/测试插件可装可用可卸
- [ ] 插件视图目录统一(无半迁移破页)
- [ ] 插件路由经过安全中间件(INV 全绿)
- [ ] 《插件迁移指南》+ 破坏性变更公告产出
- [ ] tag `tp8-p7-done`

## 回滚

加载器与插件适配分轮提交;阶段 tag 兜底。
