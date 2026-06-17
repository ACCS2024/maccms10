# 阶段验收标准(Definition of Done)模板

> 每个阶段结束、进入下一阶段**之前**必须满足。未达标 → 不得推进(铁律,防半迁移破页——参考仓库历史 `debt(A3)` 半迁移教训)。

## 通用 DoD(所有阶段)

- [ ] 本阶段 PROGRESS 子项全部 ✅ / ⚠️(⚠️ 须在债务区有登记+计划)
- [ ] `app/` 全量 `php -l` 绿(PHP 8.4)
- [ ] Docker `target-8.4` 全栈可启动,**无新增 500 / 无新增 Fatal**
- [ ] `verification/smoke-matrix.md` 本阶段相关行全部通过
- [ ] 黄金 diff:本阶段涉及页面/接口**无非预期结构差异**
- [ ] 本阶段所有轮次的 round-log 完整归档
- [ ] 打 tag `tp8-p<N>-done`

## 安全相关阶段附加 DoD(P3 / P7 / 涉鉴权·支付·上传的轮)

- [ ] `verification/security-invariants.md` **8 条全绿**(不只本阶段触碰的)
- [ ] 人工安全复核完成并在 round-log 签字(对照 `SECURITY_AUDIT_REPORT.md` 既有结论,确认无回退)
- [ ] CSRF / 防挂马 / 安全响应头 / 审计 / 限流 实际触发验证(非仅代码 review)

## 收尾阶段附加 DoD(P9)

- [ ] 冒烟矩阵 100% 通过
- [ ] 性能不劣于迁移前基线(对照 `PERFORMANCE_OPTIMIZATION.md`)
- [ ] PHP 8.4 与 8.5 各跑一轮全栈回归,弃用日志清零
- [ ] 回滚预案演练通过(能从 TP8 切回 TP5.0 镜像)
