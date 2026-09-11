# 静态扫描的多入口覆盖

固定源为 `a22b2cfd`，树 `f8d475b023634b6c8c10aad259d2d9a430567e48`。该批仅校准分析配置，不修改业务代码，也不把诊断减少记为修复了同等数量的漏洞。

此前 PHPStan 将 ENTRANCE 推断为首先扫描到的 index，进而判定 admin/api 分支恒假，甚至把后台私有方法记作不可达或未使用。维护中的四个 HTTP 入口分别使用 index、admin、api、install，think CLI 使用 install。现在 dynamicConstantNames 声明这四个实际值的联合类型，让每个入口分支都参与分析。

在同一份代码、同一套锁定依赖、PHP 8.4.25 / PHPStan 2.2.13 下对照运行，唯一分析配置差异为 ENTRANCE 类型：

| 检查 | 修正前 | 修正后 |
| --- | ---: | ---: |
| level 1 诊断 | 49 | 49 |
| level 5 诊断 | 688 | 610 |
| 扫描器全局错误 | 0 | 0 |

level 5 移除 80 条依赖错误常量推断的诊断，新增 2 条原先未覆盖后台分支的候选，位于 AdminAudit 的 JSON 编码结果判断、CsrfGuard 的旧开关判断。新增候选继续留在报告中核实；未添加 baseline、ignoreErrors 或排除路径。

完整原始报告、配置差异及 stderr 已存入 [证据归档](evidence/static-entrypoint-a22b2cfd.tar.gz)，每个文件与压缩包的 SHA-256 见[清单](static-entrypoint-coverage.json)。修正后的数字不适用于未来代码，也不能代替 PHP 8.3/8.4 的实际执行测试。作为本次固定业务源的运行证据，`a22b2cfd` 两版完整默认回归各 188 个进程、零失败；本批未重复运行未变化的业务测试。
