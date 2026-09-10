# 普通搜索建议：文本显示与真实组件合同

本批修改四份 `Suggest.Init`：`static/js/home.js`、`static_new/js/home.js`、`template/m1938pc3_v2/js/home.js`、`template/vozy/tuo/assets/mac.js`。默认主题的两份热门词/历史记录 bundle 有独立实现，另行验收；本批不替换 jQuery 或 autocomplete 依赖。

真实 Chromium 加载已提交的 jQuery、autocomplete 和实际方法后，四份实现都能复现：响应中的名称产生新的 HTML 节点，而不是按原文显示。使用的是无执行行为的 `span data-audit-suggest` 标记。后端 DTO 的 `name` 是原始文本，不能直接交给组件的 `.html()`。

同一测试还确认自定义 `parse` 只设置 `data`，缺少插件要求的 `value` 和 `result`；键盘选择的 `result` 事件收到未定义的格式化值，输入值先被清空，随后应用的另一个监听器才把 `name` 填回。仅修改 `formatResult` 无法补齐这一合同，因为插件的远程自定义解析不会调用它。

修复在显示边界转义名称，保留正常关键词加粗。解析产出完整的 `data/value/result`，选中值和跳转关键词仍使用原文，并且仅 URL 编码一次。保留各版本原有尺寸、延迟、缓存和匹配配置。

异常或畸形 JSON 响应返回空列表；坏行不会阻断后续合法行。最多处理响应前 50 行，名称上限 4096 个 UTF-16 单元；空名称和无法 URL 编码的孤立代理字符被拒绝。响应跳转模板必须包含 `mac_wd`，长度不超过 8192，且为无凭据、同源 HTTP(S) 地址，禁止控制字符、空格和反斜杠。相对路径、根路径和同源绝对地址均保留。

验证命令：

```sh
npm ci --prefix tests/browser --ignore-scripts --no-audit --no-fund
CHROMIUM_BINARY=/usr/bin/chromium node tests/browser/suggest.cjs
```

测试仅使用临时回环 HTTP 服务器，拒绝所有外部浏览器请求；从实际源码提取方法，并加载各入口对应的现有插件。覆盖 HTML 节点隔离、文本保真、正常加粗、键盘与鼠标选择、Unicode/百分号/引号、子目录与根路径、畸形响应、坏行、非同源/带凭据跳转和显示预算。通过真实 `setOptions({max:100})` 验证 50 行预算；默认插件自身仍可能只显示 10 行。

修复前对照可用 `SUGGEST_AUDIT_ROOT=/path/to/prior/checkout node tests/browser/suggest.cjs --reproduce` 执行，四入口共 10 项；此模式不进入 CI。它只复现已列问题，不等于整套旧脚本安全审计。

此浏览器回归不启动 PHP，不重复套用双 PHP 数量。后端建议与统一搜索各自拥有真实 PHP/MySQL 检查。本批没有证明旧依赖、其他 HTML 拼接点或未启用本方法的页面已全部安全。
