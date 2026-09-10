# 默认 bundle 的热门词与历史搜索建议

本批只修改 `template/default/asset/js/public-home-stack.js` 和 `user-home-stack.js` 的 `MAC.Suggest.Init`，不改变搜索 DTO、普通四份 home.js、其他历史记录组件或页面启动策略。

## 确认与修复

仓库实际 `static/js/jquery.autocomplete.js` 会把 `formatItem` 输出交给 `.html()`。源码确认两份旧 Init 把热门词和 `historyList` 原文直接拼入输出，没有文本转义。现在只在展示时进行 HTML 转义，选项仍持有未编码的名称，选择时才 `encodeURIComponent()` 写入搜索 URL。

自定义 parse 原来仅返回 `{data}`，但插件要求 `{data,value,result}`，其 `search()` 遇缺失 result 会抛错。修复补齐三个字段，`formatResult` 使用真实的 name。鼠标、键盘和插件 search() 均使用原文，不把 HTML 实体当作搜索词。

`historyList` 原来直接 JSON.parse 并假设是数组。现在存储不可读、JSON 损坏或容器错误均回退空历史，热门词可继续使用。每组只处理前 50 项，词条必须是非空字符串、长度不超过 4096 UTF-16 单元且可进行 URI 编码；历史 JSON 原始文本超过 65536 单元不解析。不再将任意对象、数字或数组强转为词条。

保持历史/热门标题、热门序号与前三项样式。标题通过内部类型标识判断；真实词条恰好叫“历史搜索”或“热门搜索”仍能搜索。选择装饰标题恢复用户已输入的查询，不跳转。

原“清除记录”只有展示，没有仓库内处理监听。现在鼠标与 Enter/空格可清除 `historyList`；捕获阶段在插件 UL 的点击处理前执行，并校验菜单对应的输入框。清除不修改其他本地设置或独立的 `mac_vod_search_history_v1` 历史。通过插件 Escape、缓存刷新和 Down 操作重新生成菜单及键盘状态，相关输入框缓存也同步失效，避免另一输入框重放已清除历史。存储写入被阻止时至少在当前实例停止展示历史。

响应必须成功且 `site_keywords` 为数组。搜索 URL 必须含旧 `mac_wd` 占位符，长度不超过 8192，不能包含空白、控制字符、反斜杠或用户名密码，解析后必须是当前 origin 的 HTTP(S) URL；空 URL、畸形响应、外站或脚本协议不产生可选择词条。相对 URL、子目录、现有查询参数和编码搜索词的合同保留。`$jumpurl` 原本未使用，本批没有新增其语义。

## 实际浏览器回归

工具沿用已锁定的 `tests/browser/package.json` / lock：`playwright-core` 1.58.2 与系统 Chromium，无新增应用依赖。按现有浏览器 CI 将该工具安装到独立目录后运行：

```sh
NODE_PATH=/path/to/isolated/browser-tools/node_modules \
  node tests/browser/suggest_history.cjs
```

测试自动启动随机端口的回环 HTTP 服务，加载真实默认模板 jQuery 及真实 autocomplete 插件，从两份当前 bundle 提取完整 Init 方法运行，不重写方法或模拟插件。外站请求一律阻断并令测试失败。无需 PHP、数据库、云凭据或应用入口。

根代理最终采用普通功能矩阵：中文、引号、百分号、与号等搜索词原文、标题与同名词条、鼠标/键盘/插件选择、真实清除后的键盘状态、跨输入框缓存、畸形历史/响应、存储异常和有限数据处理。数量边界通过真实 `setOptions({max:200})` 检查 parse 结果，避免只依赖插件默认最多显示 10 项而误判处理已受限。最终检查数量以该脚本实际输出和独立提交记录为准。

此前子任务的动态安全复现被自动审查中止，提示可能涉及网络安全风险；已停止该类复现。根代理验收没有重跑执行型输入或攻击利用，仅静态核对文本转义、URL 判断，并运行普通功能矩阵。此测试文件不包含旧复现分支，不用此前日志代替本次暂存版本验证。

## 明确边界

- 两份 bundle 末尾的默认 `MAC.Suggest.Init` 启动行目前均被注释；本组保障调用该公开方法时的组件合同，不额外启用页面功能。会员 include 明确加载该插件，公开 include 本身没有相同直接引用。
- 方法级 fixture 不执行 bundle 顶层的远端授权加载或其他初始化。顶层 `window.lang = localStorage.getItem(...)` 的异常仍需单独处理，本组不能证明禁用存储时整份 bundle 可启动。
- 紧邻 `GetHot.Init` 的动态 HTML/属性拼接属于同类已发现但未修复路径，留下一独立批次，不能将本组称为默认模板所有搜索 UI 已安全。
- 不新增历史写入/合并策略，不自动清理不合法的旧存储文本，不改变独立新页头历史组件。
