# V2 主题安装、预览与切换

当前真实数据预览：

http://85.149.233.2/theme-preview-20260909-a7c4/live/index.php

当前静态设计预览（已同步移动端横向分类 Tab）：

http://85.149.233.2/theme-preview-20260909-a7c4/v2/index.html

## 本次已执行

1. 从线上当前 `m1938pc3/html9` 建立 `template/m1938pc3_v2`，保留未迁移模板和资源。
2. 安装至 `/home/wwwroot/xingba/template/m1938pc3_v2`。
3. 将 `deploy/theme-preview.php` 放到 `/home/wwwroot/xingba/theme-preview-20260909-a7c4/live/index.php`。
4. 预览入口在单次请求中选择新主题，并使用独立缓存标识、模板编译目录和会话名；响应带 `no-store` 和 `noindex`。允许前台页面 GET/HEAD，拒绝 POST 和未列出的路由。
5. 正式站点配置、正式入口和 Nginx 均未切换。真实数据预览沿用现有框架的浏览、搜索和统计行为，未运行采集任务或提交业务表单。

`theme-preview.php` 的目录结构是部署约定：其祖父目录必须是站点根目录。不要直接运行仓库 `deploy/` 下的此文件；该位置会返回“安装未完成”。预览脚本不写入生产 `maccms.php`。

## 自动验证

```bash
php tests/theme_compile.php
NODE_PATH=/tmp/maccms-theme-audit-20260909/browser/node_modules \
  THEME_PREVIEW_URL=http://85.149.233.2/theme-preview-20260909-a7c4/live/index.php \
  node tests/theme_ui.cjs
python3 tests/theme_http.py \
  --base http://85.149.233.2/theme-preview-20260909-a7c4/live/index.php
```

浏览器依赖为 Playwright 与 Chromium；可用 `NODE_PATH` 指定已有 Playwright，`CHROMIUM_PATH` 指定浏览器。未设置 `THEME_PREVIEW_URL` 时，UI 测试只运行本地构造的多来源场景，不访问服务器。

验证记录保存在 `evidence/`：

- 12 个页面通过真实 Think 模板编译及生成 PHP 语法检查。
- 四种屏宽的 Tab、键盘操作、宽度切换、来源隔离、勾选、倒序及复制失败回退通过。
- 1440/390/360px 的真实首页与详情无页面级横向溢出，详情无重复 ID。
- 首页及第二页各 70 条且结果不同；真实父子分类和图文分类各 40 条。
- 正向搜索、空结果、含 `&` 的搜索文本、排序重置分页通过；已修正 MACCMS 预转义参数被模板二次转义的问题。
- 图文详情、影片详情、播放页外层通过 HTTP 检查；无效资源返回 404，预览写请求返回 405。

浏览器截图隐藏图片及内容名称，用于结构审查；视频实际播放、外部图片服务、外部采集端点、播放器包、会员支付和报错提交未作为本次自动检查的一部分。嵌入播放器和未迁移的会员／口令页面保留原实现。

## 正式切换步骤（尚未执行）

1. 备份当前 `application/extra/maccms.php` 至站点 Web 根目录之外，保留原文件权限和属主；记录当前 `site.template_dir`、`site.html_dir`、`site.mob_status`、`app.cache_flag`。不要将含站点密钥的配置备份加入 Git 或放到可下载目录。
2. 在 MACCMS 后台将 PC 模板目录设为 `m1938pc3_v2`，HTML 目录保持 `html9`，独立移动模板保持关闭（当前 `mob_status=0`）；新主题自身适配移动端。
3. 更新站点缓存标识，或通过站点自身的缓存管理清理本次相关页面缓存。不要清空共享 Redis，也不要删除整个 `runtime` 或会话目录。若配置了域名专用模板，逐项检查其是否覆盖全局主题选择。
4. 检查正式域名的首页、分类、搜索、详情、分页和播放器外层，再在真实手机上确认 Tab 与复制。模板必须从新目录加载，静态资源版本为 `20260909.4`。
5. 正式确认后可下线临时预览入口；静态设计稿可以单独保留。

## 回滚

将模板目录改回 `m1938pc3`、HTML 目录保持 `html9`，恢复此前的移动模板策略，再刷新站点相关页面缓存。若切换后还有其他配置修改，只恢复主题相关字段，不用旧备份覆盖整个新配置。

本轮未改动数据库结构、控制器和 URL 路由，主题切换即可恢复旧页面。原主题文件完整保留。
