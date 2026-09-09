# 首页替换记录入口

首页：<http://85.149.233.2/theme-preview-20260909-a7c4/live/index.php>

替换记录：<http://85.149.233.2/theme-preview-20260909-a7c4/live/index.php/macrep.html>

参考 `vozy/vo20w2/public/head.html` 将替换提醒与采集公告放在一起的方式，在 V2 首页“站点公告 / 采集接口”区块底部增加一条横向提示。桌面显示标签、时间、类型及查看入口；手机用两行排列，在接口折叠时仍然显示。沿用现有青色与分隔线，不增加嵌套卡片。

时间取 `rep_status=1` 的记录，按 `rep_create_time DESC, rep_id DESC` 选择最新一条，显示到分钟。这里标注“最近发布”，与替换记录页的发布时间一致，不使用本站执行 SQL 的时间。没有公开记录时显示“暂无公开替换记录”；记录缺时间时显示“时间未记录”；替换模块关闭时隐藏入口。原首页写死的迁移日期已移除，教程链接保留。

当前线上替换页没有公开记录，未为展示效果写入测试记录。已用本地数据验证有记录、无记录、缺失时间、模块关闭四种状态，以及类型名称的 HTML 转义。

本站裸 `/rep.html` 返回 404，现有路由是 `/index.php/macrep.html`。主题根据当前 PHP 入口生成地址，预览入口仅新增允许 `macrep` 和 `rep/index` 路由，继续限制 GET/HEAD。替换页接入 V2 页头页尾，修复空记录时访问不存在的筛选栏及旧 jQuery 初始化依赖；避免与主题复制按钮重复绑定。

## 验证

```bash
php tests/theme_compile.php
NODE_PATH=/tmp/maccms-theme-audit-20260909/browser/node_modules \
  THEME_PREVIEW_URL=http://85.149.233.2/theme-preview-20260909-a7c4/live/index.php \
  node tests/theme_rep.cjs
```

13 个页面模板编译通过。1440、768、390、360px 下验证四种提示状态及真实首页入口、替换页 HTTP 200、无横向溢出、无脚本异常。结果见 `evidence/home-rep.json`。现有主题的 7 组浏览器场景和 16 项 HTTP 检查也通过。这些检查不执行任何替换操作。

已检查真实服务区截图：[桌面](evidence/home-rep-desktop.png)、[手机](evidence/home-rep-mobile.png)。截图仅包含公告、接口及替换入口。

## 部署

已同步 V2 主题的 CSS、服务区模板、提示片段、替换页、设置文件，以及预览入口，共 6 个文件。部署前逐个比对原文件 SHA-256，保留权限和属主替换，部署后校验新文件哈希。静态资源版本更新为 `20260909.5`。

服务器备份：`/root/maccms-backups/home-rep-20260909-141351/`，内含原文件及 `manifest.json`。回滚时按清单恢复已有文件，删除新增的 `public/v2/rep-notice.html`，再更新资源版本。未切换正式主题，未修改站点配置、数据库记录或 Nginx。
