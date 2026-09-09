# 播放页首次打开出现错误遮罩

问题页面：<http://85.149.233.2/theme-preview-20260909-a7c4/live/index.php/vodplay/143043-1-1.html>

## 原因与修复

线上 `MacPlayerConfig.prestrain` 为 `///html/prestrain.html`，`buffer` 为 `///html/loading.html`。浏览器把前者解析为 `http://html/prestrain.html`。原播放器默认显示预加载 iframe，加载失效地址并覆盖解析播放器，配置的 5 秒结束后才隐藏。修复前用浏览器复现：初始化时错误遮罩可见，5.5 秒后隐藏，下面的解析 iframe 始终存在。

`static/js/player.js` 现在默认隐藏遮罩且使用 `about:blank`；只有有效 HTTP(S) 地址及正数预加载时长才启动预加载。空值、三斜杠及反斜杠等价错误地址、非 HTTP(S) 协议会被跳过，缓冲入口也执行相同检查。有效本地、完整外部及协议相对地址仍按原设定显示和计时。

没有覆盖线上 `playerconfig.js`，因此保留原有播放来源及解析接口。修改的是新旧主题共用的播放器脚本，对两者均生效；没有切换正式站主题。页面现有版本串基于文件修改时间，部署后新生成页面会引用新版本。

## 验证

```bash
NODE_PATH=/tmp/maccms-theme-audit-20260909/browser/node_modules \
  PLAYER_PAGE_URL=http://85.149.233.2/theme-preview-20260909-a7c4/live/index.php/vodplay/143043-1-1.html \
  node tests/player_startup.cjs
```

8 个本地浏览器场景通过：错误地址、空值、反斜杠地址、非法协议、零时长、正常本地/外部预加载及缓冲、未知播放来源。计时使用浏览器虚拟时钟。

部署页面在 1440px 和 390px 通过：解析 iframe 请求正常发起，初始遮罩隐藏并保持 `about:blank`，无 `html` 主机请求，缓冲调用不会重新显示错误遮罩。测试用静态页面代替外部解析站，不验证媒体解码或外部解析服务的播放成功率，也不采集内容截图。结果见 `evidence/player-startup.json`。

## 部署及回滚

- 2026-09-09 原文件备份：服务器 `/root/maccms-backups/player-startup-20260909-135045/player.js`。
- 替换前校验线上文件与本地原版 SHA-256 相同，再保留权限和属主原子替换。
- 部署 SHA-256：`9ea41d26776ea7cb508d20541a006256cb4e543b100b2bad0e7142db71334d59`。
- 如需回滚，将备份内容恢复到 `/home/wwwroot/xingba/static/js/player.js`，保留权限和属主，更新该文件修改时间使页面版本串刷新。无需恢复站点配置或清空共享缓存。
