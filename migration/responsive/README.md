# 老主题响应式改造：渐进式覆盖层

适用：把一个固定宽度、float 排版的老 maccms 主题改成手机可用，**而不重写主题**。
2026-08-31 在番号站群（主题 `default_pc`，83 个模板，日均百万级请求）上落地并验证。

---

## 为什么不重写

改造对象的家底（`default_pc` 实测）：

| 项 | 值 |
|---|---|
| 容器宽度 | `body:1000px` / `.area:1160px` / `.outside:1120px` / `.index-bar:920px` |
| 分栏 | 首页三栏 200/600/200；详情页 320+387+300 三块浮动 |
| `float` 声明 | **145 处** |
| 媒体查询 | **0 个** |
| 模板数 | 83 |

重写 = 动 83 个模板 + 一整套 float 布局，在一个跑着真实流量的站上，收益/风险比很差。

## 做法：覆盖层

新建一个 `responsive.css`，**最后加载**，且**所有规则都写在 `@media (max-width:…)` 里**。

```
内容页 CSS 顺序： home.css → head.css → responsive.css
```

由此得到三个性质：

1. **桌面端（>1200px）逐像素不变** —— 本文件一条规则都不匹配。实测首页改造前后
   diff 只有 3 行新增（viewport meta + link + 注释），正文结构零改动。
2. **原 CSS 一个字节没动** —— 没有"改坏老样式"这种失败模式。
3. **回滚 = 删一行 `<link>`**。

断点：`1200`（容器流体化）/ `992`（分栏降级）/ `768`（取消 float、纵向堆叠、点击区 ≥40px）/ `480`（小屏微调）。

`viewport` meta 加在 `public/include.html` —— 它被所有模板 include 在 `<head>` 里，一处生效。

> ⚠️ **viewport 必须和响应式 CSS 一起上**。单独加 viewport 到固定宽布局上，
> 结果比不加更糟：原本浏览器用 980px 虚拟视口整体缩放（丑但可用），
> 加了之后固定宽内容直接溢出、横向滚动。

## 没有浏览器，怎么证明改对了

两个静态检查器，比肉眼可靠：

### `css_check.py` —— 证明「桌面端零影响」+「没写空规则」

```bash
python3 css_check.py responsive.css <渲染后的页面.html> <主题CSS合并.txt>
```

输出三件事：
- 括号配平
- **顶层（非 `@media`）规则数必须为 0** —— 这是"桌面端零影响"的机器证明
- 覆盖的类名有多少真实存在于渲染页面/主题 CSS —— 揪出拍脑袋写的空规则

### `overflow_check.py` —— 找出手机上会横向撑破的元素

```bash
python3 overflow_check.py <主题CSS合并.txt> responsive.css <渲染后的页面.html>
```

解析主题 CSS 里所有 `width > 375px` 的规则，**只保留渲染页面里真实出现的选择器**
（滤掉主题自带的死样式），再比对 `responsive.css` 有没有覆盖。

番号站首轮跑出 **7 条漏网**，全是主结构：
`.nr`（列表行）、`.pag2`（分页）、`.banner1`、`.ml`、`.top_inside`、`.list_pic`、`.yq`。
补完后归零。**这 7 条靠人眼看 CSS 很难发现。**

## 落地步骤

```bash
# 0) 准备语料:抓几个真实页面 + 主题实际加载的 CSS
for p in / /index.php/vod/detail/id/N.html /index.php/vod/type/id/1.html; do
  curl -s "https://<站点>$p" >> pages.html; done
for c in head home foot; do
  curl -s "https://<站点>/template/<主题>/html/style/css/$c.css" >> css.txt; done

# 1) 摸清家底:列出所有 >=300px 的固定宽规则(决定要写多少覆盖)
#    见本目录 css_audit 思路，或直接 grep width:[0-9]{3,}px

# 2) 以 responsive-default_pc.css 为模板改写(容器名换成该主题的)

# 3) 两个检查器都要过:顶层规则 0 条、溢出候选 0 条

# 4) 部署:responsive.css 放进主题 css 目录,
#    public/include.html 头部加 viewport meta、末尾加 <link>

# 5) 清模板缓存,验证 CSS 加载顺序(responsive 必须在最后)
```

## 已知未覆盖

- **播放器 iframe**：`≤768px` 用了 `height:56.25vw`（16:9）。若站点播放器有自己的
  固定高度，需按实际调整。
- **后台**：本方案只管前台。后台 `static_new/` 是 layui + tailwind，另有一套。
- **图片实际尺寸**：`img{max-width:100%}` 只解决溢出，不解决"手机上下载 1080p 封面"
  的流量问题。真要优化要在图床侧做响应式图片（`srcset` / CDN 裁剪参数）。

## 关联

- 番号站落地记录与踩坑：记忆 `project-fanhao-migration-2026-08`
- 主题其它工程（jQuery 升级、死代码清理）：同上
