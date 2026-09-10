# Manga 章节解析与安装表兼容

日期：2026-09-10。此批仅修复漫画读取的 PHP 8 可用性问题。完整授权计划与仍未修复的密码、缓存、购买问题见 [manga-resource-access-plan.md](manga-resource-access-plan.md)。不能将本批作为漫画资源授权已经完成的结论。

## 原因与改动

实际安装 `mac_manga` 表保存 `manga_chapter_from` / `manga_chapter_url`，没有 `manga_play_server` / `manga_play_note`。`Manga::infoData` 读取正常非空章节时直接引用后两键，PHP 8 E_ALL 抛异常。仅在模型补 `?? ''` 仍不足以修复：`mac_manga_list` 对空 server/note 产生空数组，随后再次无条件读取对应键。

模型现在为旧站可选字段提供空默认值；解析函数的 server/note 参数也可省略。源、URL、可选元数据分别按 `$$$` 分组，按已声明源的原位置取值；缺失位置补空字符串，不创建数据库列。空/null 或非字符串容器受控为空数据。存在于旧站扩展表的 server/note 字符串照常保留，不拼入原图片 URL。

源 sid 与 `mac_play_list_one` 返回的章 nid 都保持原一基位置。章节 `One$url1##Three$url3` 仍是键 1、3；空前导源不会把 sid2 变成 sid1。URL 比源少时保留空源；URL 比源多时不发明源。正常 URL-only 章节格式、标题和源名字符串 `0` 均有明确回归。

本批不修改 API/前台请求坐标、next 算法、密码、积分、核心缓存或模板。输入过滤和授权必须在下一读取批按实际坐标另行完成。

## 验证

`python3 tests/run_manga_parser_audit.py`：PHP 8.3.33、PHP 8.4.25，每版 **50 项**通过。专用 MySQL 8 使用安装 DDL 原样建表；真实 Request/User/ORM/API 验证正常详情、真实章 1/3、缺章 2、空/null/错位采集数据，公共 DTO 仍不返回原图片。SQL 监听确认正常生产读取不执行 ALTER/CREATE/DROP。随后仅在临时表增加旧站兼容列，验证其元数据保留；没有生产运行时补表逻辑。

解析以 `cache=0`/既有 `cache=1` 取得相同目录结构；这项仅验证结构一致，**没有修复旧缓存对状态/价格的绕过**。后续授权批应 fresh 读取并统一权限判断。

原故障证据是双 PHP、真实安装表的 Undefined array key 复现，保存于 `/tmp/maccms-audit-20260910/manga-resource-diagnostics-frozen`。已解除模型 500 的部署应紧接完整读取授权修复，不能把原异常偶然阻断当成密码保护。

既有公共 DTO/默认前端回归 `python3 tests/run_api_content_view_audit.py`：每版 **600 项 + 13 项实际 JavaScript** 通过。
