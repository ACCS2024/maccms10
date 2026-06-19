# TP8 技术债修复追踪

> 状态：`[ ]` 待做 / `[x]` 完成 / `[!]` 跳过/False Positive

---

## Fix 1 — install.php TP5 bootstrap 崩溃

**文件**：`install.php:42`  
**问题**：`require __DIR__ . '/thinkphp/start.php'` — TP5 路径，已不存在，全新安装即 500  
**修复**：替换为 TP8 `vendor/autoload.php` + `App` 启动方式（参照 index.php 模式）

- [x] 修复 install.php bootstrap
- [x] lint 通过
- [x] commit 8646dc4

---

## Fix 2 — `type_id|type_id_1` 管道字段 OR（API 控制器）

**问题**：TP5 支持 `$where['field1|field2'] = $val` 作为 OR 条件；TP8 ORM 不解析管道，导致条件静默失效（分类过滤不生效）

**受影响文件（7 处）**：
- `application/api/controller/Vod.php` 行 50, 498, 651
- `application/api/controller/Art.php` 行 48, 415, 463
- `application/api/controller/Manga.php` 行 36

**修复**：每处改为 closure OR 条件  
```php
// Before (TP5):
$where['type_id|type_id_1'] = $tid;

// After (TP8):
$where[] = function($query) use ($tid) {
    $query->where('type_id', $tid)->whereOr('type_id_1', $tid);
};
```

- [x] api/controller/Vod.php (3 处)
- [x] api/controller/Art.php (3 处)
- [x] api/controller/Manga.php (1 处)
- [x] common/model/Actor|Art|Manga|Vod|Website.php（模型层 type_id|type_id_1，共 5 处）
- [x] admin/controller/Actor|Art|Manga|Vod|Website.php + Make.php（admin 层，共 6 处）
- [x] index/controller/Ajax.php（前台层，共 2 处）
- [x] commit 8646dc4

---

## Fix 3 — 管道字段 LIKE（tuple 内）

**问题**：`['actor_name|actor_en', 'like', '%wd%']` — TP8 将 `actor_name|actor_en` 当字面列名，SQL 语法错误或无结果

**受影响（2 处）**：
- `application/common/model/Actor.php:298`
- `application/api/controller/Role.php:72`

**修复**：同上，closure OR
```php
$where[] = function($query) use ($wd) {
    $query->where('actor_name', 'like', '%'.$wd.'%')
          ->whereOr('actor_en', 'like', '%'.$wd.'%');
};
```

- [x] Actor.php:298
- [x] api/controller/Role.php:72
- [x] common/model/Role|Website|Topic.php（模型层 LIKE 管道，3 处）
- [x] admin/controller/Adminaudit|Comment|Gbook|Task|Chatroom|Danmaku|Vod.php（admin 层 LIKE 管道，9 处）
- [x] commit 8646dc4

---

## Fix 4 — 裸数组 BETWEEN（dict 格式，共 28 处）

**问题**：TP5 `$where['field'] = [$min, $max]` 表示 BETWEEN；TP8 把它当 IN 条件（只匹配精确两个值），语义完全错误

**修复**：每处改为 TP8 expression tuple
```php
// Before:
$where['actor_hits_month'] = [$tmp[0],$tmp[1]];

// After:
$where[] = ['actor_hits_month', 'between', [$tmp[0], $tmp[1]]];
```

**受影响文件**：
- `application/common/model/Actor.php` 行 253, 262, 271, 280 （4 处）
- `application/common/model/Art.php` 行 331, 340, 349, 358 （4 处）
- `application/common/model/Manga.php` 行 330, 339, 348, 357 （4 处）
- `application/common/model/Vod.php` 行 412, 421, 430, 439 （4 处）
- `application/common/model/Website.php` 行 307, 316, 325, 334, 343, 352, 361, 370 （8 处）
- `application/common/model/Role.php` 行 203, 212, 221, 230 （4 处）
- `application/common/model/Topic.php` 行 192, 201, 210, 219 （4 处）

- [x] Actor.php（4 处）
- [x] Art.php（4 处）
- [x] Manga.php（4 处）
- [x] Vod.php（4 处）
- [x] Website.php（8 处）
- [x] Role.php（4 处）
- [x] Topic.php（4 处）
- [x] commit 8646dc4

---

## Fix 5 — false=== ORM 检查（已核实）

**核实结论**：剩余 3 处 `=== false` 均为合法非 ORM 用途（VodSearch.php 中的布尔参数和 stripos 检查），**不是技术债**。

- [!] 跳过，无需修复

---

## 完成后验收

- [x] `php -l` 所有修改文件通过
- [x] 无 `type_id|type_id_1` 管道 WHERE 残留（grep 零结果）
- [x] 无管道 LIKE 残留（grep 零结果）
- [x] 无裸数组 BETWEEN 残留（grep 零结果）
- [ ] git commit
