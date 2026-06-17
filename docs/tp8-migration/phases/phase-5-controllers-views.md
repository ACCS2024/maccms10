# P5 · 控制器 / 视图 / taglib / 模板

## 目标

迁移 **151 个控制器**(基类/命名空间)、**184 `->fetch()` + 769 `->assign()`** 视图收口、**727 行自定义标签库**(Maccms/Macdiy)到 think-view,并让**模板渲染产出与 baseline 等价**(黄金 diff)。

## 前置依赖

P1(BaseController 就位)、P2(view 配置)、P4(数据层就绪,页面有数据可渲染)。

## 改动清单

| 项 | 计数 | 处置 |
|---|---|---|
| `extends Controller`/`extends Base` | 151 | → `extends app\BaseController` |
| `$this->fetch()`/`->display()` | 184 | → `return $this->fetch()`(BaseController 封装 View) |
| `$this->assign()` | 769 | → BaseController 封装等价 `assign`,**调用面尽量零改** |
| `extends Validate` | 50 | → `think\Validate`(命名空间不变,验规则) |
| taglib `Maccms.php`/`Macdiy.php` | 727 行 | → think-view taglib 注册 + 标签编译 API 适配 |
| 模板 `template/**/*.html` | 大量 | 语法基本兼容,**渲染产出对照** |

## 设计要点

- **BaseController 吸收改动面**:在 `app\BaseController` 里封装 `assign()/fetch()`(内部调 `think\facade\View`),使 769+184 处**调用写法基本不变**——这是 P5 把改动面压小的关键。
- **taglib 是硬骨头**:TP8 标签库经 think-view 注册(`config/view.php` 的 `taglib_pre_load` 或 `tag_begin/tag_end`)。Maccms/Macdiy 的标签解析逻辑要适配新编译器 API;**逐标签验证渲染**(列表/详情/首页 diy 标签都要覆盖)。
- **保留模板安全加固**:后台模板编辑器扩展名白名单 + `<?`/`php`/`eval` 黑名单(`security-invariants.md` 非行为类项)——P5 触碰模板编辑功能时保留。
- **入库即转义不变量**:后台编辑自由文本字段的 HTML 转义、写 JS 消毒——保留。

## 切片建议(每轮先分析,按应用切)

- ROUND:`app\BaseController` 封装 fetch/assign + 1 个控制器端到端打通
- ROUND:taglib 迁移(先 Maccms 核心标签,后 Macdiy)+ 首页/列表渲染 diff
- ROUND:index 应用控制器批量迁移 + 前台冒烟
- ROUND:admin 应用控制器批量迁移 + 后台冒烟
- ROUND:api 应用控制器 + 接口结构 diff
- ROUND:50 验证器迁移 + 表单校验冒烟

## 风险 & 安全不变量

🟠 中,**含 🔴 轮**:上传(#21 目录穿越/flag 加固)、模板编辑(#19 白名单/黑名单)、评论/留言(#8 入库转义+限流)、支付下单/回调(#11/#12 金额核对)。这些控制器所在轮按 🔴 验。

## 验证

```bash
php -S 127.0.0.1:8800 -t public public/router.php
bash tests/golden/capture.sh target && bash tests/golden/diff.sh   # 模板渲染等价
bash tests/security/check_invariants.sh INV-2 INV-3 INV-5          # 涉表单/上传/模板的轮
```
冒烟行:前台 #1-#10、后台 #15-#23、API #24-#26、支付 #11-#14。

## 退出标准(DoD)

- [ ] 151 控制器迁 BaseController,`php -l` 绿
- [ ] fetch/assign 收口,所有页面可渲染
- [ ] taglib 迁移完成,**首页/列表/详情/diy 渲染黄金 diff 全绿**
- [ ] 50 验证器迁移,表单校验等价
- [ ] 上传/模板编辑/评论/支付相关 🔴 行 + 对应 INV 全绿
- [ ] tag `tp8-p5-done`

## 回滚

按应用分批提交,可逐应用 revert;taglib 单独成轮便于隔离回退。
