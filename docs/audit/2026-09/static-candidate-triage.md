# 静态候选分类与扩查规则

数据基准固定为提交 `a6de166`，使用仓库 tools/audit 锁定工具，未加载本地站点配置。PHPStan level1：1027条文件候选、0条全局错误；PHPCompatibility：0错误、8警告；原生维护范围696文件在8.3.33/8.4.25均无诊断。后续修复会改变计数，本报告不是最终零缺陷结论。

| PHPStan标识 | 数量 | 分类与处置 |
| --- | ---: | --- |
| array.duplicateKey | 643 | 语言包覆盖，PHP取最后值；逐文案维护，避免机械删除改变最终翻译 |
| variable.undefined | 216 | 190条来自include迁移的pre/sql，另有分支定义与真实候选，不能整体忽略 |
| staticMethod.notFound | 102 | 主要Db动态门面；核对锁定ORM转发与真实执行 |
| constant.notFound | 31 | 运行期入口常量，需核对具体入口初始化 |
| property.notFound | 8 | AiTask模型属性映射，不能据动态字段假定库里存在同名列 |
| arguments.count | 1 | 后台Database旧Dir::create参数，已随备份生命周期组替换 |
| constructor.unusedParameter | 1 | Database兼容构造参数；保留调用契约 |
| class.notFound | 1 | 可选GeoIP异常类；核对依赖缺失时真实调用路径 |
| empty.variable | 19 | 部分Collection永远非empty；区分冗余分支和实际数组/行结果错误 |
| unset.variable | 4 | 独立核对引用释放与原变量定义，暂不做批量删除 |
| isset.variable | 1 | 已定义局部变量冗余判断 |

兼容工具8条警告：7个构造函数exit，1个配置文件混合换行。构造终止请求会影响可组合性和错误响应，但不是PHP8解析失败；需按路由行为收口。维护范围外的真实依赖仍通过全工作区扫描单独检查，不能因默认排除vendor漏掉延迟加载问题。

闭环按根因而不是工具条数：定位调用入口→建立正常数据与边界→使用真实框架/ORM或明确服务fixture复现→修复→从暂存快照回归→独立提交。由一个empty(Collection)候选扩查出同类数组引用helper，是有效的启发；仅观察循环中的empty而忽略末尾count退出，则会产生误判。

状态分为已修复并回归、已解释且保留、已确认待修、待核实、受工具限制未完成；任何类别都不通过全局baseline消失。原始工具JSON保留在执行环境 phase-reports-a6de166，仓库保存配置、版本与复验入口，不提交可能含本地路径的整份诊断输出。

## 刷新与语言键分类

提交 `d5e4f5d` 的固定快照已使用同一工具重新完成：PHPStan 1038 条文件候选、0 全局错误；PHPCompatibility 仍为 0 错误、8 警告。相对 a6de166，动态静态方法提示由 102 变为 115，empty 提示由 19 变为 18，旧 Dir 参数数目错误已消失，其余类别数量相同。这些增量不能直接解释为新增 11 个漏洞。

643 条语言覆盖已逐个解析分类：627 个键完全同值（629 条后续冗余声明），16 个键有冲突。前者按最终值与键顺序完全不变原则清理，后者保留逐条处置，见 [语言键分类](language-key-triage.md)。此后源码的预期候选减少不等于该快照已重新跑完全部分析器；每次结果都明确对应版本。

## cdc213f 重扫

固定源码与工具锁见 [阶段记录](phase-verification-cdc213f.json)。在相同 level 1、目标 PHP 8.4 下完整运行，422 条文件诊断、0 全局错误；PHPCompatibility 目标 8.3–8.4 仍为 0 错误、8 警告。语言同值冗余清理后诊断大幅减少，不能把减少条数解释为同样数量的漏洞修复。

| 标识 | 数量 | 当前分类 |
| --- | ---: | --- |
| variable.undefined | 219 | 190 条旧 include 更新 SQL，15 条 Vod 分支局部变量，10 条 URL 兜底分支，2 条 Payment 参数约束分支，1 条附件提交状态分支，1 条用户原有迁移文件 |
| staticMethod.notFound | 119 | 本轮全部为 Db 动态门面；锁定 ORM 的转发与真实数据库测试提供执行证据，未加全局忽略 |
| constant.notFound | 37 | 运行期入口常量；仍按调用入口核对，不能整体标为安全 |
| empty.variable | 18 | Collection/数组及控制流分别核对；同类扩查继续发现未迁移的 Collection 消费者 |
| array.duplicateKey | 14 | 剩余语言冲突，保留人工决定最终文案 |
| property.notFound | 8 | AiTask 的模型映射；已有实际 schema/生命周期回归，不能改为普通动态属性掩盖字段映射 |
| unset.variable | 4 | 原变量释放候选，未为降低条数机械删除 |
| isset.variable | 1 | 已定义局部变量的冗余判断 |
| constructor.unusedParameter | 1 | 保留旧 Database 构造调用合同 |
| class.notFound | 1 | GeoIp2 遗留 catch；实际 IpLocationQuery 自动加载正常，没有缺包必然致命的路径 |

已读过的 Vod 删除组分支、URL 兜底、Payment 经 parameters 限定的 mid/type 和 LocalAttachment 提交前 manifest 分支都有赋值前提；静态工具未传播全部相关条件。此解释限于这些分支，不代表其它输入类型、SQL 或业务策略已经全面核实。190 条 include 候选仍随更新来源与执行入口一起治理，用户原有迁移文件继续保留，不进行顺手修复。

8 条兼容警告仍为 7 个构造函数 exit 生命周期提示和 1 个配置混合换行提示，均不是原生编译失败。原始两份工具 JSON 的 SHA-256 已保存；没有加入 baseline、ignoreErrors 或人为修改工具结果来归零。

## 52f70b90 重扫

固定源码及工具锁见[阶段记录](phase-verification-52f70b90.md)。相同 level 1 为 421 条文件诊断、0 全局错误；分类与 cdc213f 相比只有 `variable.undefined` 从 219 变成 218。PHPCompatibility 仍为 0 错误、8 警告。

额外 level 5 为 1,166 条文件诊断、0 全局错误，各标识计数和原始报告摘要保存在[JSON 记录](phase-verification-52f70b90.json)。此级别补充参数、返回值和不可达分支候选，没有改变正式 level 1 配置。

新 Search 的 `ConnectionInterface::getPdo/query`、Query 返回父类型等诊断需要结合实际连接类核对；已完成的实际 MySQL 回归能够执行这些路径，不能仅凭接口缺少声明断言运行时必然失败。保留的响应形状检查也不能仅为减少 PHPDoc 冗余提示而删除。

另发现 AiSearch 的 Meili 回表仍对 Collection 使用 `is_array`，使后续映射不可达；它有独立的 SQL 回退、模块空结果和缓存语义，已进入下一组实际验证，不能套用已提交 Search 的修复结论。旧 ORM `=== false` 候选仍区分删除对象、幂等更新和抛出异常，不机械全局替换。
