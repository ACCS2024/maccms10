# Qrcode 独立修复批次

范围为 `application/common/util/Qrcode.php` 中合并的 PHP QR Code 1.1.4、`application/index/controller/Qrcode.php` 调用边界，以及独立测试和参考矩阵。未替换二维码库，未修改 Reed–Solomon 编码、定位图案、数据放置或掩码评分算法。

## 已确认故障

普通短 URL 在修改前能够生成二维码。本批通过实际调用复现的故障包括：

| 分支 | 原行为 | 修复 |
| --- | --- | --- |
| 清除帧缓存 | 访问不存在的 `QRtools::$frames`，抛出 Error。 | 清除真正保存帧的 `QRspec::$frames`；关闭磁盘缓存时 buildCache 不写相对路径文件。 |
| 8-bit 编码 | `string` 被当作常量、append 参数错位，入口不可用。 | 恢复变量和三参数调用，验证输入容量。 |
| Kanji / 混合大小写 | 未定义 hint/run、位流类名拼错、静态调用非静态估算方法；大小写转换错误调用模式识别器。 | 修正调用和返回的字节长度；Shift-JIS 双字节字符不参与 ASCII 大小写转换。 |
| 多个纠错块交错 | 数组下标来自浮点除法，PHP 8.3/8.4 报精度损失弃用。 | 使用整数除法计算列索引。 |
| 输入与容量估算 | 数字分组估算的强制转换位置错误；先用小版本字段估算时，可能误拒绝标准最大容量。 | 正确计算整组三位数字；宣布超限前用最大版本字段重新估算。 |
| Structured Append 辅助方法 | buf 被当作常量，header 保存整数但编码器读取字节字符，parity 对字符串做数值 XOR。 | 使用字节值和正确 header 长度、索引、校验范围；未新增自动多二维码拆分功能。 |
| PNG 输出与错误处理 | saveandprint 参数被覆盖；异常被吞掉且遗留输出缓冲；失败写盘没有明确失败结果。 | 正确传递参数、finally 清理缓冲/图像对象、写入失败抛出可捕获异常。 |

同时校正合并后未导入的全局 Exception、类名大小写及多余实参。大小写和 PHP 用户函数的多余参数诊断不等于运行时漏洞；未使用的 `$ret;` 表达式及 PHPStan 对 unset/子类属性 hook 的推断也单独归类为静态清理。

公开渲染入口拒绝非法纠错等级、空/非字符串输入、负数或过大边距、非法原始矩阵，并保持最大图像尺寸限制。超出任一 QR 版本容量的输入在拆分为字节数组前拒绝，避免为明显不可能编码的超长输入分配大型数组。有效最大容量仍被保留。

## 独立验证

运行器只将仓库只读挂载到 PHP 容器，使用临时输出目录和 `--network none`。不启动应用，不加载站点配置，也不访问数据库。

```sh
python3 tests/run_qrcode_audit.py
```

可在命令后传入要运行的 PHP 镜像。默认镜像为 `maccms10-migration-check:latest`、`maccms-audit-php84:20260910`。主机测试环境需要 Python 的 `opencv-python-headless` 和 `zxing-cpp`；本次验证使用 OpenCV 4.13.0 读取图像、ZXing-C++ 2.3.0 解码，后者安装于仓库外的临时目录，未增加生产 Composer 依赖。

PHP 8.3.33、8.4.25 各 **116 项检查通过**，包括：

- 38 个固定掩码矩阵与独立实现的 SHA-256 完全一致，覆盖全部 8 个 mask、4 个纠错等级及版本 1/7/10/27/40；包含 7089 位数字和 2953 字节的最大容量。
- 原始、文本、PNG、JPEG、saveandprint 输出，缓存清理、结构化头的 20 位内容、非法参数、文件写入失败和输出缓冲保持。
- 强制 byte、Kanji、大小写转换、跨多个纠错块及容量上下界。

每个 PHP 版本另生成 **9 个 PNG**，由 ZXing-C++ 同时校验原始字节和解码文本，包含中文 URL、混合 ASCII/Kanji 和大于一个纠错块的内容。二维码输出没有用于构造期望值。

调用边界在两个 PHP 版本各通过 **37 项真实 HTTP 检查**：合法 URL 返回可被 ZXing-C++ 解码的 PNG；缺失、空、数组、非法 URL 及容量超限返回 400 JSON；在库已经设置 PNG 头之后注入输出失败或空输出，均返回 500 JSON，且调用方缓冲和此前的原生 Content-Type 保持完整。HTTP 服务仅在禁网容器的回环地址运行，不使用站点入口或配置。可用 `python3 tests/run_qrcode_audit.py --http-only` 单独运行该组。

最终库与控制器在 PHP 8.3/8.4 原生 lint 均无诊断，使用本轮校准配置的 PHPStan 定向检查为零错误。

参考矩阵来自独立的 [Nayuki QR Code generator](https://www.nayuki.io/page/qr-code-generator-library)，固定使用 [v1.8.0 Python 源码](https://github.com/nayuki/QR-Code-generator/blob/v1.8.0/python/qrcodegen.py)。源码 SHA-256、版本、纠错等级、mode、mask 和输入数据均记录在 `tests/fixtures/qrcode_reference.json`。重建方法为单一 segment 调用 `encode_segments(..., minversion=version, maxversion=version, mask=mask, boostecl=False)`，对无尾随换行的 LF 连接二进制矩阵求摘要；存在 repeat 时先重复对应字节序列。

实际 PNG 解码采用 [ZXing-C++ 官方 Python 接口](https://github.com/zxing-cpp/zxing-cpp/tree/master/wrappers/python)。Shift-JIS 用其原始字节契约验证，避免把其他解码器的字符集展示差异误判成编码失败。

## 接口与剩余边界

- 成功输出的接口保持原样；无效纠错等级不再悄悄降级为 L。PNG 编码或写盘失败会抛出 Exception，调用方可以区分失败，不再收到空白的“成功”输出。
- 二维码控制器验证标量 URL，在自己的输出缓冲内完成编码后返回 PNG Response；预期参数/容量错误返回 400，编码/输出故障返回 500。finally 清除新增缓冲并恢复库修改前的原生 Content-Type，最终由 Response 发送正确类型；没有引入写临时文件的运行依赖。
- 未添加 ECI、自动 Structured Append 或新的字符集协议；未承诺所有扫描器都以相同方式展示未标明 ECI 的内容。
- 磁盘缓存配置仍关闭，未测试启用后的部署权限和跨进程缓存行为。本批也不是对全部 40 个版本、所有输入组合的完整标准认证。
