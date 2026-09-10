# 图片依赖、动画与上传调用迁移

## 问题与调用范围

当前锁定的 `topthink/think-image v1.0.8`，源码引用 `d1d748cbb2fe2f29fca6138cf96cb8b5113892f1`，GIF Decoder/Encoder 使用 PHP 8 已移除的花括号字符串下标。读取有效动画 GIF 即出现 `ParseError`；仅检查项目目录而排除 vendor，或仅测 JPEG，均不能发现这一实际生产入口故障。修复前复现输出在 `/tmp/maccms-audit-20260910/image-original-gif-php84.log`。官方稳定发布与主分支尚无可直接解决该问题的升级版：[原依赖](https://packagist.org/packages/topthink/think-image)、[上游 Decoder](https://github.com/top-think/think-image/blob/master/src/image/gif/Decoder.php)。

直接调用只有 `common/model/Image.php` 的水印/缩略，以及 `common/model/Upload.php` 的头像转换。间接调用包括 Collect 采集、后台 Images 下载、本地/远程上传和 VodAiCover 完成处理。仓库未发现其他 `think\Image` 方法调用；本组不提供未被使用的旧类全量兼容接口。

真实文件分支还使用 TP8 不再提供的 `UploadedFile::checkExt()`、`File::getSaveName()` 和 `getInfo()`。头像输入在验证前直接覆盖 `uid.jpg`，失败会破坏已有头像。普通 base64 图片没有稳定的后缀/日期目录，且把数据类型记为 `png/gif` 导致后续 `type=image` 处理分支不执行。

## 可复现依赖方案

Composer 移除旧库，新增：

| 依赖 | 锁定版本 | 上游源码引用 |
| --- | --- | --- |
| `intervention/image` | `4.3.2` | `bc15ed24bb88dc58f921daf78091a019ce42fe2c` |
| `intervention/gif`（传递依赖） | `5.0.1` | `bb395af960deffe64d70c976b4df9283f68e762d` |

新库采用 MIT 许可证，PHP 下限符合 8.3。版本、许可证与上游要求见 [Intervention Image](https://packagist.org/packages/intervention/image) 和 [GIF 依赖](https://packagist.org/packages/intervention/gif)。其余已锁定包版本没有变动。没有直接修改 vendor，也没有建立难以重建的应用内依赖副本。

先试验 GD 动画驱动，独立样本发现有限循环计数偏移和局部帧 disposal 合成错误；不能据“支持动画”这一接口声明推断输出保真。因此最终选用同一维护库的 **Imagick 驱动处理 GIF 和静态 WebP**，PNG/JPEG 保持 GD。真实样本确认有限/无限/单次播放、整数百分之一秒延迟、透明背景、局部帧和恢复前帧均正确。没有自行实现 LZW 解码器或动画合成器。驱动接口和动画语义见 [官方配置](https://image.intervention.io/v4/getting-started/configuration-drivers)、[动画文档](https://image.intervention.io/v4/modifying-images/animations)；合成由 [Imagick::coalesceImages](https://www.php.net/manual/en/imagick.coalesceimages.php) 完成。

部署新增 **`ext-imagick:^3.8.1`**。`docker/Dockerfile` 安装 `libmagickwand-dev`、固定 `imagick-3.8.1` 并启用扩展，原 GD 扩展仍必需。扩展发布来源为 [PECL imagick 3.8.1](https://pecl.php.net/package/imagick)。CI 的两个 setup-php `extensions` 已加入 `imagick-3.8.1`；Web 安装预检同步检查扩展存在且版本满足 3.8.1 至 4.0 之前。

依赖和业务调用必须一起发布：执行 lock 安装、平台要求检查并重新生成自动加载，重建含 Imagick 的运行镜像，发布后重启相应 PHP 工作进程以清除旧自动加载/OPcache。不能先移除旧包却继续部署 `think\Image` 调用。本组不执行部署。

## 应用行为

- 新 `ImageProcessor` 只适配实际使用的读取、六种缩略模式、文字水印和保存。保留等比例不放大、白色填充、居中/左上/右下裁剪与固定拉伸的配置编号。
- 每个缩略图复制同一份已解码原图，不从上一个较小缩略图继续缩放。水印是否已成功应用作为内部布尔值传入，Upload、下载和 VodAiCover 路径避免再次叠加；单独调用 makethumb 仍按配置加一次水印。
- 文字仍按原 GD 字号和 RGBA 语义处理，`#RRGGBB00` 是不透明。GIF 每一帧叠加无损 PNG 文字层，编解码和合成交由维护库/扩展完成。自动文字颜色采样裁剪到图像范围，空文字与长文字不会越界或除零。
- 保存先完整编码，再同目录临时写入、检查字节数并重命名。编码、部分写入或重命名失败保留已有目标文件并清理临时文件；拒绝输出到符号链接或目录。
- 头像先接收至随机临时输入文件，明确编码为 **JPEG 第一帧**，成功后返回正式头像路径并更新元数据；坏图、无效尺寸或上传异常保留旧头像，清理临时输入。普通 GIF 处理保持全部帧，不使用头像的静态转换规则。
- 普通上传使用真实 TP8 文件 API 的扩展名、move 和 getSize，保留白名单和日期路径。base64 图片严格解码，补齐后缀、目录与正确图片分类。请求解析或文件移动失败返回受控错误。

## 有界处理与限制

解码前限制本地输入 20 MiB、单边 8,192 像素、GIF 300 帧和累计工作像素 1,600 万。GIF 前置检查仅遍历块长度、帧尺寸与数量，不解压图像；拒绝截断或越界数据。缩放检查源/目标合计像素；参考 PHP 剩余内存按每工作像素 16 字节加 16 MiB 余量保守拒绝，不能视为所有原生实现的精确峰值预测。

Imagick 另限制内存/映射缓存各至多 128 MiB、关闭磁盘溢出缓存并限制单线程，且不提高宿主已有更低上限。极大图片会受控拒绝，不截帧或降为静图。管理员可在后续独立容量规划中调整有明确回归的上限。本组没有增加远程文件读取；公共 HTTP 图片抓取继续使用之前已审计的 transport。

当前新增 WebP 路径覆盖静态 WebP；发现动画 WebP 时帧数校验拒绝处理，未宣称支持其动画转换。EXIF 自动旋转保持关闭，与旧像素方向行为一致。水印和缩略的上层接口继续兼容原有尽力处理语义：失败返回 false/空缩略结果，原文件保留。站点如要求水印失败时拒绝整个上传，需要另行定义业务策略。

## 回归与运行方式

`security_audit_image_processing.php` 检查真实 PNG/JPEG/GIF/WebP 输出、六种缩略、每帧像素/延迟/循环、disposal/透明、9 个水印位置、多个缩略来源、单次水印、显式头像格式以及文件系统故障回滚。GIF 样本由独立 Pillow 生成，测试用独立块读取器核对元数据并由 GD 解码输出帧；不是让被测 GIF 解码器自行证明编码正确。

`security_audit_image_upload.php` 运行真实 `Image::down_exec`、`Upload::upload`、TP8 UploadedFile 移动和 GD/Imagick 处理，覆盖 base64 与普通文件上传、正式头像路径、失败保留旧图、日期后缀、批量缩略和重复水印。仅隔离外部下载内容、User/Annex 元数据持久化；不连接生产数据库、不启动项目入口。`UploadedFile(test=true)` 用于 CLI 的上传文件来源检查，同时另测真实 Request 的上传异常分支；不宣称包含完整鉴权或 HTTP 端到端上传验证。

干净 Composer 安装目录：`/tmp/maccms-audit-20260910/image-install-83/vendor` 和 `image-install-84/vendor`。独立扩展镜像：`maccms-audit-image83:20260910`、`maccms-audit-image84:20260910`，PHP 分别 8.3.33/8.4.25，Imagick 3.8.1、ImageMagick 7.1.1-43 Q16。正式 Dockerfile 另构建 `maccms-audit-image-apache83:20260910` / `maccms-audit-image-apache84:20260910` 用于部署镜像复核。

最终正式 Dockerfile 两版镜像均构建成功，分别通过图片处理 **111 项**、上传/下载调用 **38 项**。新依赖包全部 **468 个 PHP 文件**在 8.3/8.4 原生 lint 中均通过。辅助 CLI 扩展镜像也通过相应回归；最终结果以正式镜像的 `image-apache-processing-php{83,84}.log` 和 `image-apache-upload-php{83,84}.log` 为准。

示例（只读挂载源码与干净依赖，所有图片输出写入临时目录）：

```sh
docker run --rm \
  -v /home/dev/maccms10:/work:ro \
  -v /tmp/maccms-audit-20260910/image-install-84/vendor:/work/vendor:ro \
  -w /work maccms-audit-image84:20260910 \
  php tests/security_audit_image_processing.php
```

Composer 全新安装、`validate`、`check-platform-reqs` 均独立执行；audit 未发现已知公告或废弃包（不等于已排除所有漏洞）。锁文件、安装与审计日志位于 `/tmp/maccms-audit-20260910/image-*`。工作区原 vendor 保持未修改，由主线程在最终提交复核后统一更新。

## 后续独立边界

上传鉴权、请求 user_id 与服务器账号归属、非图像文件校验，以及外部存储成功后本地记录同步不由本组验证。下载后附件大小目前仍在水印/缩略前计算，历史格式不符的文件命名也没有批量修正。原始图片/头像的数据库写失败与已完成文件替换之间不构成跨资源事务，需要后续独立的附件生命周期方案。
