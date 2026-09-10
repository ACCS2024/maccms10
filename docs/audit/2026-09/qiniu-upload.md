# 七牛文件上传参数与资源释放

本仓库内嵌 SDK 的 `UploadManager::putFile()` 向七参数 `FormUploader::put()` 传了八个参数：第七项 CRC 开关被作为 multipart 文件名，实际 basename 被忽略。已有本地文件在 `$checkCrc=false/true` 下分别产生空文件名或 `1`。独立回归在原代码稳定报错 `CRC flag replaced the local filename`。

修复为传递真实 basename；保留公开方法签名与既有总是计算 CRC 的行为。该参数顺序与 [七牛官方 UploadManager](https://github.com/qiniu/php-sdk/blob/master/src/Qiniu/Storage/UploadManager.php) 一致。二进制流默认/显式 null 文件名规范为 `default_filename`，避免 PHP 8 的 null-to-string 弃用；已有空 key 行为保留。

同时覆盖同一文件读取路径：零字节文件不调用 `fread(..., 0)`；短读在提交前失败；整个读取及上传生命周期用 finally 关闭文件，包含分块传输异常。

`tests/extensions_audit_qiniu_upload.php` 执行实际 UploadManager、FormUploader 和 multipart 编码，仅隔离 cURL 与大文件分块传输。PHP 8.3/8.4 各 20 项覆盖文件名、两种 CRC 参数、元数据、正文、空文件、默认/自定文件名、短读、普通/分块异常以及资源释放。已有 TLS/响应回归与上传适配器回归同时通过；未向真实七牛账号上传文件。
