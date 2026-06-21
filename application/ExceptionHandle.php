<?php
declare(strict_types=1);
namespace app;

use think\exception\Handle;
use think\exception\HttpException;
use think\Request;
use think\Response;
use Throwable;

class ExceptionHandle extends Handle
{
    public function render(Request $request, Throwable $e): Response
    {
        // 404 无论 debug 模式均返回简洁页，不暴露框架指纹
        if ($e instanceof HttpException && $e->getStatusCode() === 404) {
            return $this->plainPage(404, '页面不存在', '您访问的页面不存在');
        }

        // debug=true 时其他异常交给 TP8 默认处理（开发需要完整信息）
        if ($this->app->isDebug()) {
            return parent::render($request, $e);
        }

        // 生产环境其他异常：返回简洁页，不暴露框架/堆栈
        $status = ($e instanceof HttpException) ? $e->getStatusCode() : 500;
        return $this->plainPage($status, '页面错误', '服务器发生错误，请稍后重试');
    }

    private function plainPage(int $status, string $title, string $message): Response
    {
        $html = <<<HTML
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{$title}</title>
<style>
body{margin:0;padding:0;font-family:Arial,sans-serif;background:#f5f5f5;color:#333;}
.w{max-width:600px;margin:120px auto;text-align:center;}
h1{font-size:80px;margin:0;color:#ccc;}
h2{font-size:24px;margin:10px 0 20px;}
p{color:#888;}
a{color:#e6004d;text-decoration:none;}
a:hover{text-decoration:underline;}
</style>
</head>
<body>
<div class="w">
  <h1>{$status}</h1>
  <h2>{$title}</h2>
  <p>{$message}，<a href="/">返回首页</a></p>
</div>
</body>
</html>
HTML;
        return Response::create($html, 'html', $status);
    }
}
