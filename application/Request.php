<?php
namespace app;

/** Request boundary for method input types and explicit client IP trust. */
class Request extends \think\Request
{
    public function ip(): string
    {
        return \app\common\util\ClientIp::fromRequest($this);
    }

    public function method(bool $origin = false): string
    {
        $raw = $this->server('REQUEST_METHOD');
        if ($raw !== null && !is_string($raw)) { $this->invalidMethod(); }
        if (!$origin && !$this->method) {
            if (array_key_exists($this->varMethod, $this->post) && !is_string($this->post[$this->varMethod])) {
                $this->invalidMethod();
            }
            $override = $this->server('HTTP_X_HTTP_METHOD_OVERRIDE');
            if ($override !== null && !is_string($override)) { $this->invalidMethod(); }
        }
        return parent::method($origin);
    }

    private function invalidMethod(): never
    {
        // Route and exception rendering may both ask for the method. An explicit response avoids
        // recursively parsing the rejected input while formatting an ordinary client error.
        throw new \think\exception\HttpResponseException(\think\Response::create(
            ['code'=>1001, 'msg'=>'Invalid request method'], 'json', 400
        )->header(['Cache-Control'=>'private, no-store', 'X-Content-Type-Options'=>'nosniff']));
    }
}
