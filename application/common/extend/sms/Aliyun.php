<?php
namespace app\common\extend\sms;

class Aliyun {

    public $name = '阿里云短信';
    public $ver = '2.0';

    /**
     * 生成签名并发起请求
     *
     * @param $accessKeyId string AccessKeyId (https://ak-console.aliyun.com/)
     * @param $accessKeySecret string AccessKeySecret
     * @param $domain string API接口所在域名
     * @param $params array API具体参数
     * @param $security boolean 使用https
     * @param $method boolean 使用GET或POST方法请求，VPC仅支持POST
     * @return bool|\stdClass 返回API接口调用结果，当发生错误时返回false
     */
    public function request($accessKeyId, $accessKeySecret, $domain, $params, $security=true, $method='POST') {
        $apiParams = array_merge(array (
            "SignatureMethod" => "HMAC-SHA1",
            "SignatureNonce" => uniqid(mt_rand(0,0xffff), true),
            "SignatureVersion" => "1.0",
            "AccessKeyId" => $accessKeyId,
            "Timestamp" => gmdate("Y-m-d\TH:i:s\Z"),
            "Format" => "JSON",
        ), $params);
        ksort($apiParams);

        $sortedQueryStringTmp = "";
        foreach ($apiParams as $key => $value) {
            $sortedQueryStringTmp .= "&" . $this->encode($key) . "=" . $this->encode($value);
        }

        $stringToSign = "{$method}&%2F&" . $this->encode(substr($sortedQueryStringTmp, 1));

        $sign = base64_encode(hash_hmac("sha1", $stringToSign, $accessKeySecret . "&",true));

        $signature = $this->encode($sign);

        $url = ($security ? 'https' : 'http')."://{$domain}/";

        try {
            $content = $this->fetchContent($url, $method, "Signature={$signature}{$sortedQueryStringTmp}");
            return json_decode($content,true);
        } catch( \Exception $e) {
            return false;
        }
    }

    private function encode($str)
    {
        $res = urlencode($str);
        $res = preg_replace("/\+/", "%20", $res);
        $res = preg_replace("/\*/", "%2A", $res);
        $res = preg_replace("/%7E/", "~", $res);
        return $res;
    }

    private function fetchContent($url, $method, $body) {
        $ch = curl_init();

        if($method == 'POST') {
            curl_setopt($ch, CURLOPT_POST, 1);//post提交方式
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        } else {
            $url .= '?'.$body;
        }

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            "x-sdk-client" => "php/2.0.0"
        ));

        if(substr($url, 0,5) == 'https') {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        }

        $rtn = curl_exec($ch);

        if($rtn === false) {
            $message = "[CURL_" . curl_errno($ch) . "]: " . curl_error($ch);
            curl_close($ch);
            throw new \RuntimeException($message);
        }
        curl_close($ch);

        return $rtn;
    }

    public function submit($phone,$code,$type_flag,$type_des,$text)
    {
        if (!is_scalar($phone) || !is_scalar($code) || !is_scalar($type_flag)
            || empty($phone) || empty($code) || empty($type_flag)) {
            return ['code'=>101,'msg'=>'参数错误'];
        }

        $appid = $GLOBALS['config']['sms']['aliyun']['appid'];
        $appkey = $GLOBALS['config']['sms']['aliyun']['appkey'];
        $sign = $GLOBALS['config']['sms']['sign'];
        $security = true;
        $tpl = $GLOBALS['config']['sms']['tpl_code_'.$type_flag];

        $params=[];
        $params['PhoneNumbers'] = $phone;
        $params['SignName'] = $sign;
        $params['TemplateCode'] = $tpl;
        $params['TemplateParam'] = [
            'code'=>$code,
        ];

        if( is_array($params["TemplateParam"])) {
            $params["TemplateParam"] = json_encode($params["TemplateParam"], JSON_UNESCAPED_UNICODE);
        }

        try {
            $rsp = $this->request(
                $appid,
                $appkey,
                "dysmsapi.aliyuncs.com",
                array_merge($params, array(
                    "RegionId" => "cn-hangzhou",
                    "Action" => "SendSms",
                    "Version" => "2017-05-25",
                )),
                $security
            );

            if (is_array($rsp) && ($rsp['Code'] ?? null) === 'OK') {
                return ['code'=>1,'msg'=>'ok'];
            }
            $message = is_array($rsp) && is_string($rsp['Message'] ?? null)
                ? $rsp['Message'] : '短信服务请求失败，请重试';
            return ['code'=>101,'msg'=>$message];
        }
        catch(\Throwable $e) {
            return ['code'=>102,'msg'=>'发生异常请重试'];
        }
    }
}
