<?php
namespace app\common\extend\pay;

class Weixin {

    public $name = '微信支付';
    public $ver = '1.0';

    public function submit($user,$order,$param)
    {
        $total_fee = $order['order_price'];
        $data = array();
        $data['appid'] =  trim($GLOBALS['config']['pay']['weixin']['appid']);//公众号
        $data['mch_id'] =  trim($GLOBALS['config']['pay']['weixin']['mchid']);//商户号
        $data['nonce_str'] =  mac_get_rndstr();//随机字符串
        $data['body'] =  '积分充值（UID：'.$user['user_id'].'）';//商品描述
        $data['fee_type'] =  'CNY';//标价币种
        $data['out_trade_no'] = $order['order_code'];//商户订单号
        $data['total_fee'] = $total_fee*100;//金额，单位分
        $data['spbill_create_ip'] =  mac_get_client_ip();//终端IP
        $data['notify_url'] =  $GLOBALS['http_type'] . $_SERVER['HTTP_HOST'] . '/index.php/payment/notify/pay_type/weixin';
        $data['trade_type'] =  'NATIVE';//交易类型 JSAPI，NATIVE，APP
        $data['product_id'] = '1';//商品ID
        //$data['openid'] =  '';//用户标识 trade_type=JSAPI时（即公众号支付），此参数必传
        $data['sign'] =  $this->makeSign($data);
        //获取付款二维码
        $data_xml = mac_array2xml($data);
        $res = mac_curl_post('https://api.mch.weixin.qq.com/pay/unifiedorder', $data_xml);
        $res = mac_xml2array($res);

        if($res['return_code']=='SUCCESS' && $res['result_code']=='SUCCESS'){
            //返回付款信息
            $res = [
                'user_id'=>$user['user_id'],
                'total_fee'=>$total_fee,
                'out_trade_no'=>$data['out_trade_no'],
                'code_url'=>$res['code_url']
            ];

            //echo '<img src=http://paysdk.weixin.qq.com/example/qrcode.php?data='.urlencode($res['code_url']).'/>';
            return $res;
        }
        //echo '获取微信二维码失败,'.$res['return_msg'];
        return false;
    }

    public function notify()
    {
        $accepted = false;
        try {
            $xml = file_get_contents('php://input', false, null, 0, 1048577);
            $GLOBALS['config']['pay'] = config('maccms.pay');
            $data = is_string($xml) && strlen($xml) <= 1048576 ? mac_xml2array($xml) : [];
            $accepted = is_array($data) && $this->acceptNotification($data);
        } catch (\Throwable $e) {
            // A failed transaction must remain retryable by the payment gateway.
        }
        if ($accepted) {
            echo '<xml><return_code><![CDATA[SUCCESS]]></return_code><return_msg><![CDATA[OK]]></return_msg></xml>';
        } else {
            echo '<xml><return_code><![CDATA[FAIL]]></return_code><return_msg><![CDATA[通知处理失败]]></return_msg></xml>';
        }
    }

    private function acceptNotification(array $data): bool
    {
        foreach ($data as $field => $value) {
            // SimpleXML's JSON representation encodes an empty XML element as [].
            if ($value === []) {
                $data[$field] = '';
            } elseif (!is_string($value) && !is_int($value)) {
                return false;
            }
        }
        $config = $GLOBALS['config']['pay']['weixin'] ?? [];
        $key = trim((string)($config['appkey'] ?? ''));
        if ($key === '' || empty($data['sign']) || empty($data['out_trade_no']) || empty($data['transaction_id'])
            || ($data['return_code'] ?? '') !== 'SUCCESS' || ($data['result_code'] ?? '') !== 'SUCCESS'
            || empty($config['appid']) || (string)($data['appid'] ?? '') !== trim((string)$config['appid'])
            || empty($config['mchid']) || (string)($data['mch_id'] ?? '') !== trim((string)$config['mchid'])
            || ($data['fee_type'] ?? 'CNY') !== 'CNY') {
            return false;
        }
        $fee = (string)($data['total_fee'] ?? '');
        if (!preg_match('/^[0-9]{1,10}$/D', $fee) || (int)$fee <= 0) {
            return false;
        }
        $receivedSign = (string)$data['sign'];
        unset($data['sign']);
        $sign = $this->makeSign($data);
        if ($sign === '' || !hash_equals($sign, $receivedSign)) {
            return false;
        }
        // total_fee is integer fen; preserve the exact decimal amount without float division.
        $cents = (int)$fee;
        $paid = intdiv($cents, 100) . '.' . str_pad((string)($cents % 100), 2, '0', STR_PAD_LEFT);
        $res = (new \app\common\model\Order())->notify($data['out_trade_no'], 'weixin', $paid);
        return in_array($res['code'] ?? null, [1, '1'], true);
    }

    public function makeSign($data){
        //获取微信支付秘钥
        $key = trim($GLOBALS['config']['pay']['weixin']['appkey']);
        // 去空
        $data = array_filter($data, static fn($value) => $value !== '' && $value !== null);
        //签名步骤一：按字典序排序参数
        ksort($data);
        $string_a=http_build_query($data);
        $string_a=urldecode($string_a);
        //签名步骤二：在string后加入KEY
        $string_sign_temp=$string_a."&key=".$key;
        //签名步骤三：MD5加密
        $signType = $data['sign_type'] ?? 'MD5';
        if ($signType === 'HMAC-SHA256') {
            $sign = hash_hmac('sha256', $string_sign_temp, $key);
        } elseif ($signType === 'MD5') {
            $sign = md5($string_sign_temp);
        } else {
            return '';
        }
        // 签名步骤四：所有字符转为大写
        $result=strtoupper($sign);
        return $result;
    }

}
