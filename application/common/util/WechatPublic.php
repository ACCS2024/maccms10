<?php
namespace app\common\util;

class WechatPublic
{
    var $_conf;
    
    function __construct($config){
        $this->_conf = $config;
    }

    public function valid() {
        if (!$this->checkSignature() || !is_string($_GET['echostr'] ?? null)) {
            http_response_code(403);
            echo 'forbidden';
            return;
        }
        echo htmlspecialchars(strip_tags($_GET['echostr']), ENT_QUOTES);
    }

    private function checkSignature()
    {
        $signature = $_GET['signature'] ?? null;
        $timestamp = $_GET['timestamp'] ?? null;
        $nonce = $_GET['nonce'] ?? null;
        $token = $this->_conf['token'] ?? '';
        if (!is_string($signature) || !preg_match('/^[a-f0-9]{40}$/i', $signature)
            || !is_string($timestamp) || !ctype_digit($timestamp)
            || !is_string($nonce) || $nonce === '' || !is_string($token) || $token === '') {
            return false;
        }
        $tmpArr = array($token, $timestamp, $nonce);
        sort($tmpArr, SORT_STRING);
        $tmpStr = implode( $tmpArr );
        $tmpStr = sha1( $tmpStr );
        return hash_equals($tmpStr, strtolower($signature));
    }

    public function responseMsg() {
        if (!$this->checkSignature()) {
            http_response_code(403);
            echo 'forbidden';
            return;
        }
        $postStr = file_get_contents('php://input', false, null, 0, 1048577);
        header('Content-Type: application/xml; charset=utf-8');
        echo $this->replyToMessage($postStr === false ? '' : $postStr);
    }

    private function replyToMessage(string $postStr): string
    {
        if ($postStr === '' || strlen($postStr) > 1048576 || stripos($postStr, '<!DOCTYPE') !== false) {
            http_response_code(400);
            return 'invalid request';
        }
        $previous = libxml_use_internal_errors(true);
        try {
            $postObj = simplexml_load_string($postStr, 'SimpleXMLElement', LIBXML_NOCDATA | LIBXML_NONET);
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
        if ($postObj === false || (string)$postObj->FromUserName === '' || (string)$postObj->ToUserName === '') {
            http_response_code(400);
            return 'invalid request';
        }
            $postType = trim((string)$postObj->MsgType);
            switch ($postType) {
                case 'text':
                    $res = $this->receiveText($postObj);
                    break;
                case 'image':
                case 'location':
                case 'voice':
                case 'video':
                    // These message types have no business handler; acknowledge without a reply.
                    $res = 'success';
                    break;
                case 'link':
                    $res = $this->receiveLink($postObj);
                    break;
                case 'event':
                    $res = $this->receiveEvent($postObj);
                    break;
                default:
                    $res = 'success';
                    break;
            }
            return $res;
    }
    private function receiveLink($object) {
        $msg = '你发送的是链接已收到，请等待处理';
        $res = $this->transmitText($object, $msg);
        return $res;
    }

    private function receiveText($object) {
        $content = trim((string)$object->Content);
        $txt = '请点击下方链接：'. "\n";

        if ($this->_conf['gjc1'] <> '' && strstr($content, $this->_conf['gjc1'])) {
            $data = array();
            $txt .=  '<a href="'.$this->_conf['gjcl1'].'">'.$this->_conf['gjcm1'].'</a>' . "\n";
            $data[] = array('Title'=>$this->_conf['gjcm1'], 'Description'=>'', 'PicUrl'=>$this->_conf['gjci1'], 'Url'=>$this->_conf['gjcl1']);
        }
        elseif ($this->_conf['gjc2'] <> '' && strstr($content, $this->_conf['gjc2'])) {
            $data = array();
            $txt .=  '<a href="'.$this->_conf['gjcl2'].'">'.$this->_conf['gjcm2'].'</a>' . "\n";
            $data[] = array('Title'=>$this->_conf['gjcm2'], 'Description'=>'', 'PicUrl'=>$this->_conf['gjci2'], 'Url'=>$this->_conf['gjcl2']);
        }
        elseif ($this->_conf['gjc3'] <> '' && strstr($content, $this->_conf['gjc3'])) {
            $data = array();
            $txt .=  '<a href="'.$this->_conf['gjcl3'].'">'.$this->_conf['gjcm3'].'</a>' . "\n";
            $data[] = array('Title'=>$this->_conf['gjcm3'], 'Description'=>'', 'PicUrl'=>$this->_conf['gjci3'], 'Url'=>$this->_conf['gjcl3']);
        }
        elseif ($this->_conf['gjc4'] <> '' && strstr($content, $this->_conf['gjc4'])) {
            $data = array();
            $txt .=  '<a href="'.$this->_conf['gjcl4'].'">'.$this->_conf['gjcm4'].'</a>' . "\n";
            $data[] = array('Title'=>$this->_conf['gjcm4'], 'Description'=>'', 'PicUrl'=>$this->_conf['gjci4'], 'Url'=>$this->_conf['gjcl4']);
        }
        else {
            $param =[];
            $param['wd'] = $content;
			$param['num']=7;
            if($this->_conf['msgtype'] !=1){
                $param['num'] =1;
            }

            if (substr($this->_conf['sousuo'], 0, 4) != 'http') {
                $this->_conf['sousuo'] = 'http://' . $this->_conf['sousuo'];
            }


            $res = (new \app\common\model\Vod())->listCacheData($param);
            $data = [];
            if($res['code']>1 || empty($res['list'])){
                $txt .=  '<a href="'.$this->_conf['wuziyuanlink'].'">'.$this->_conf['wuziyuan'].'</a>' . "\n";
                $data[] = array('Title'=>$this->_conf['wuziyuan'], 'Description'=>'', 'PicUrl'=>'', 'Url'=>$this->_conf['wuziyuanlink']);
            }
            else{

                if($this->_conf['bofang'] ==2){
                    $search_url = $this->_conf['sousuo'] .mac_url('vod/search',['wd'=>$content]); //'/index.php/vod/search/wd/' . urlencode($content);
                    $txt .=  '<a href="'.$search_url.'">点击进入搜索页面查看</a>' . "\n";
                    $data[] = array('Title'=>'点击进入搜索页面查看', 'Description'=>'恭喜您找到了相关资源，由于微信限制请进入搜索页查看', 'PicUrl'=>'', 'Url'=>$search_url );
                }
                else {
                    foreach ($res['list'] as $k => $v) {

                        $url = $this->_conf['sousuo'] . mac_url_vod_detail($v);
                        if ($this->_conf['bofang'] > 0) {
                            $url = $this->_conf['sousuo'] . mac_url_vod_play($v, ['sid' => 1, 'nid' => 1]);
                        }

                        if (substr($v['vod_pic'], 0, 4) == 'http' || substr($v['vod_pic'], 0, 4) == 'mac:') {
                            $picUrl = mac_url_img($v['vod_pic']);
                        } else {
                            $picUrl = $this->_conf['sousuo'] . "/" . $v['vod_pic'];
                        }

                        $txt .= '<a href="' . $url . '">' . ($k + 1) . ',' . $v['vod_name'] . ' ' . $v['vod_remarks'] . '</a>' . "\n";
                        $data[] = array('Title' => $v['vod_name'], 'Description' => mac_substring(strip_tags($v["vod_content"]), 20), 'PicUrl' => $picUrl, 'Url' => $url);
                    }
                }
            }
        }
        if (is_array($data)){
            if ( $this->_conf['msgtype'] !=1 && isset($data[0])){
                $r = $this->transmitNews($object, $data);
            }
            else{
                $r = $this->transmitText($object, $txt);
            }
        }
        return $r;
    }

    private function receiveEvent($object) {
        $guanzhu = $this->_conf['guanzhu'] ?? '';
        $msg = '';
        switch ($object->Event) {
            case 'subscribe':
                $msg = $guanzhu;
                break;
            case 'unsubscribe':
                $msg = '拜拜了您内~';
                break;
            case 'CLICK':
                switch ($object->EventKey) {
                    default:
                        $msg = '你点击了: '.$object->EventKey;
                        break;
                }
                break;
            default:
                $msg = 'receive a new event: '.$object->Event;
                break;
        }
        $res = $this->transmitText($object, $msg);
        return $res;
    }
    private function transmitText($object, $content) {
        $xmlTpl = '<xml>
            <ToUserName><![CDATA[%s]]></ToUserName>
            <FromUserName><![CDATA[%s]]></FromUserName>
            <CreateTime>%s</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[%s]]></Content>
            </xml>';
        $res = sprintf($xmlTpl, self::cdata($object->FromUserName), self::cdata($object->ToUserName), time(), self::cdata($content));
        return $res;
    }
    private function transmitNews($object, $newsArray) {
        if (!is_array($newsArray)) {
            return;
        }
        $itemTpl = '<item>
        <Title><![CDATA[%s]]></Title>
        <Description><![CDATA[%s]]></Description>
        <PicUrl><![CDATA[%s]]></PicUrl>
        <Url><![CDATA[%s]]></Url>
        </item>';
        $item_str = '';
        foreach($newsArray as $item) {
            $item_str.= sprintf($itemTpl, self::cdata($item['Title']), self::cdata($item['Description']), self::cdata($item['PicUrl']), self::cdata($item['Url']));
        }
        $xmlTpl = '<xml>
        <ToUserName><![CDATA[%s]]></ToUserName>
        <FromUserName><![CDATA[%s]]></FromUserName>
        <CreateTime>%s</CreateTime>
        <MsgType><![CDATA[news]]></MsgType>
        <ArticleCount>%s</ArticleCount>
        <Articles>%s</Articles>
        </xml>';
        $res = sprintf($xmlTpl, self::cdata($object->FromUserName), self::cdata($object->ToUserName), time(), count($newsArray),$item_str);
        return $res;
    }

    private function transmitImage($object, $imageArray) {
        $xmlTpl = '<xml>
            <ToUserName><![CDATA[%s]]></ToUserName>
            <FromUserName><![CDATA[%s]]></FromUserName>
            <CreateTime>%s</CreateTime>
            <MsgType><![CDATA[image]]></MsgType>
            <Image>
            <MediaId><![CDATA[%s]]></MediaId>
            </Image>
            </xml>';

        $res = sprintf($xmlTpl, self::cdata($object->FromUserName), self::cdata($object->ToUserName), time(), self::cdata($imageArray['MediaId']));
        return $res;
    }

    private static function cdata($value): string
    {
        return str_replace(']]>', ']]]]><![CDATA[>', (string)$value);
    }
}
