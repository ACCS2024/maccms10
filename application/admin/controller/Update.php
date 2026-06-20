<?php
// 注意：修改此文件后，需同步更新 application/extra/version.php 中的 update_hash 值
// update_hash = md5_file('application/admin/controller/Update.php')
namespace app\admin\controller;
use think\facade\Db;
use app\common\util\PclZip;

class Update extends Base
{
    var $_url;
    var $_save_path;

    public function __construct()
    {
        parent::__construct();
        //header('X-Accel-Buffering: no');

        $this->_url = 'https://update.maccms.la/'  /* 原base64已还原 */."v10/";
        $this->_save_path = './application/data/update/';
    }

    public function index()
    {
        return $this->fetch('admin@update/index');
    }

    public function step1($file='')
    {
        // 安全加固:已切断与官方升级源(update.maccms.la)的通信,防止上游被劫持下发恶意代码。
        // 升级方式:① 代码用 git pull 从自有仓库拉取;② 库结构在登录后台时自动迁移,无需手动SQL。
        echo $this->fetch('admin@public/head');
        echo "<div class='update' style='padding:20px'><h1>在线更新已停用(安全加固)</h1>";
        echo "<textarea rows=\"16\" class='layui-textarea' readonly>";
        echo "为防止官方升级服务器被劫持向本站下发恶意代码,系统已切断与官方的全部通信。\n\n";
        echo "请按以下方式升级:\n";
        echo "1) 代码升级:在服务器执行  git pull  (从你自己的仓库/加固分支拉取最新代码);\n";
        echo "2) 数据库结构升级:登录后台时已自动检测并完成,无需手动执行任何 SQL;\n";
        echo "3) 如需回滚:git 版本回退即可。\n";
        echo "</textarea></div>";
        exit;

        // 以下为原在线更新逻辑(已禁用,保留备查)
        if(empty($file)){
            return $this->error(lang('param_err'));
        }
        $version = config('version.code');
        $url = $this->_url .$file . '.zip?t='.time();

        echo $this->fetch('admin@public/head');
        echo "<div class='update'><h1>".lang('admin/update/step1_a')."</h1><textarea rows=\"25\" class='layui-textarea' readonly>".lang('admin/update/step1_b')."\n";
        ob_flush();flush();
        sleep(1);

        $save_file = $version.'.zip';
        
        $html = mac_curl_get($url);
        @fwrite(@fopen($this->_save_path.$save_file,'wb'),$html);
        if(!is_file($this->_save_path.$save_file)){
            echo lang('admin/update/download_err')."\n";
            exit;
        }

        if(filesize($this->_save_path.$save_file) <1){
            @unlink($this->_save_path.$save_file);
            echo lang('admin/update/download_err')."\n";
            exit;
        }

        // SHA1校验：.sha1文件进行比对防篡改
        $sha1_url = $this->_url . $file . '.zip.sha1?t=' . time();
        $remote_sha1 = trim(mac_curl_get($sha1_url));
        $local_sha1 = sha1_file($this->_save_path . $save_file);
        if (empty($remote_sha1) || strpos($remote_sha1, $local_sha1) !== 0) {
            @unlink($this->_save_path . $save_file);
            echo lang('admin/update/sha1_err') . "\n";
            exit;
        }
        echo lang('admin/update/sha1_ok') . "\n";

        echo lang('admin/update/download_ok')."\n";
        echo lang('admin/update/upgrade_package_processed')."\n";
        ob_flush();flush();
        sleep(1);

        $archive = new PclZip();
        $archive->PclZip($this->_save_path.$save_file);
        // 安全加固(V6/zip-slip):解压前预扫条目名,拒绝 ../、绝对路径、盘符、空字节,防穿越写入Web目录
        $entries = $archive->listContent();
        if (is_array($entries)) {
            foreach ($entries as $entry) {
                $en = isset($entry['stored_filename']) ? $entry['stored_filename'] : (isset($entry['filename']) ? $entry['filename'] : '');
                $en = str_replace('\\', '/', (string)$en);
                if ($en === '' || strpos($en, '../') !== false || strpos($en, "\0") !== false
                    || $en[0] === '/' || preg_match('#^[a-zA-Z]:/#', $en)) {
                    @unlink($this->_save_path.$save_file);
                    echo lang('admin/update/upgrade_err')."\n";
                    exit;
                }
            }
        }
        if(!$archive->extract(PCLZIP_OPT_PATH, '', PCLZIP_OPT_REPLACE_NEWER)) {
            echo $archive->error_string."\n";
            echo lang('admin/update/upgrade_err').'' ."\n";;
            exit;
        }
        else{

        }
        @unlink($this->_save_path.$save_file);
        echo '</textarea></div>';
        mac_jump( url('update/step2',['jump'=>1]) ,3);
    }

    public function step2()
    {
        $version = config('version.code');

        $save_file = 'database.php';

        echo $this->fetch('admin@public/head');
        echo "<div class='update'><h1>".lang('admin/update/step2_a')."</h1><textarea rows=\"25\" class='layui-textarea' readonly>\n";
        ob_flush();flush();
        sleep(1);

        $res=true;
        // 导入SQL
        $sql_file = $this->_save_path .$save_file;

        if (is_file($sql_file)) {
            echo lang('admin/update/upgrade_sql')."\n";
            ob_flush();flush();
            $pre = config('database.connections.mysql.prefix');
            $schema = Db::query('select * from information_schema.columns where table_schema = ?',[ config('database.database') ]);
            $col_list = [];
            $sql='';
            foreach($schema as $k=>$v){
                $col_list[$v['TABLE_NAME']][$v['COLUMN_NAME']] = $v;
            }
            @include $sql_file;
            //dump($sql);die;

            /*
            //$html =  @file_get_contents($sql_file);
            //$sql = mac_get_body($html,'--'.$version.'-start--','--'.$version.'-end--');
            $sql = @file_get_contents($sql_file);
            */
            if(!empty($sql)) {
                $sql_list = mac_parse_sql($sql, 0, ['mac_' => $pre]);

                if ($sql_list) {
                    $sql_list = array_filter($sql_list);
                    foreach ($sql_list as $v) {
                        echo $v;
                        try {
                            Db::execute($v);
                            echo "    ---".lang('success')."\n\n";
                        } catch (\Exception $e) {
                            echo "    ---".lang('fail')."\n\n";
                        }
                        ob_flush();flush();
                    }
                }
            }
            else{

            }
            @unlink($sql_file);
        }
        else{
            echo lang('admin/update/no_sql')."\n";
        }
        echo '</textarea></div>';
        mac_jump(url('update/step3', ['jump' => 1]), 3);
    }

    public function step3()
    {
        echo $this->fetch('admin@public/head');
        echo "<div class='update'><h1>".lang('admin/update/step3_a')."</h1><div rows=\"25\" class='layui-textarea' readonly>\n";
        ob_flush();flush();
        sleep(1);

        $this->_cache_clear();

        echo lang('admin/update/update_cache')."<br>";
        echo lang('admin/update/upgrade_complete')."<br>";

        if(is_file($this->_save_path . 'database.php')){
            echo "<strong style='color: red;'>" . lang('admin/update/not_delete') . ":application/data/update/database.php</strong>";
        }
        ob_flush();flush();
        echo '</div></div>';
    }
}
