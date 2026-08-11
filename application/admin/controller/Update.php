<?php
// 注意：修改此文件后，需同步更新 application/extra/version.php 中的 update_hash 值
// update_hash = md5_file('application/admin/controller/Update.php')
namespace app\admin\controller;
use think\facade\Db;

class Update extends Base
{
    var $_save_path;

    public function __construct()
    {
        parent::__construct();
        //header('X-Accel-Buffering: no');

        // 升级源地址已移除。原值指向 update.maccms.la（已被证实投毒的官方升级通道），
        // 保留一个可用的 URL 只会让人以为「改回去就能用」。本类不再有任何出站调用。
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

        // ── 原「在线更新」逻辑已【整段删除】，不是注释掉 ──
        //
        // 删掉而不是保留备查的理由：
        // 1. 它是奇安信 xlab 披露的 FUNNULL/RingH23 投毒链的服务端落点 ——
        //    远程 JS 驱动浏览器请求本方法并带上 file=laupd<hash>，原逻辑会把该参数拼上 .zip
        //    从 update.maccms.la 下载、校验 sha1、用 PclZip 解压覆盖到站点目录。
        //    本站 nginx 日志实测该请求发生过 26 次（全部紧跟成功登录 1~3 秒内自动发出）。
        // 2. 留着「已禁用但完整可用」的代码等于上膛的枪：只要有人误删上面那句 exit、
        //    或将来重构时把它挪走，整条投毒通道立刻复活。本仓库刚因为
        //    「删了函数头留下尾巴」造成过后台整块 JS 失效，教训就在眼前。
        // 3. 升级路径已改为：代码用 git pull 从自有仓库拉；库结构在登录后台时自动迁移。
        //
        // 需要查看原实现请翻 git 历史（本次删除的提交里有完整 diff）。
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
            $schema = Db::query('select * from information_schema.columns where table_schema = ?',[ Db::connect()->getConfig('database') ]);
            $col_list = [];
            $sql='';
            foreach($schema as $k=>$v){
                $col_list[$v['TABLE_NAME']][$v['COLUMN_NAME']] = $v;
            }

            // fail-closed:schema 探测失效时【拒绝执行整份升级脚本】。
            // application/data/update/database.php 全篇是 60 个 `if(empty($col_list[...]))`
            // 守卫,$col_list 一空就【全部打开】,于是已存在的表重新 CREATE、已存在的列
            // 重新 ADD;而其中多条是合并式 ALTER(一条语句加 4 个列),在部分升级过的库上
            // 会因第一个重复列整条失败,真正缺的列反而永远补不上 —— 下面的 catch 只打印
            // 「失败」,操作者无法把真失败和噪声区分开,得到的是一次静默不完整的升级。
            // 这个分支在修掉 config('database.database') 恒 NULL 之前是必然发生的。
            if (empty($col_list)) {
                echo "\n" . lang('admin/update/schema_probe_err') . "\n";
                echo '</textarea></div>';
                ob_flush();flush();
                return;
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
