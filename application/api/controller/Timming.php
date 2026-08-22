<?php
namespace app\api\controller;
use app\common\util\ExternalSyncRunner;
use app\common\util\AnalyticsAggregator;

class Timming extends Base
{
    public function __construct()
    {
        parent::__construct();
    }

    public function index()
    {
        // 安全加固(V1/CVE-2026-4562):未授权定时任务收紧为 fail-closed。
        // CLI(本机 crontab/命令行)放行;HTTP 必须携带与后台配置一致的 token,
        // 且 token 未配置时一律拒绝(杜绝默认空 token 时的未授权触发采集/SSRF/清缓存)。
        // IS_CLI 在 application/common.php 统一定义;这里仍用 defined() 兜底,
        // 使「常量缺失」退化为最严格的分支(要求 token),而不是致命 Error。
        if (!defined('IS_CLI') || !IS_CLI) {
            if (strtoupper($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
                echo json_encode(['code'=>0,'msg'=>'POST method not allowed for timming']);
                exit;
            }
            $token = \think\facade\Request::header('X-Maccms-Timming-Token', '');
            if ($token === '') {
                $token = \think\facade\Request::get('token', '', 'trim');
            }
            $expected_token = (string)config('maccms.app.timming_token');
            if ($expected_token === '' || !hash_equals($expected_token, (string)$token)) {
                echo json_encode(['code'=>0,'msg'=>'invalid or missing timming token']);
                exit;
            }
        }

        // 闸门已过(本机 CLI 或 token 正确)。定时任务要以后台身份实例化 admin 控制器,
        // 授权由【真正做过校验的这段代码】显式授予,而不是让 admin\Base 从 URL 里的
        // 控制器名反推(那样一来任何 /api.php/timming/* 形状的请求都能顶着后台身份跑)。
        if (!defined('MAC_TIMMING_AUTHORIZED')) {
            define('MAC_TIMMING_AUTHORIZED', true);
        }

        // 低峰兜底:把 Redis 播放/阅读计数缓冲的零头落库(未开 hits_buffer 时为空操作)
        \app\common\util\HitsBuffer::flush();

        $param = \think\facade\Request::get();
        $name    = (string)($param['name'] ?? '');
        $enforce = (string)($param['enforce'] ?? '');

        $list = config('timming');
        foreach($list as $k=>$v){
            if(!empty($name) && $v['name'] !=$name){
                continue;
            }

            $oldweek = ''; $oldhours = '';
            if(!empty($v['runtime'])) { $oldweek= date('w',$v['runtime']); $oldhours= date('H',$v['runtime']); }
            $curweek= date('w',time()) ;	$curhours= date("H",time());
            if(strlen($oldhours)==1 && intval($oldhours) <10){ $oldhours= '0'.$oldhours; }
            if(strlen($curhours)==1 && intval($curhours) <10){ $curhours= substr($curhours,1,1); }
            $last = (!empty($v['runtime']) ? date('Y-m-d H:i:s',$v['runtime']) : lang('api/never'));
            $status = $v['status'] == '1' ?  lang('open'): lang('close');

            //测试
            //$v['runtime']=0;

            if( $v['status']=='1' &&
                ( empty($v['runtime']) || ($oldweek."-".$oldhours) != ($curweek."-".$curhours) && strpos($v['weeks'],$curweek)!==false && strpos($v['hours'],$curhours)!==false  || $enforce =='1')
               ) {
                mac_echo( lang('api/task_tip_exec',[$v['name'] ,$status,$last]));
                $list[$k]['runtime'] = time();

                $res = mac_arr2file( APP_PATH .'extra/timming.php', $list);
                if($res===false){
                    return $this->error(lang('write_err_config'));
                }
                $this->reset();

                $taskName = (string)$v['name'];
                $startedAt = (int)$list[$k]['runtime'];
                $previousRuntime = (int)($v['runtime'] ?? 0);
                $restoreRuntime = function () use ($taskName, $startedAt, $previousRuntime) {
                    $this->restoreRuntime($taskName, $startedAt, $previousRuntime);
                };

                // 兼容旧数据：早期资源站中心写入的任务使用 type/url 字段
                $file  = isset($v['file']) && $v['file'] !== '' ? $v['file'] : (isset($v['type']) ? $v['type'] : '');
                $param = isset($v['param']) ? $v['param'] : '';
                if ($param === '' && !empty($v['url'])) {
                    // 旧数据的 url 形如 .../collect/api?ac=cj&...，取 query string 作为 param
                    $query = parse_url($v['url'], PHP_URL_QUERY);
                    $param = $query !== null ? $query : '';
                }

                if (!is_string($file) || $file === '' || !method_exists($this, $file)) {
                    $restoreRuntime();
                    mac_echo(lang('api/task_tip_jump', [$v['name'], $status, $last]));
                    die;
                }

                register_shutdown_function(function () use ($restoreRuntime) {
                    $error = error_get_last();
                    $fatalTypes = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];
                    if ($error !== null && in_array($error['type'], $fatalTypes, true)) {
                        $restoreRuntime();
                    }
                });

                try {
                    $this->$file($param);
                } catch (\Throwable $e) {
                    $restoreRuntime();
                    throw $e;
                }
                die;

            }
            else{
                mac_echo(lang('api/task_tip_jump',[$v['name'] ,$status,$last]));
            }
        }
    }

    private function reset()
    {
        foreach($_REQUEST as $k=>$v){
            $_REQUEST[$k]='';
        }
    }

    private function restoreRuntime(string $taskName, int $startedAt, int $previousRuntime): void
    {
        $configFile = APP_PATH . 'extra/timming.php';
        $list = is_file($configFile) ? include $configFile : [];
        if (!is_array($list)) {
            return;
        }

        foreach ($list as $key => $task) {
            if (($task['name'] ?? '') !== $taskName || (int)($task['runtime'] ?? 0) !== $startedAt) {
                continue;
            }

            $list[$key]['runtime'] = $previousRuntime;
            mac_arr2file($configFile, $list);
            return;
        }
    }

    /**
     * TP5 的全局助手 controller('admin/xxx') 在 TP8 中【不存在】
     * (vendor/topthink/framework/src/helper.php 无此函数,think\Loader 也已移除),
     * 调用它是 "Call to undefined function" 致命 Error —— 与 IS_CLI 同一类缺陷,
     * 藏在 IS_CLI 后面,只修 IS_CLI 的话 7 种任务里有 5 种照样 500。
     * TP8 下直接实例化即可(鉴权由 MAC_TIMMING_AUTHORIZED 显式授予)。
     */
    protected function collect($param)
    {
        @parse_str($param,$output);
        (new \app\admin\controller\Collect())->api($output);
    }

    protected function make($param)
    {
        @parse_str($param,$output);
        (new \app\admin\controller\Make())->make($output);
    }

    protected function cj($param)
    {
        @parse_str($param,$output);
        (new \app\admin\controller\Cj())->col_all($output);
    }

    protected function cache($param)
    {
        @parse_str($param,$output);
        (new \app\admin\controller\Index())->clear();
    }

    protected function urlsend($param)
    {
        @parse_str($param,$output);
        (new \app\admin\controller\Urlsend())->push($output);
    }

    protected function analytics($param)
    {
        @parse_str($param, $output);
        $mode = empty($output['mode']) ? 'hour' : trim($output['mode']);
        $date = empty($output['date']) ? '' : trim($output['date']);
        $res = $mode === 'day'
            ? AnalyticsAggregator::runDay($date)
            : AnalyticsAggregator::runHour($date);
        if (isset($res['msg'])) {
            mac_echo('[analytics] ' . $res['msg']);
        }
    }

    protected function extsync($param)
    {
        @parse_str($param, $output);
        $provider = isset($output['provider']) ? trim((string)$output['provider']) : '';
        $cfg = config('maccms');
        $extCfg = isset($cfg['ai_search']['external_sources']) && is_array($cfg['ai_search']['external_sources'])
            ? $cfg['ai_search']['external_sources']
            : [];
        $runner = new ExternalSyncRunner();
        $runner->runDueJobs($extCfg, $provider);
    }
}
