<?php
namespace app\admin\controller;

use app\common\model\Rep as RepModel;
use think\facade\Config;
use think\facade\Db;
use think\facade\Request;

class Rep extends Base
{
    public function __construct()
    {
        parent::__construct();
        // TP8 的视图配置组名是 'view';'template' 是 TP5 的旧组名,全仓没有任何读取点,
        // 写进去等于空操作。这五处今天之所以没出事,只是因为 AppInit 对
        // ENTRANCE==='admin' 无条件把 view.view_path 置空,think-view 恰好回落到
        // application/admin/view/ —— 与这行想指定的目录相同。一旦 AppInit 那个
        // 分支改成有条件的(债务方案 S5 正打算这么做),这五个页面会静默改渲染前台
        // 主题模板。把组名修正为 'view',让这行真正承担它声称的职责。
        Config::set(['view_path' => APP_PATH . 'admin/view/'], 'view');
    }

    public function index()
    {
        $list    = RepModel::allList();
        $enabled = $GLOBALS['config']['rep']['enabled'] ?? '1';
        $this->assign('list', $list);
        $this->assign('rep_enabled', $enabled);
        $this->assign('types', array_keys(RepModel::$typeMap));
        // 前台地址由 mac_rep_url() 统一产出（本站没配伪静态,必须带 /index.php/）,
        // 后台「查看前台页面」按钮和主题里用的是同一个来源,不会两边不一致。
        $this->assign('front_url', mac_rep_url());
        // 哪些类型能一键执行 —— 前端据此决定是否显示演练/执行按钮,
        // 避免站长对着「其他」类型点了才被告知不支持。
        $auto = [];
        foreach (RepModel::$typeMap as $t => $m) {
            $auto[$t] = !empty($m);
        }
        $this->assign('auto_types', json_encode($auto, JSON_UNESCAPED_UNICODE));
        return $this->fetch('rep/index');
    }

    public function add()
    {
        $param = Request::post();
        $type  = trim($param['rep_type'] ?? '');
        $orig  = trim($param['rep_original'] ?? '');
        $rep   = trim($param['rep_replacement'] ?? '');
        $note  = trim($param['rep_note'] ?? '');

        if (empty($type) || empty($orig) || empty($rep)) {
            return json(['code' => 0, 'msg' => '参数不完整']);
        }
        if (!array_key_exists($type, RepModel::$typeMap)) {
            return json(['code' => 0, 'msg' => '不支持的替换类型']);
        }

        RepModel::create([
            'rep_type'         => $type,
            'rep_original'     => $orig,
            'rep_replacement'  => $rep,
            'rep_note'         => $note,
            'rep_status'       => 1,
            'rep_applied'      => 0,
            'rep_applied_time' => 0,
            'rep_create_time'  => time(),
        ]);

        return json(['code' => 1, 'msg' => '添加成功']);
    }

    /**
     * 编辑已有记录。
     *
     * 两件事必须在这里处理，否则会留下前后矛盾的状态：
     *
     * 1. 正在执行的记录不许改。execute() 会把执行时的 orig/repl 记进进度文件，
     *    续跑时比对不一致就中止 —— 那道守卫是最后一道保险，但站长看到的是
     *    「执行到一半突然报错」，不知道是自己刚才改的。在这里直接拦住，说清原因。
     *
     * 2. 改了类型/原文/替换文之后，「已执行」这个标记就作废了 ——
     *    库里跑过的是【旧的】那一对字符串，新的一对一行都没替过。
     *    不清掉的话列表上会显示绿色「已执行」，站长据此以为不用再跑，
     *    实际上新内容根本没生效。所以一并把 rep_applied 归零并告知。
     *    只改备注则不影响执行状态，不归零。
     */
    public function edit()
    {
        $param = Request::post();
        $id    = intval($param['rep_id'] ?? 0);
        if (!$id) {
            return json(['code' => 0, 'msg' => '参数错误']);
        }
        $row = RepModel::find($id);
        if (!$row) {
            return json(['code' => 0, 'msg' => '记录不存在']);
        }

        $type = trim($param['rep_type'] ?? '');
        $orig = trim($param['rep_original'] ?? '');
        $rep  = trim($param['rep_replacement'] ?? '');
        $note = trim($param['rep_note'] ?? '');

        if ($type === '' || $orig === '' || $rep === '') {
            return json(['code' => 0, 'msg' => '参数不完整']);
        }
        if (!array_key_exists($type, RepModel::$typeMap)) {
            return json(['code' => 0, 'msg' => '不支持的替换类型']);
        }

        if (is_file($this->statePath($id))) {
            return json(['code' => 0, 'msg' => '该记录正在执行中，无法编辑。请等执行完成，或先把它执行完再改']);
        }

        $changed = ($type !== $row->rep_type)
                || ($orig !== $row->rep_original)
                || ($rep  !== $row->rep_replacement);

        $row->rep_type        = $type;
        $row->rep_original    = $orig;
        $row->rep_replacement = $rep;
        $row->rep_note        = $note;

        $msg = '保存成功';
        if ($changed && $row->rep_applied) {
            $row->rep_applied      = 0;
            $row->rep_applied_time = 0;
            $msg = '保存成功。因为替换内容变了，「已执行」标记已重置 —— '
                 . '库里跑过的是改之前那一对字符串，新的内容需要重新执行';
        }
        $row->save();

        return json(['code' => 1, 'msg' => $msg, 'reset' => $changed && $msg !== '保存成功']);
    }

    public function del()
    {
        $ids = Request::post('ids');
        if (empty($ids)) {
            return json(['code' => 0, 'msg' => '参数错误']);
        }
        if (!is_array($ids)) {
            $ids = explode(',', $ids);
        }
        $ids = array_values(array_filter(array_map('intval', $ids)));
        if (empty($ids)) {
            return json(['code' => 0, 'msg' => '参数错误']);
        }
        RepModel::destroy($ids);
        return json(['code' => 1, 'msg' => '删除成功']);
    }

    public function toggle()
    {
        $id = intval(Request::post('id'));
        if (!$id) {
            return json(['code' => 0, 'msg' => '参数错误']);
        }
        $row = RepModel::find($id);
        if (!$row) {
            return json(['code' => 0, 'msg' => '记录不存在']);
        }
        $row->rep_status = $row->rep_status ? 0 : 1;
        $row->save();
        return json(['code' => 1, 'status' => $row->rep_status, 'msg' => $row->rep_status ? '已显示' : '已隐藏']);
    }

    public function toggleEnabled()
    {
        $configFile = APP_PATH . 'extra/maccms.php';

        // Atomic read-modify-write with exclusive lock
        $fp = fopen($configFile, 'r+');
        if (!$fp) {
            return json(['code' => 0, 'msg' => '配置文件不可写']);
        }
        flock($fp, LOCK_EX);
        $config  = include $configFile;
        $current = $config['rep']['enabled'] ?? '1';
        $config['rep']['enabled'] = ($current === '1') ? '0' : '1';
        $content = '<?php' . "\nreturn " . var_export($config, true) . ";\n";
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, $content);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);

        $GLOBALS['config']['rep'] = $config['rep'];
        $newState = $config['rep']['enabled'];
        return json(['code' => 1, 'enabled' => $newState, 'msg' => $newState === '1' ? '已开启' : '已关闭']);
    }

    /*
     * ================= 替换执行器 =================
     *
     * 原来的 execute() 是这么干的：
     *     UPDATE mac_art SET art_content = REPLACE(art_content, ?, ?) WHERE art_content LIKE ?
     * 一条语句、无边界、直接对生产库跑。这在本站的实际体量下是不能接受的：
     *     mac_art  38,892 行 / 759M（art_content 是 longtext，均行约 19KB）
     *     mac_vod 182,383 行 / 149M
     * 一条无边界 UPDATE 会把整张表的匹配行放进同一个事务：长时间持写锁、undo 与
     * binlog 同时暴涨，前台在这期间写不进去；中途超时回滚则前功尽弃，且没有断点。
     * 更要命的是没有演练、没有备份 —— 原文填错一次就只能去翻昨天的整库备份。
     *
     * 现在拆成四步，浏览器按顺序驱动，每一步都是一个短请求：
     *     preview      演练：只读，统计命中行数 + 抽样 10 条展示「改前 → 改后」
     *     backup       备份：后台 mysqldump 受影响的表 → /home/backup/db/rep-<id>-<ts>.sql.gz
     *     backupStatus 轮询备份进度（返回已写入字节数）
     *     execute      真正执行：按主键窗口分批，每次请求跑一段就返回进度，可续跑
     *
     * 分批的形状（见 RepModel::plan() 里的说明）：
     *     UPDATE tbl SET f = REPLACE(f,?,?) WHERE pk > :lo AND pk <= :lo+1000 AND f LIKE ?
     * 走聚簇索引，每批稳定只碰 1000 行；游标是一个整数，天然可续跑、可断点。
     * 本站主键连续无空洞（art 1..38892 / vod 1..184535），窗口不会空转。
     *
     * 进度状态放在 application/data/rep/run-<id>.json，不动表结构；
     * 全部单元跑完才回写 mac_rep.rep_applied / rep_applied_time。
     */

    /** 每批扫描的主键窗口宽度。1000 行是「单批足够小」与「批次数不至于太多」的折中 */
    const BATCH_STEP = 1000;

    /**
     * 单次 HTTP 请求内最多连续跑多久（秒），到点就返回进度、由前端再发一轮。
     * nginx 这边 fastcgi_read_timeout 是 300 秒，取 8 秒留了极大余量：
     * 既不会撞超时，又把 448 批的往返次数从 448 次压到十几次。
     */
    const TIME_BUDGET = 8;

    /** 演练时抽样展示几条 */
    const SAMPLE_LIMIT = 10;

    private function stateDir()
    {
        $dir = APP_PATH . 'data/rep/';
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        return $dir;
    }

    private function statePath($id)
    {
        return $this->stateDir() . 'run-' . intval($id) . '.json';
    }

    /**
     * 备份落盘目录。优先 /home/backup/db（与站点其它备份放一起，且不在 web 根下），
     * 不可写时回落到 application/data/rep/backup/ —— 回落要在返回值里说清楚，
     * 否则站长会以为备份进了 /home/backup/db 而实际没有。
     */
    private function backupDir()
    {
        $preferred = '/home/backup/db';
        if (is_dir($preferred) && is_writable($preferred)) {
            return $preferred;
        }
        $fallback = $this->stateDir() . 'backup';
        if (!is_dir($fallback)) {
            @mkdir($fallback, 0755, true);
        }
        return $fallback;
    }

    /** 取出记录并做执行前校验，失败时直接返回 json 响应（调用方用 !== null 判断） */
    private function loadExecutable(&$row)
    {
        $id = intval(Request::post('id'));
        if (!$id) {
            return json(['code' => 0, 'msg' => '参数错误']);
        }
        $row = RepModel::find($id);
        if (!$row) {
            return json(['code' => 0, 'msg' => '记录不存在']);
        }
        $err = RepModel::checkExecutable($row->rep_type, $row->rep_original, $row->rep_replacement);
        if ($err !== '') {
            return json(['code' => 0, 'msg' => $err]);
        }
        return null;
    }

    /**
     * 演练（dry-run）。只读，不写任何东西。
     *
     * 抽样为什么用 SQL 里的 SUBSTRING 而不是把整行取回 PHP 再截：
     * art_content 均行 19KB，PHP 这边 memory_limit 只有 128M，
     * 10 行看着不多，但字段本身可以到几百 KB。让 MySQL 只回传命中位置前后
     * 各 40 字符的片段，PHP 永远不接触大字段。
     */
    public function preview()
    {
        $row = null;
        if (($bad = $this->loadExecutable($row)) !== null) {
            return $bad;
        }

        $orig = (string)$row->rep_original;
        $repl = (string)$row->rep_replacement;
        $like = RepModel::likePattern($orig);

        try {
            $units   = RepModel::plan($row->rep_type);
            $details = [];
            $total   = 0;
            $batches = 0;

            foreach ($units as $u) {
                $cnt = (int)Db::query(
                    "SELECT COUNT(*) AS c FROM `{$u['table']}` WHERE `{$u['field']}` LIKE ? ESCAPE '\\\\'",
                    [$like]
                )[0]['c'];
                $total   += $cnt;
                $batches += (int)ceil(max(0, $u['max'] - $u['min'] + 1) / self::BATCH_STEP);

                $samples = [];
                if ($cnt > 0) {
                    $rows = Db::query(
                        "SELECT `{$u['pk']}` AS _pk,
                                SUBSTRING(`{$u['field']}`,
                                          GREATEST(1, LOCATE(?, `{$u['field']}`) - 40),
                                          CHAR_LENGTH(?) + 80) AS _snip
                         FROM `{$u['table']}`
                         WHERE `{$u['field']}` LIKE ? ESCAPE '\\\\'
                         LIMIT " . self::SAMPLE_LIMIT,
                        [$orig, $orig, $like]
                    );
                    foreach ($rows as $r) {
                        $snip = (string)$r['_snip'];
                        $samples[] = [
                            'pk'     => $r['_pk'],
                            'before' => $snip,
                            'after'  => str_replace($orig, $repl, $snip),
                        ];
                    }
                }

                $details[] = [
                    'target'  => $u['table'] . '.' . $u['field'],
                    'count'   => $cnt,
                    'samples' => $samples,
                ];
            }

            return json([
                'code'    => 1,
                'msg'     => 'ok',
                'total'   => $total,
                'batches' => $batches,
                'tables'  => array_values(array_unique(array_column($units, 'table'))),
                'details' => $details,
                'orig'    => $orig,
                'repl'    => $repl,
            ]);
        } catch (\Throwable $e) {
            return json(['code' => 0, 'msg' => '演练失败：' . $e->getMessage()]);
        }
    }

    /**
     * 备份受影响的表。mysqldump 在后台跑，本请求立刻返回，由 backupStatus 轮询。
     *
     * 759M 的 mac_art 导出加压缩要几十秒，放在请求里同步等会顶到 nginx 超时；
     * 更重要的是同步等的话前端只能干等，没有进度可回传。
     *
     * 口令通过 --defaults-file 传，绝不写进命令行 —— 命令行参数在 ps 里是全机可见的。
     */
    public function backup()
    {
        $row = null;
        if (($bad = $this->loadExecutable($row)) !== null) {
            return $bad;
        }

        foreach (['exec', 'escapeshellarg'] as $fn) {
            if (!function_exists($fn) || in_array($fn, array_map('trim', explode(',', (string)ini_get('disable_functions'))), true)) {
                return json(['code' => 0, 'msg' => "PHP 禁用了 {$fn}()，无法调起 mysqldump。请在服务器上手工备份后勾选「已自行备份」再执行"]);
            }
        }

        $units  = RepModel::plan($row->rep_type);
        $tables = array_values(array_unique(array_column($units, 'table')));
        if (!$tables) {
            return json(['code' => 0, 'msg' => '没有需要备份的表']);
        }

        $db  = config('database.connections.mysql');
        $dir = $this->backupDir();
        if (!is_writable($dir)) {
            return json(['code' => 0, 'msg' => "备份目录不可写：{$dir}"]);
        }

        $token = date('YmdHis');
        $base  = $dir . '/rep-' . intval($row->rep_id) . '-' . $token . '.sql.gz';

        // 0600 的临时凭据文件,用完即删。目录用 PHP 的临时目录,不进 web 根。
        $cnf = tempnam(sys_get_temp_dir(), 'repdump');
        if ($cnf === false) {
            return json(['code' => 0, 'msg' => '无法创建临时凭据文件']);
        }
        chmod($cnf, 0600);
        file_put_contents($cnf, "[client]\n"
            . 'host=' . $db['hostname'] . "\n"
            . 'port=' . ($db['hostport'] ?: 3306) . "\n"
            . 'user=' . $db['username'] . "\n"
            . 'password="' . str_replace(['\\', '"'], ['\\\\', '\\"'], $db['password']) . "\"\n");

        $q    = fn($s) => escapeshellarg($s);
        $args = implode(' ', array_map($q, $tables));
        // --single-transaction: 用 MVCC 快照导出,不锁表,前台照常读写
        // --quick:              不把整表读进内存再吐,逐行流式输出(mac_art 759M 必须)
        // --no-tablespaces:     MySQL 8 下免去 PROCESS 权限要求
        $dump = 'mysqldump --defaults-file=' . $q($cnf)
              . ' --single-transaction --quick --skip-lock-tables --no-tablespaces '
              . $q($db['database']) . ' ' . $args . ' 2>' . $q($base . '.err')
              . ' | gzip -c > ' . $q($base . '.part');

        // 成败都要落一个 .done 标记,否则前端只能靠超时猜结果
        $inner = $dump
               . ' && mv ' . $q($base . '.part') . ' ' . $q($base)
               . ' && echo ok > ' . $q($base . '.done')
               . ' || echo fail > ' . $q($base . '.done');
        $inner .= '; rm -f ' . $q($cnf);

        exec('nohup sh -c ' . escapeshellarg($inner) . ' > /dev/null 2>&1 &');

        return json([
            'code'   => 1,
            'token'  => $token,
            'path'   => $base,
            'dir'    => $dir,
            'tables' => $tables,
            'msg'    => '备份已开始',
        ]);
    }

    public function backupStatus()
    {
        $id    = intval(Request::post('id'));
        $token = preg_replace('/[^0-9]/', '', (string)Request::post('token'));
        if (!$id || $token === '') {
            return json(['code' => 0, 'msg' => '参数错误']);
        }
        $base = $this->backupDir() . '/rep-' . $id . '-' . $token . '.sql.gz';

        clearstatcache();
        $bytes = is_file($base) ? filesize($base) : (is_file($base . '.part') ? filesize($base . '.part') : 0);

        if (is_file($base . '.done')) {
            $ok = trim((string)file_get_contents($base . '.done')) === 'ok';
            if ($ok && is_file($base)) {
                @unlink($base . '.err');
                @unlink($base . '.done');
                return json(['code' => 1, 'state' => 'done', 'bytes' => (int)$bytes, 'path' => $base]);
            }
            $err = is_file($base . '.err') ? trim((string)file_get_contents($base . '.err')) : '';
            return json(['code' => 0, 'state' => 'failed', 'msg' => 'mysqldump 失败：' . ($err ?: '未知原因')]);
        }
        return json(['code' => 1, 'state' => 'running', 'bytes' => (int)$bytes]);
    }

    /**
     * 真正执行。每次请求跑一段（TIME_BUDGET 秒）就返回进度，由前端循环调用。
     *
     * 入参：
     *   id           记录 ID
     *   restart=1    丢弃已有进度重新开始
     *   backup       备份文件路径（由 backup/backupStatus 得到）
     *   skip_backup=1 站长明确表示已自行备份
     *
     * 不带备份也不带 skip_backup 的调用会被拒 —— 这是最后一道闸。
     */
    public function execute()
    {
        $row = null;
        if (($bad = $this->loadExecutable($row)) !== null) {
            return $bad;
        }

        $id    = (int)$row->rep_id;
        $state = $this->statePath($id);
        $fresh = Request::post('restart') == '1' || !is_file($state);

        if ($fresh) {
            $backup = (string)Request::post('backup');
            $skip   = Request::post('skip_backup') == '1';
            if ($backup === '' && !$skip) {
                return json(['code' => 0, 'msg' => '缺少备份。请先执行备份，或明确勾选「已自行备份」']);
            }
            if ($backup !== '' && !is_file($backup)) {
                return json(['code' => 0, 'msg' => "备份文件不存在：{$backup}"]);
            }
            $data = [
                'rep_id'   => $id,
                'started'  => time(),
                'backup'   => $backup ?: '(站长声明已自行备份)',
                'orig'     => (string)$row->rep_original,
                'repl'     => (string)$row->rep_replacement,
                'units'    => RepModel::plan($row->rep_type),
                'total'    => 0,
            ];
            if (!$data['units']) {
                return json(['code' => 0, 'msg' => '没有可执行的表字段']);
            }
        } else {
            $data = json_decode((string)file_get_contents($state), true);
            if (!is_array($data) || empty($data['units'])) {
                return json(['code' => 0, 'msg' => '进度文件损坏，请点「重新开始」']);
            }
            // 记录在跑到一半时被改过,继续跑会把两半替换成不同的东西
            if (($data['orig'] ?? null) !== (string)$row->rep_original
                || ($data['repl'] ?? null) !== (string)$row->rep_replacement) {
                return json(['code' => 0, 'msg' => '记录内容在执行期间被修改过，已中止。请点「重新开始」']);
            }
        }

        // 同一条记录不允许两个浏览器同时推进,否则游标会互相覆盖
        $lock = fopen($state . '.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            if ($lock) { fclose($lock); }
            return json(['code' => 0, 'msg' => '该记录正在执行中（可能是另一个窗口），请稍候']);
        }

        $like  = RepModel::likePattern($data['orig']);
        $begin = microtime(true);
        $ran   = 0;

        try {
            foreach ($data['units'] as $i => &$u) {
                if (!empty($u['done'])) {
                    continue;
                }
                while ($u['cursor'] < $u['max']) {
                    $lo = (int)$u['cursor'];
                    $hi = $lo + self::BATCH_STEP;
                    $n  = Db::execute(
                        "UPDATE `{$u['table']}` SET `{$u['field']}` = REPLACE(`{$u['field']}`, ?, ?)
                         WHERE `{$u['pk']}` > ? AND `{$u['pk']}` <= ? AND `{$u['field']}` LIKE ? ESCAPE '\\\\'",
                        [$data['orig'], $data['repl'], $lo, $hi, $like]
                    );
                    $u['cursor']    = min($hi, (int)$u['max']);
                    $u['affected'] += (int)$n;
                    $data['total'] += (int)$n;
                    $ran++;
                    if (microtime(true) - $begin >= self::TIME_BUDGET) {
                        break 2;
                    }
                }
                $u['done'] = true;
            }
            unset($u);
        } catch (\Throwable $e) {
            file_put_contents($state, json_encode($data, JSON_UNESCAPED_UNICODE));
            flock($lock, LOCK_UN); fclose($lock);
            return json(['code' => 0, 'msg' => '执行出错（进度已保存，可续跑）：' . $e->getMessage()]);
        }

        // 进度百分比按主键区间推进程度算,不按命中行数 —— 命中行数事先无从知道
        $span = 0; $doneSpan = 0; $cur = '';
        foreach ($data['units'] as $u) {
            $w = max(1, (int)$u['max'] - (int)$u['min'] + 1);
            $span     += $w;
            $doneSpan += !empty($u['done']) ? $w : max(0, (int)$u['cursor'] - (int)$u['min'] + 1);
            if ($cur === '' && empty($u['done'])) {
                $cur = $u['table'] . '.' . $u['field'];
            }
        }
        $allDone = $cur === '';

        if ($allDone) {
            $row->rep_applied      = 1;
            $row->rep_applied_time = time();
            $row->save();
            @unlink($state);
        } else {
            file_put_contents($state, json_encode($data, JSON_UNESCAPED_UNICODE));
        }
        flock($lock, LOCK_UN); fclose($lock);
        @unlink($state . '.lock');

        return json([
            'code'    => 1,
            'done'    => $allDone,
            'percent' => $span > 0 ? round($doneSpan * 100 / $span, 1) : 100,
            'total'   => (int)$data['total'],
            'current' => $cur,
            'batches' => $ran,
            'backup'  => $data['backup'],
            'units'   => array_map(fn($u) => [
                'target'   => $u['table'] . '.' . $u['field'],
                'affected' => (int)$u['affected'],
                'done'     => !empty($u['done']),
            ], $data['units']),
            'msg'     => $allDone ? '执行完成' : '执行中',
        ]);
    }
}
