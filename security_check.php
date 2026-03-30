<?php
/**
 * MACCMS 安全检测工具
 * 
 * 用法: 
 *   命令行: php security_check.php
 *   浏览器: http://yoursite/security_check.php (检测完毕后立即删除此文件!)
 * 
 * 功能:
 *   1. 检测 application/extra/ 目录是否存在可疑文件
 *   2. 检测 JS 文件是否被篡改
 *   3. 检测 Update.php 是否存在 one() 风险方法
 *   4. 检测 ThinkPHP _method 注入是否已封堵
 *   5. 检测管理后台鉴权机制是否安全
 *   6. 检测 API Timming 鉴权绕过漏洞
 *   7. 检测会话安全配置
 *   8. 检测 addons.php 文件是否被篡改
 */

error_reporting(E_ALL);
ini_set('display_errors', 0);

define('ROOT_PATH', __DIR__ . DIRECTORY_SEPARATOR);
define('APP_PATH', ROOT_PATH . 'application' . DIRECTORY_SEPARATOR);

$isWeb = php_sapi_name() !== 'cli';
$results = [];
$hasVuln = false;

function check($name, $status, $detail = '') {
    global $results, $hasVuln;
    $results[] = [
        'name' => $name,
        'status' => $status,
        'detail' => $detail,
    ];
    if ($status === 'DANGER' || $status === 'WARNING') {
        $hasVuln = true;
    }
}

// ============================================
// 检查 1: application/extra/ 可疑文件检测
// ============================================
$extraDir = APP_PATH . 'extra' . DIRECTORY_SEPARATOR;
$allowedFiles = [
    'addons.php', 'bind.php', 'blacks.php', 'captcha.php',
    'domain.php', 'maccms.php', 'queue.php', 'quickmenu.php',
    'timming.php', 'version.php', 'voddowner.php', 'vodplayer.php',
    'vodserver.php',
];

if (is_dir($extraDir)) {
    $files = scandir($extraDir);
    $suspicious = [];
    foreach ($files as $f) {
        if ($f === '.' || $f === '..') continue;
        if (!in_array($f, $allowedFiles)) {
            $suspicious[] = $f;
        }
    }
    if (!empty($suspicious)) {
        check('extra/目录可疑文件', 'DANGER', 
            '发现未知文件: ' . implode(', ', $suspicious) . 
            "\n  这些文件可能是攻击者植入的后门，ThinkPHP 会自动加载 extra/ 下的所有 .php 文件。\n  请立即检查并删除这些文件！"
        );
    } else {
        check('extra/目录可疑文件', 'SAFE', '未发现异常文件');
    }
} else {
    check('extra/目录可疑文件', 'SAFE', '目录不存在');
}

// ============================================
// 检查 2: addons.php 完整性检测
// ============================================
$addonsFile = $extraDir . 'addons.php';
if (is_file($addonsFile)) {
    $size = filesize($addonsFile);
    $content = file_get_contents($addonsFile);
    
    // 正常的 addons.php 很小（约100字节），被篡改后通常 20-30KB
    if ($size > 1024) {
        check('addons.php 完整性', 'DANGER',
            "文件大小异常: {$size} 字节（正常约100字节）\n  该文件可能已被篡改，请用干净的 addons.php 替换！\n  正常内容应为:\n  <?php\n  return array('autoload'=>false,'hooks'=>array(),'route'=>array());"
        );
    } else {
        // 检查是否包含可疑代码
        $dangerPatterns = [
            'eval', 'assert', 'system', 'exec', 'passthru', 'shell_exec',
            'base64_decode', 'gzuncompress', 'gzinflate', 'str_rot13',
            'preg_replace.*\/e', 'call_user_func', 'file_put_contents',
            'fwrite', 'curl_exec', 'popen', 'proc_open',
        ];
        $found = [];
        foreach ($dangerPatterns as $p) {
            if (preg_match('/' . $p . '/i', $content)) {
                $found[] = $p;
            }
        }
        if (!empty($found)) {
            check('addons.php 完整性', 'DANGER',
                '发现可疑函数调用: ' . implode(', ', $found)
            );
        } else {
            check('addons.php 完整性', 'SAFE', '文件大小和内容正常');
        }
    }
} else {
    check('addons.php 完整性', 'WARNING', '文件不存在');
}

// ============================================
// 检查 3: active.php / system.php（攻击特征文件）
// ============================================
$attackFiles = ['active.php', 'system.php'];
foreach ($attackFiles as $af) {
    $fp = $extraDir . $af;
    if (is_file($fp)) {
        check("攻击特征文件 extra/{$af}", 'DANGER',
            "发现已知攻击特征文件！该文件是攻击者植入的后门。\n  请立即删除: {$fp}"
        );
    } else {
        check("攻击特征文件 extra/{$af}", 'SAFE', '未发现');
    }
}

// ============================================
// 检查 4: Update.php 是否存在 one() 方法
// ============================================
$updateFile = APP_PATH . 'admin/controller/Update.php';
if (is_file($updateFile)) {
    $updateContent = file_get_contents($updateFile);
    if (preg_match('/function\s+one\s*\(/', $updateContent)) {
        check('Update.php one() 方法', 'DANGER',
            "Update.php 仍包含高危的 one() 方法！\n  该方法允许下载并写入任意文件，是攻击者的主要利用入口。\n  请更新到最新版本以移除此方法。"
        );
    } else {
        check('Update.php one() 方法', 'SAFE', 'one() 方法已移除');
    }
    
    // 检查 Update URL 是否使用 HTTPS
    if (preg_match('/http:\/\/update/', $updateContent)) {
        check('Update.php 更新源安全', 'DANGER',
            "更新地址使用 HTTP 协议，存在中间人攻击风险！\n  请更新到最新版本以使用 HTTPS。"
        );
    } else {
        check('Update.php 更新源安全', 'SAFE', '使用 HTTPS 协议');
    }
    
    // 校验文件完整性
    $versionFile = $extraDir . 'version.php';
    if (is_file($versionFile)) {
        $versionConfig = include $versionFile;
        if (!empty($versionConfig['update_hash'])) {
            $actualHash = md5_file($updateFile);
            if ($actualHash !== $versionConfig['update_hash']) {
                check('Update.php 完整性', 'DANGER',
                    "Update.php 文件被篡改！\n  期望 hash: {$versionConfig['update_hash']}\n  实际 hash: {$actualHash}"
                );
            } else {
                check('Update.php 完整性', 'SAFE', 'MD5 校验通过');
            }
        } else {
            check('Update.php 完整性', 'WARNING', '未配置 update_hash，无法校验完整性');
        }
    }
} else {
    check('Update.php one() 方法', 'WARNING', 'Update.php 不存在');
}

// ============================================
// 检查 5: _method 注入是否封堵
// ============================================
$configFile = APP_PATH . 'config.php';
if (is_file($configFile)) {
    $configContent = file_get_contents($configFile);
    if (preg_match("/['\"]var_method['\"]\s*=>\s*['\"]_method['\"]/", $configContent)) {
        check('_method 参数注入', 'WARNING',
            "var_method 仍设置为 '_method'，存在请求参数注入风险。\n  建议将 var_method 设置为空字符串 '' 以禁用。"
        );
    } elseif (preg_match("/['\"]var_method['\"]\s*=>\s*['\"]['\"]/" , $configContent)) {
        check('_method 参数注入', 'SAFE', '_method 覆盖已禁用');
    } else {
        check('_method 参数注入', 'WARNING', '未找到 var_method 配置项');
    }
}

// ============================================
// 检查 6: Base.php 鉴权机制
// ============================================
$baseFile = APP_PATH . 'admin/controller/Base.php';
if (is_file($baseFile)) {
    $baseContent = file_get_contents($baseFile);
    
    // 检查是否使用了真实类名检查（而非 Request 单例）
    if (strpos($baseContent, 'get_class($this)') !== false || strpos($baseContent, 'get_class(') !== false) {
        check('Base.php 鉴权绕过修复', 'SAFE', '已使用真实类名校验');
    } elseif (preg_match("/\\$this->_cl\s*[!=].*Timming/", $baseContent)) {
        check('Base.php 鉴权绕过修复', 'DANGER',
            "鉴权检查使用 Request 单例的 controller() 值，存在绕过风险！\n  当通过 API Timming 间接实例化 admin 控制器时，\n  Request 仍报告 controller='Timming'，导致鉴权被跳过。\n  应使用 get_class(\$this) 获取真实控制器类名。"
        );
    }
}

// ============================================
// 检查 7: API Timming 安全性
// ============================================
$timmingFile = APP_PATH . 'api/controller/Timming.php';
if (is_file($timmingFile)) {
    $timmingContent = file_get_contents($timmingFile);
    
    // 检查是否有 POST 方法限制
    if (stripos($timmingContent, 'POST') !== false && stripos($timmingContent, 'REQUEST_METHOD') !== false) {
        check('API Timming POST 限制', 'SAFE', '已限制 POST 访问');
    } else {
        check('API Timming POST 限制', 'WARNING',
            "API Timming 未限制 POST 请求方式。\n  建议添加 POST 方法拒绝以缩小攻击面。"
        );
    }
    
    // 检查是否有 token 验证
    if (stripos($timmingContent, 'timming_token') !== false || stripos($timmingContent, 'token') !== false) {
        check('API Timming 令牌验证', 'SAFE', '已配置令牌验证机制');
    } else {
        check('API Timming 令牌验证', 'WARNING',
            "API Timming 未配置访问令牌验证。\n  建议在后台配置 timming_token 以限制访问。"
        );
    }
}

// ============================================
// 检查 8: 会话安全
// ============================================
$adminModelFile = APP_PATH . 'common/model/Admin.php';
if (is_file($adminModelFile)) {
    $adminContent = file_get_contents($adminModelFile);
    if (strpos($adminContent, 'session_regenerate_id') !== false) {
        check('会话固定攻击防护', 'SAFE', '登录时已重新生成 session ID');
    } else {
        check('会话固定攻击防护', 'WARNING',
            "登录时未调用 session_regenerate_id()。\n  攻击者可能通过会话固定攻击获取管理权限。"
        );
    }
}

// ============================================
// 检查 9: JS 文件篡改检测
// ============================================
$jsDirs = [
    ROOT_PATH . 'static/js/',
    ROOT_PATH . 'static_new/js/',
];
$suspiciousJs = [];
foreach ($jsDirs as $jsDir) {
    if (!is_dir($jsDir)) continue;
    $jsFiles = glob($jsDir . '*.js');
    foreach ($jsFiles as $jsFile) {
        $content = file_get_contents($jsFile);
        $contentLen = strlen($content);
        $lastLines = substr($content, -2000);
        // 检测常见的 JS 注入特征：仅在文件末尾追加的加密代码
        // 排除整个文件就是压缩JS的情况（如jquery.cookie.js）
        $jsPatterns = [
            '/eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,/',
            '/document\s*\.\s*write\s*\(\s*unescape\s*\(/',
            '/atob\s*\(\s*[\'"][A-Za-z0-9+\/=]{50,}/',
            '/new\s+Function\s*\(\s*[\'"]\\\\x/',
        ];
        foreach ($jsPatterns as $jp) {
            if (preg_match($jp, $lastLines)) {
                // 如果整个文件就是 eval(function(p,a,c,k,e, 开头的压缩JS，跳过（合法压缩）
                $trimmed = ltrim($content);
                if (preg_match('/^eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k/', $trimmed) && $contentLen < 10000) {
                    break; // 整文件是压缩JS，非注入
                }
                $suspiciousJs[] = basename($jsFile);
                break;
            }
        }
    }
}

if (!empty($suspiciousJs)) {
    check('JS 文件篡改检测', 'DANGER',
        '发现可疑 JS 文件: ' . implode(', ', array_unique($suspiciousJs)) .
        "\n  这些文件末尾可能被注入了加密恶意代码。\n  请对比干净版本逐个检查并还原。"
    );
} else {
    check('JS 文件篡改检测', 'SAFE', '未发现可疑注入');
}

// ============================================
// 检查 10: template/ 目录 JS 文件检测
// ============================================
$templateDir = ROOT_PATH . 'template/';
if (is_dir($templateDir)) {
    $templateJs = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($templateDir, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if ($file->getExtension() === 'js') {
            $content = file_get_contents($file->getPathname());
            $lastLines = substr($content, -2000);
            $jsPatterns = [
                '/eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,/',
                '/document\s*\.\s*write\s*\(\s*unescape\s*\(/',
                '/atob\s*\(\s*[\'"][A-Za-z0-9+\/=]{50,}/',
            ];
            foreach ($jsPatterns as $jp) {
                if (preg_match($jp, $lastLines)) {
                    $templateJs[] = str_replace($templateDir, 'template/', $file->getPathname());
                    break;
                }
            }
        }
    }
    if (!empty($templateJs)) {
        check('模板目录 JS 文件检测', 'DANGER',
            '发现可疑模板 JS 文件: ' . implode(', ', $templateJs)
        );
    } else {
        check('模板目录 JS 文件检测', 'SAFE', '未发现可疑注入');
    }
}

// ============================================
// 检查 11: Timming 配置安全性
// ============================================
$timmingConfigFile = $extraDir . 'timming.php';
if (is_file($timmingConfigFile)) {
    $timmingConfig = include $timmingConfigFile;
    if (is_array($timmingConfig)) {
        $enabledTasks = [];
        foreach ($timmingConfig as $k => $v) {
            if (isset($v['status']) && $v['status'] == '1') {
                $enabledTasks[] = $v['name'] ?? $k;
            }
        }
        if (!empty($enabledTasks)) {
            check('Timming 任务状态', 'INFO',
                '已启用的定时任务: ' . implode(', ', $enabledTasks) .
                "\n  如非必要，建议禁用不需要的定时任务以缩小攻击面。"
            );
        } else {
            check('Timming 任务状态', 'SAFE', '所有定时任务已禁用');
        }
    }
}

// ============================================
// 检查 12: admin.php 入口文件安全
// ============================================
if (is_file(ROOT_PATH . 'admin.php')) {
    check('admin.php 入口文件', 'WARNING',
        "admin.php 未重命名！\n  攻击者可直接定位后台入口。请将 admin.php 重命名为不可预测的文件名。"
    );
} else {
    check('admin.php 入口文件', 'SAFE', 'admin.php 已重命名');
}

// ============================================
// 检查 13: install.php 是否可访问
// ============================================
if (is_file(ROOT_PATH . 'install.php') && !is_file(APP_PATH . 'data/install/install.lock')) {
    check('install.php 安装入口', 'DANGER',
        "install.php 存在且未锁定！攻击者可重新安装系统。\n  请确保 application/data/install/install.lock 文件存在。"
    );
} else {
    check('install.php 安装入口', 'SAFE', '安装已锁定或入口不存在');
}

// ============================================
// 输出结果
// ============================================
$dangerCount = count(array_filter($results, function($r) { return $r['status'] === 'DANGER'; }));
$warningCount = count(array_filter($results, function($r) { return $r['status'] === 'WARNING'; }));
$safeCount = count(array_filter($results, function($r) { return $r['status'] === 'SAFE'; }));

if ($isWeb) {
    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>MACCMS 安全检测</title>';
    echo '<style>
        body{font-family:monospace;background:#1a1a2e;color:#eee;padding:20px;max-width:900px;margin:0 auto}
        h1{color:#e94560;border-bottom:2px solid #e94560;padding-bottom:10px}
        .summary{background:#16213e;padding:15px;border-radius:8px;margin:20px 0;display:flex;gap:20px}
        .summary span{padding:5px 15px;border-radius:4px;font-weight:bold}
        .danger{background:#e94560;color:#fff}
        .warning{background:#f5a623;color:#000}
        .safe{background:#2ecc71;color:#fff}
        .info{background:#3498db;color:#fff}
        .item{background:#16213e;margin:10px 0;padding:15px;border-radius:8px;border-left:4px solid}
        .item.d{border-color:#e94560} .item.w{border-color:#f5a623} .item.s{border-color:#2ecc71} .item.i{border-color:#3498db}
        .item h3{margin:0 0 5px 0} .item pre{margin:5px 0;white-space:pre-wrap;font-size:12px;color:#aaa}
        .banner{text-align:center;color:#e94560;font-size:12px;margin-top:30px}
    </style></head><body>';
    echo '<h1>🔒 MACCMS 安全检测报告</h1>';
    echo '<div class="summary">';
    echo "<span class='danger'>危险: {$dangerCount}</span>";
    echo "<span class='warning'>警告: {$warningCount}</span>";
    echo "<span class='safe'>安全: {$safeCount}</span>";
    echo '</div>';
    
    foreach ($results as $r) {
        $cls = $r['status'] === 'DANGER' ? 'd' : ($r['status'] === 'WARNING' ? 'w' : ($r['status'] === 'INFO' ? 'i' : 's'));
        $statusLower = strtolower($r['status']);
        if ($statusLower === 'danger') { $badgeClass = 'danger'; }
        elseif ($statusLower === 'warning') { $badgeClass = 'warning'; }
        elseif ($statusLower === 'info') { $badgeClass = 'info'; }
        else { $badgeClass = 'safe'; }
        $badge = "<span class='" . $badgeClass . "'>" . $r['status'] . "</span>";
        echo "<div class='item " . $cls . "'><h3>" . $badge . " " . htmlspecialchars($r['name']) . "</h3>";
        if (!empty($r['detail'])) {
            echo "<pre>" . htmlspecialchars($r['detail']) . "</pre>";
        }
        echo '</div>';
    }
    
    echo '<div class="banner">⚠️ 安全提醒：检测完毕后请立即删除 security_check.php 文件！</div>';
    echo '</body></html>';
} else {
    // CLI 输出
    echo "\n";
    echo "═══════════════════════════════════════════════════\n";
    echo "  MACCMS 安全检测报告\n";
    echo "═══════════════════════════════════════════════════\n\n";
    echo "  危险: {$dangerCount}  |  警告: {$warningCount}  |  安全: {$safeCount}\n\n";
    echo "───────────────────────────────────────────────────\n\n";
    
    foreach ($results as $r) {
        $icon = $r['status'] === 'DANGER' ? '❌' : ($r['status'] === 'WARNING' ? '⚠️ ' : ($r['status'] === 'INFO' ? 'ℹ️ ' : '✅'));
        echo "  {$icon} [{$r['status']}] {$r['name']}\n";
        if (!empty($r['detail'])) {
            $lines = explode("\n", $r['detail']);
            foreach ($lines as $line) {
                echo "     {$line}\n";
            }
        }
        echo "\n";
    }
    echo "───────────────────────────────────────────────────\n";
    echo "  ⚠️  检测完毕后请立即删除 security_check.php！\n";
    echo "═══════════════════════════════════════════════════\n\n";
}

exit($hasVuln ? 1 : 0);
