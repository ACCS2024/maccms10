#!/bin/bash
# 155 站群部署：把本地代码树一次性同步到新机的两个站点实例。
#
# 为什么是两个目录而不是共用一个：
#   两站需要不同的 application/extra/maccms.php（api 开关、upload.mode、interface.pass 等），
#   而 maccms 的 domain.php 只能覆盖 $config['site'] 一节，覆盖不了 api/upload/collect。
#   更重要的是物理隔离：155api 目录里不存在 Yzm 入库接口与主站后台入口，
#   这个保证不依赖任何一行 nginx 规则（nginx 的 location 优先级很容易写错而静默失效）。
#
# 「要改两遍」的成本由本脚本消除：一条命令同步两站，不会漏。
set -euo pipefail

HOST="${MACCMS_HOST:-23.224.241.250}"

# 默认一次发两站（「要改两遍」的成本由本脚本消除）。
# 但**金丝雀发布必须能只发一个站**：155api 没有后台、没有前台主题、故障面最小，
# 是天然的金丝雀。改动大时先只发它、观察，确认无恙再发主站。
#   MACCMS_SITES="155api.com" bash bin/deploy-155.sh
# 多个站用空格分隔。留空则用默认的两站。
if [ -n "${MACCMS_SITES:-}" ]; then
    read -r -a SITES <<< "$MACCMS_SITES"
else
    SITES=("155zy.com" "155api.com")
fi
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/"

if [ -z "${SSHPASS:-}" ]; then
    echo "请先 export SSHPASS='<新机 root 口令>'" >&2
    exit 1
fi
# 连接复用：本脚本会发起多次 ssh/rsync，逐次新建连接容易撞上 sshd 的
# MaxStartups / 认证节流（表现为 kex_exchange_identification: Connection closed）。
# ControlMaster 让所有操作共用一条连接，既避开节流也更快。
CTL="/tmp/.deploy155-%r@%h:%p"
SSH_OPTS="-o StrictHostKeyChecking=no -o PreferredAuthentications=password -o PubkeyAuthentication=no \
-o ControlMaster=auto -o ControlPath=$CTL -o ControlPersist=120"
SSH="ssh $SSH_OPTS root@$HOST"

cleanup() { ssh -O exit -o ControlPath="$CTL" "root@$HOST" 2>/dev/null || true; }
trap cleanup EXIT

# 建立主连接（唯一一次需要口令）
sshpass -e ssh $SSH_OPTS -fN root@$HOST

# 每个站点自有、绝不能被代码树覆盖的东西
EXCLUDES=(
    --exclude='.git/'            --exclude='.github/'
    --exclude='runtime/'         --exclude='upload/'
    --exclude='log/'             --exclude='.env'
    --exclude='.user.ini'                                  # aaPanel 用 chattr +i 锁定，且各站 open_basedir 不同
    --exclude='application/extra/maccms.php'               # 两站配置本就不同
    --exclude='application/extra/yzm.php'                  # 转码机对接的站点私有配置(含基础设施地址)
    --exclude='application/data/install/install.lock'
    --exclude='template/155zy/'                            # 线上主题，不在仓库里
    --exclude='admin.php'        --exclude='adm_*.php'     # 后台入口已各自改随机名
    --exclude='install.php'                                # 装完即删，不应重新出现
    --exclude='vendor/'                                    # 由 composer install 管理
    --exclude='thinkphp_legacy_*/'
    --exclude='composer.phar'    --exclude='tests/'
    --exclude='migration/'       --exclude='docs/'
    --exclude='*.log'            --exclude='.claude/'
    --exclude='bin/deploy-155.sh'
)

# 155api 不应存在的文件（物理隔离的关键，同步后强制清除）
# API 站按设计【不含】转码机入库接口 —— 这个隔离不依赖任何一行 nginx 规则。
# 名单必须随控制器改名一起更新：Yzm.php 改名成 Ppvod.php 之后这里没跟着改，
# 结果入库控制器被同步进了 API 站（实测 /api.php/yzm/yzmauto 在 API 站返回 200），
# 隔离静默失效。旧名保留，防止历史部署残留。
API_FORBIDDEN=(
    "application/api/controller/Ppvod.php"  # 入库接口（现名），只应存在于主站
    "application/api/controller/Yzm.php"    # 旧名，清理历史残留
    "application/api/route/route.php"       # 仅为入库接口提供 yzm/* 历史别名路由
)

# 仓库里已删除、必须同步从生产删掉的路径。
#
# 为什么需要这份名单：上面的 rsync 【没有】 --delete，也不能加 —— 加了会连站点私有的
# template/155zy/、.env、随机名后台入口一起删掉（它们只存在于生产，不在代码树里）。
# 于是"仓库里删掉一个文件"这件事默认不会传播到生产：孤儿 PHP 会永久留在站点根目录。
# 对刚做完木马取证的机器，留一堆没人维护的孤儿 PHP 本身就是净负债；
# 更现实的问题是，任何"断言这些路径不存在"的自检在生产上会恒为 FAIL。
#
# 规则：任何删除文件的 commit，必须同时往这份数组里加一行。
REMOVED_PATHS=(
    # TP5 死平面（TP8 从不加载，却仍被后台/安装器写入）
    "application/config.php"
    "application/database.php"
    "application/route.php"
    "application/command.php"
    "application/tags.php"
    "application/common/behavior"
    # TP8 下不再使用的实现
    "application/middleware/SessionSameSite.php"   # 依赖 session_start()，TP8 从不调用
    "application/index/controller/Myerror.php"     # TP5 的 _empty 约定，TP8 不认
    # FUNNULL/RingH23 投毒链清理：孤儿的在线更新 JS（内含 update.maccms.la）
    "static_new/js/update.js"
    "static/js/update.js"
)

echo "源: $SRC"
echo "目标: $HOST → ${SITES[*]}"
echo

for site in "${SITES[@]}"; do
    echo "── $site ──────────────────────────────"
    # --no-owner --no-group：以 root 跑 rsync 会把目标属主改成 root，
    # 导致 FPM(www) 无法在站点根创建 log/ 等目录（本次迁移踩过）
    rsync -a --no-owner --no-group --info=stats1 \
        -e "ssh $SSH_OPTS" "${EXCLUDES[@]}" \
        "$SRC" "root@$HOST:/home/wwwroot/$site/" 2>&1 | grep -E 'transferred|created' || true

    if [ "$site" = "155api.com" ]; then
        for f in "${API_FORBIDDEN[@]}"; do
            $SSH "rm -f /home/wwwroot/$site/$f" && echo "  已移除 $f（API 站不应包含）"
        done
    fi

    # 传播删除（rsync 无 --delete，见 REMOVED_PATHS 上方说明）
    if [ ${#REMOVED_PATHS[@]} -gt 0 ]; then
        removed=0
        for p in "${REMOVED_PATHS[@]}"; do
            if $SSH "test -e /home/wwwroot/$site/$p"; then
                $SSH "rm -rf /home/wwwroot/$site/$p"
                echo "  已删除残留 $p"
                removed=$((removed+1))
            fi
        done
        [ "$removed" = "0" ] && echo "  无待删除残留"
    fi

    # vendor/ 被 EXCLUDES 排除（由 composer 管理），所以依赖必须在远端装。
    # 不装的后果很隐蔽：改了 composer.json 的 psr-4 或加了新依赖之后，
    # 部署会"看起来成功"，然后整站 Class not found。
    if $SSH "command -v composer >/dev/null 2>&1"; then
        echo "  composer install …"
        $SSH "cd /home/wwwroot/$site && sudo -u www COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --no-interaction --no-progress -o 2>&1 | tail -3" || {
            echo "  ⚠ composer install 失败，请手工在 /home/wwwroot/$site 下执行后再冒烟"
        }
    else
        echo "  ⚠ 远端没有 composer：跳过依赖安装。若本次改动了 composer.json，请先装 composer"
    fi

    # .user.ini 被 aaPanel 用 chattr +i 锁定，chown 必然失败且不应中断部署，
    # 故显式排除它；其余一律归还 www:www（rsync 以 root 跑会把新建文件留给 root）。
    # runtime 清理：只清编译产物与缓存，【保留 session】。
    # 原先是 rm -rf runtime/*，等于每次部署把所有管理员与会员踢下线
    # （20 次部署 = 20 次强制登出）。会话要单独清时用 --flush-sessions。
    KEEP_SESSION="! -name session"
    [ "${FLUSH_SESSIONS:-0}" = "1" ] && KEEP_SESSION=""
    $SSH "find /home/wwwroot/$site -name .user.ini -prune -o -exec chown www:www {} + 2>/dev/null; \
          chmod -R 775 /home/wwwroot/$site/runtime /home/wwwroot/$site/log /home/wwwroot/$site/application/data 2>/dev/null; \
          find /home/wwwroot/$site/runtime -mindepth 1 -maxdepth 1 $KEEP_SESSION -exec rm -rf {} + 2>/dev/null; \
          chown -R www:www /home/wwwroot/$site/runtime; true" >/dev/null
    # 静态资源版本戳：模板里的 ?v=__ASSETV__ 取这个值（见 middleware/AppInit.php）。
    # 每次部署写一个新时间戳 —— 这是唯一「每次 push 必变、同一次部署内不变」的来源。
    # 不写的话，改了 JS/CSS 推上去浏览器仍吃旧缓存，表现为「明明改了却没生效」。
    $SSH "date +%Y%m%d%H%M%S > /home/wwwroot/$site/application/data/asset_version.txt && \
          chown www:www /home/wwwroot/$site/application/data/asset_version.txt"
    echo "  静态资源版本戳已更新"

    [ "${FLUSH_SESSIONS:-0}" = "1" ] && echo "  已清空会话（所有人需重新登录）"
    echo "  属主与缓存已处理"
done

# OPcache：不 reload 的话，改过的 config/ 与 application/ 下的 PHP 在旧进程里仍是旧字节码，
# 于是"改配置 → 立刻 curl 验证"既可能假绿也可能假红。放在冒烟之前。
echo
echo "── reload php-fpm ────────────────────"
$SSH "if [ -x /etc/init.d/php-fpm-83 ]; then /etc/init.d/php-fpm-83 reload && echo '  php-fpm-83 reloaded'; \
      elif command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service --all 2>/dev/null | grep -qE 'php[0-9.-]*fpm'; then \
        systemctl reload \$(systemctl list-units --type=service --all --no-legend 2>/dev/null | grep -oE 'php[0-9.-]*fpm[^ ]*' | head -1) && echo '  php-fpm reloaded (systemd)'; \
      else echo '  ⚠ 未找到 php-fpm 服务，请手工 reload，否则本次改动可能未生效'; fi" || true

echo
echo "── 站点私有配置完整性 ────────────────"
# 这些文件被 EXCLUDES 排除（含各站自己的凭据/地址），一旦缺失，
# 站点会静默降级：Yzm 入库直接拒绝服务、数据库连不上。
# 部署后必须显式校验存在性，否则问题要等到转码机推内容失败才暴露。
missing=0
for site in "${SITES[@]}"; do
    for f in ".env" "application/extra/maccms.php"; do
        $SSH "test -s /home/wwwroot/$site/$f" \
            && printf "  %-12s %-34s ok\n" "$site" "$f" \
            || { printf "  %-12s %-34s !! 缺失\n" "$site" "$f"; missing=1; }
    done
done
# PPVOD 入库配置：只有装了入库控制器的站才需要（API 站按设计不含它）。
#
# 不要写死 ${SITES[0]}——那假设了「第一个站就是主站」，金丝雀模式
# （MACCMS_SITES="155api.com"）下会去 API 站找主站才该有的东西，报假警报。
# 也不要再找 application/extra/yzm.php：那份独立配置在 Yzm→Ppvod 改名时
# 已并入 application/extra/maccms.php 的 'ppvod' 段，文件本身不该再存在。
# 改为按「该站有没有 Ppvod 控制器」自描述地判断，并校验配置真的可用。
for site in "${SITES[@]}"; do
    if ! $SSH "test -f /home/wwwroot/$site/application/api/controller/Ppvod.php" 2>/dev/null; then
        continue
    fi
    if $SSH "sudo -u www php -r '
        \$c = @include \"/home/wwwroot/$site/application/extra/maccms.php\";
        \$p = (is_array(\$c) ? (\$c[\"ppvod\"] ?? []) : []);
        exit((is_array(\$p) && !empty(\$p[\"play_domain\"]) && !empty(\$p[\"pic_domain\"])
              && !empty(\$p[\"category_map\"])) ? 0 : 1);'" 2>/dev/null; then
        printf "  %-12s %-34s ok\n" "$site" "extra/maccms.php 的 ppvod 段"
    else
        printf "  %-12s %-34s !! 不完整（转码机入库将拒绝服务）\n" "$site" "extra/maccms.php 的 ppvod 段"
        missing=1
    fi
done
if [ "$missing" = "1" ]; then
    echo
    echo "  ⚠ 有站点私有配置缺失或不完整。"
    echo "     .env / extra/maccms.php 被本脚本 EXCLUDES 排除，不随代码分发。"
    echo "     PPVOD 相关项在后台「系统 → PPVOD 转码入库」里填（播放域名/图床域名/分类映射为必填）。"
fi

echo
echo "── 远端静态自检 ──────────────────────"
# 以 www 身份跑：以 root 跑会在 www 属主的 runtime 下留 root 属主文件，
# 下一次 FPM 写同一路径会失败——而这条路径恰好是 fail-silent 的。
for site in "${SITES[@]}"; do
    out=$($SSH "cd /home/wwwroot/$site && sudo -u www php think mac:selfcheck 2>&1 | tail -1" || echo "ERR")
    printf "  %-12s %s\n" "$site" "$out"
    $SSH "chown -R www:www /home/wwwroot/$site/runtime 2>/dev/null; true" >/dev/null
done

echo
echo "── 冒烟 ──────────────────────────────"
for site in "${SITES[@]}"; do
    for path in "/" "/api.php/provide/vod/?ac=list"; do
        code=$(curl -sS -o /dev/null -w '%{http_code}' -m 25 -H "Host: $site" "http://$HOST$path" 2>/dev/null || echo "ERR")
        printf "  %-12s %-32s %s\n" "$site" "${path:0:30}" "$code"
    done
done
echo
echo "提示：清空所有登录会话请用  FLUSH_SESSIONS=1 bash bin/deploy-155.sh"
echo
echo "完成。若改动了 application/admin/controller/Update.php，"
echo "记得同步 application/extra/version.php 的 update_hash（否则后台会被完整性校验锁死）。"
