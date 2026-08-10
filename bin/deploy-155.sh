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
SITES=("155zy.com" "155api.com")
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
API_FORBIDDEN=(
    "application/api/controller/Yzm.php"   # 入库接口只应存在于主站
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

    # .user.ini 被 aaPanel 用 chattr +i 锁定，chown 必然失败且不应中断部署，
    # 故显式排除它；其余一律归还 www:www（rsync 以 root 跑会把新建文件留给 root）。
    $SSH "find /home/wwwroot/$site -name .user.ini -prune -o -exec chown www:www {} + 2>/dev/null; \
          chmod -R 775 /home/wwwroot/$site/runtime /home/wwwroot/$site/log /home/wwwroot/$site/application/data 2>/dev/null; \
          rm -rf /home/wwwroot/$site/runtime/*; \
          chown -R www:www /home/wwwroot/$site/runtime; true" >/dev/null
    echo "  属主与缓存已处理"
done

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
# yzm 配置只有主站需要（API 站不含入库接口）
$SSH "test -s /home/wwwroot/${SITES[0]}/application/extra/yzm.php" \
    && printf "  %-12s %-34s ok\n" "${SITES[0]}" "application/extra/yzm.php" \
    || { printf "  %-12s %-34s !! 缺失（转码机入库将拒绝服务）\n" "${SITES[0]}" "application/extra/yzm.php"; missing=1; }
if [ "$missing" = "1" ]; then
    echo
    echo "  ⚠ 有站点私有配置缺失。备份在 /home/migrate/ 下，例如："
    echo "      cp /home/migrate/site-config-backup-yzm.php \\"
    echo "         /home/wwwroot/${SITES[0]}/application/extra/yzm.php"
    echo "      chown www:www … && chmod 640 …"
fi

echo
echo "── 冒烟 ──────────────────────────────"
for site in "${SITES[@]}"; do
    for path in "/" "/api.php/provide/vod/?ac=list"; do
        code=$(curl -sS -o /dev/null -w '%{http_code}' -m 25 -H "Host: $site" "http://$HOST$path" 2>/dev/null || echo "ERR")
        printf "  %-12s %-32s %s\n" "$site" "${path:0:30}" "$code"
    done
done
echo
echo "完成。若改动了 application/admin/controller/Update.php，"
echo "记得同步 application/extra/version.php 的 update_hash（否则后台会被完整性校验锁死）。"
