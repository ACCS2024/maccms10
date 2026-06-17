#!/usr/bin/env bash
# maccms-cli 公共函数库(被 bin/maccms 引用)
set -euo pipefail

# 颜色(非 TTY 时禁用)
if [ -t 2 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
else
  C_RED=''; C_GRN=''; C_YEL=''; C_DIM=''; C_RST=''
fi

log()  { printf '%s[maccms]%s %s\n' "$C_GRN" "$C_RST" "$*" >&2; }
warn() { printf '%s[maccms]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
die()  { printf '%s[maccms] 错误:%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

# 找 php 可执行
php_bin() { command -v php >/dev/null 2>&1 || die "未找到 php,可执行环境缺失"; echo php; }

# 交互确认(--yes / 非 TTY 直接通过由调用方控制)
confirm() {
  local msg="$1"
  printf '%s [y/N] ' "$msg" >&2
  local ans; read -r ans || true
  [[ "$ans" =~ ^[Yy]$ ]]
}

# 读取 root 口令:env MACCMS_DB_ROOT_PASS > stdin(管道) > 交互
# 输出到 stdout(由调用方捕获),绝不出现在参数里
read_root_pass() {
  if [ -n "${MACCMS_DB_ROOT_PASS:-}" ]; then printf '%s' "$MACCMS_DB_ROOT_PASS"; return; fi
  if [ ! -t 0 ]; then cat -; return; fi
  local p; read -rs -p "MySQL root 口令: " p >&2; printf '\n' >&2; printf '%s' "$p"
}

# 设置站点目录可写项(只放开必要的可写路径,代码目录不世界可写)
ensure_writable() {
  local root="$1"
  mkdir -p "$root/runtime" "$root/upload" "$root/application/data/install" \
           "$root/application/data/backup" "$root/application/data/update" 2>/dev/null || true
  # 这些路径安装/运行期需要写
  chmod -R u+rwX "$root/runtime" "$root/upload" "$root/application/data" "$root/application/extra" 2>/dev/null || true
  chmod u+rw "$root/application/database.php" "$root/application/route.php" 2>/dev/null || true
}

# 同步源码树到目标路径(排除运行期/版本控制/已有安装锁)
provision_code() {
  local src="$1" dest="$2"
  mkdir -p "$dest"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
      --exclude '.git' \
      --exclude 'runtime/*' \
      --exclude 'application/data/install/install.lock' \
      "$src/" "$dest/"
  else
    warn "未找到 rsync,改用 cp(不做差量/清理)"
    cp -a "$src/." "$dest/"
    rm -f "$dest/application/data/install/install.lock" 2>/dev/null || true
  fi
}

# 环境体检
check_env() {
  local php; php="$(php_bin)"
  log "PHP: $("$php" -r 'echo PHP_VERSION;')"
  local need=(pdo pdo_mysql mbstring curl json zip)
  local miss=()
  for ext in "${need[@]}"; do "$php" -m | grep -qi "^${ext}$" || miss+=("$ext"); done
  if [ "${#miss[@]}" -gt 0 ]; then warn "缺少扩展: ${miss[*]}"; else log "扩展齐全: ${need[*]}"; fi
  command -v rsync >/dev/null 2>&1 && log "rsync: 可用" || warn "rsync 不可用(new 将回落到 cp)"
}
