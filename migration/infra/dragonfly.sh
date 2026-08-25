#!/usr/bin/env bash
#
# Dragonfly 一键部署 / 升级 / 状态检查脚本（裸机二进制 + systemd）。
# 为 maccms10 的 Redis 协议缓存与会话存储配套。
#
# 默认配置会按机器资源自适应：
#   - maxmemory 取总内存约 1/16，限制在 512 MiB ~ 8 GiB。
#   - proactor_threads 按 CPU 和缓存额度取小值，默认最多 8。
#   - 始终保证每个 proactor thread 至少有 256 MiB，避免高核机器拒绝启动。
#
# 用法：
#   sudo bash dragonfly.sh install
#   sudo bash dragonfly.sh status
#   sudo bash dragonfly.sh upgrade
#   sudo bash dragonfly.sh uninstall
#   sudo bash dragonfly.sh uninstall --purge
#
# 可用环境变量覆盖自动值，例如：
#   sudo DF_MAXMEMORY_MB=4096 DF_PROACTOR_THREADS=4 bash dragonfly.sh install
#   sudo DF_VERSION=v1.40.1 GH_PROXY=https://ghproxy.net/ bash dragonfly.sh upgrade
#
set -euo pipefail

# ============================ 可配置变量 ============================
DF_VERSION="${DF_VERSION:-v1.40.1}"
DF_BIND="${DF_BIND:-127.0.0.1}"
DF_PORT="${DF_PORT:-6379}"
DF_MAXMEMORY_MB="${DF_MAXMEMORY_MB:-}"
DF_PROACTOR_THREADS="${DF_PROACTOR_THREADS:-}"
DF_MAX_AUTO_THREADS="${DF_MAX_AUTO_THREADS:-8}"

DF_USER="${DF_USER:-dragonfly}"
DF_GROUP="${DF_GROUP:-dragonfly}"
DF_HOME="${DF_HOME:-/var/lib/dragonfly}"
DF_ETC_DIR="${DF_ETC_DIR:-/etc/dragonfly}"
DF_CONFIG="${DF_CONFIG:-${DF_ETC_DIR}/dragonfly.conf}"
DF_PASSWORD_FILE="${DF_PASSWORD_FILE:-${DF_ETC_DIR}/password}"
DF_BIN_DIR="${DF_BIN_DIR:-/opt/dragonfly/bin}"
DF_BIN_LINK="${DF_BIN_LINK:-/usr/local/bin/dragonfly}"

SERVICE_NAME="${SERVICE_NAME:-dragonfly}"
SYSTEMD_UNIT="/etc/systemd/system/${SERVICE_NAME}.service"
GH_BASE="${GH_BASE:-https://github.com/dragonflydb/dragonfly/releases/download}"
GH_PROXY="${GH_PROXY:-}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-30}"

# ============================ 基础工具 ============================
C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'; C_BLU=$'\033[36m'; C_RST=$'\033[0m'
log()  { printf '%s[dragonfly]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$C_YLW" "$C_RST" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

need_root() {
  [ "$(id -u)" = "0" ] || die "需要 root 权限（systemd/创建用户/写系统目录）。请用 sudo 运行。"
}

have() { command -v "$1" >/dev/null 2>&1; }
ver_num() { printf '%s' "${1#v}"; }
bin_path_for() { printf '%s/dragonfly-%s' "$DF_BIN_DIR" "$(ver_num "$1")"; }

is_uint() {
  case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac
}

cpu_count() {
  getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1
}

total_memory_mb() {
  awk '/^MemTotal:/{print int($2/1024); exit}' /proc/meminfo
}

# 共享 Web/DB 主机默认只给缓存约 1/16 内存，且控制在 512 MiB ~ 8 GiB。
auto_maxmemory_mb() {
  local total value
  total="$(total_memory_mb)"
  value=$((total / 16))
  # 取最接近的 512 MiB 档位，避免生成 4023 MiB 这类难读配置。
  value=$((((value + 256) / 512) * 512))
  [ "$value" -lt 512 ] && value=512
  [ "$value" -gt 8192 ] && value=8192
  printf '%s\n' "$value"
}

# 缓存每 1 GiB 默认配一个线程；同时受 CPU、8 线程上限和 256 MiB/线程硬门槛约束。
auto_proactor_threads() {
  local memory_mb="$1" cpus threads memory_ceiling
  cpus="$(cpu_count)"
  threads=$((memory_mb / 1024))
  [ "$threads" -lt 1 ] && threads=1
  [ "$threads" -gt "$cpus" ] && threads="$cpus"
  [ "$threads" -gt "$DF_MAX_AUTO_THREADS" ] && threads="$DF_MAX_AUTO_THREADS"
  memory_ceiling=$((memory_mb / 256))
  [ "$memory_ceiling" -lt 1 ] && memory_ceiling=1
  [ "$threads" -gt "$memory_ceiling" ] && threads="$memory_ceiling"
  printf '%s\n' "$threads"
}

resolve_resources() {
  local min_memory
  if [ -z "$DF_MAXMEMORY_MB" ]; then
    DF_MAXMEMORY_MB="$(auto_maxmemory_mb)"
  fi
  is_uint "$DF_MAXMEMORY_MB" || die "DF_MAXMEMORY_MB 必须是 MiB 整数，当前：$DF_MAXMEMORY_MB"
  [ "$DF_MAXMEMORY_MB" -ge 256 ] || die "DF_MAXMEMORY_MB 至少为 256 MiB。"

  if [ -z "$DF_PROACTOR_THREADS" ]; then
    DF_PROACTOR_THREADS="$(auto_proactor_threads "$DF_MAXMEMORY_MB")"
  fi
  is_uint "$DF_PROACTOR_THREADS" || die "DF_PROACTOR_THREADS 必须是正整数，当前：$DF_PROACTOR_THREADS"
  [ "$DF_PROACTOR_THREADS" -ge 1 ] || die "DF_PROACTOR_THREADS 至少为 1。"

  min_memory=$((DF_PROACTOR_THREADS * 256))
  [ "$DF_MAXMEMORY_MB" -ge "$min_memory" ] || die "当前线程数至少需要 ${min_memory} MiB；请增大 DF_MAXMEMORY_MB 或减小 DF_PROACTOR_THREADS。"
}

arch_suffix() {
  case "$(uname -m)" in
    x86_64|amd64) echo x86_64 ;;
    aarch64|arm64) echo aarch64 ;;
    *) die "不支持的 CPU 架构：$(uname -m)。" ;;
  esac
}

download() {
  local url="$1" dest="$2" final tries=0
  final="${GH_PROXY}${url}"
  while [ "$tries" -lt 4 ]; do
    tries=$((tries + 1))
    if have curl; then
      curl -fL --connect-timeout 15 --retry 2 -o "$dest" "$final" && return 0
    elif have wget; then
      wget -q -O "$dest" "$final" && return 0
    else
      die "未找到 curl 或 wget，无法下载。"
    fi
    warn "下载失败，重试 ($tries/4)：$final"
    sleep $((tries * 2))
  done
  return 1
}

installed_version() {
  [ -x "$DF_BIN_LINK" ] || { echo ""; return; }
  { "$DF_BIN_LINK" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1; } || true
}

password() {
  [ -r "$DF_PASSWORD_FILE" ] || { echo ""; return; }
  tr -d '\r\n' < "$DF_PASSWORD_FILE"
}

gen_password() {
  if have openssl; then
    openssl rand -hex 24
  else
    head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

ensure_user() {
  if ! id "$DF_USER" >/dev/null 2>&1; then
    log "创建系统用户 $DF_USER"
    if have useradd; then
      useradd --system --no-create-home --shell /usr/sbin/nologin "$DF_USER"
    elif have adduser; then
      adduser -S -H -s /sbin/nologin "$DF_USER"
    else
      die "无 useradd/adduser，无法创建用户 $DF_USER。"
    fi
  fi
}

ensure_dirs() {
  install -d -m 750 -o "$DF_USER" -g "$DF_GROUP" "$DF_HOME"
  install -d -m 750 -o root -g "$DF_GROUP" "$DF_ETC_DIR"
  install -d -m 755 "$DF_BIN_DIR"
}

fetch_binary() {
  local version="$1" arch url tmp_dir archive binary dest got
  arch="$(arch_suffix)"
  dest="$(bin_path_for "$version")"
  if [ -x "$dest" ]; then
    got="$({ "$dest" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1; } || true)"
    [ "$got" = "$(ver_num "$version")" ] && { log "二进制已就绪：$dest ($got)"; return; }
  fi

  tmp_dir="$(mktemp -d)"
  archive="${tmp_dir}/dragonfly.tar.gz"
  url="${GH_BASE}/${version}/dragonfly-${arch}.tar.gz"
  log "下载 Dragonfly ${version} (${arch}) ..."
  download "$url" "$archive" || { rm -rf "$tmp_dir"; die "下载失败：${GH_PROXY}${url}"; }
  tar -xzf "$archive" -C "$tmp_dir"
  binary="$(find "$tmp_dir" -maxdepth 2 -type f -name "dragonfly-${arch}" | head -n1 || true)"
  [ -n "$binary" ] || { rm -rf "$tmp_dir"; die "压缩包中未找到 dragonfly-${arch}。"; }
  got="$({ "$binary" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1; } || true)"
  [ "$got" = "$(ver_num "$version")" ] || { rm -rf "$tmp_dir"; die "版本校验不符：期望 $(ver_num "$version")，实际 ${got:-未知}。"; }
  install -m 0755 "$binary" "$dest"
  rm -rf "$tmp_dir"
  ok "二进制就位：$dest ($got)"
}

link_binary() {
  ln -sfn "$(bin_path_for "$1")" "$DF_BIN_LINK"
}

write_password() {
  local value
  value="$(password)"
  [ -n "$value" ] || value="$(gen_password)"
  ( umask 077; printf '%s' "$value" > "$DF_PASSWORD_FILE" )
  chown root:"$DF_GROUP" "$DF_PASSWORD_FILE"
  chmod 640 "$DF_PASSWORD_FILE"
}

write_config() {
  local value tmp
  value="$(password)"
  [ -n "$value" ] || die "密码文件为空：$DF_PASSWORD_FILE"
  tmp="$(mktemp)"
  cat > "$tmp" <<EOF
# 由 dragonfly.sh 生成。文件含认证口令，禁止放宽权限或提交到仓库。
--bind=${DF_BIND}
--port=${DF_PORT}
--requirepass=${value}
--maxmemory=${DF_MAXMEMORY_MB}mb
--cache_mode=true
--dir=${DF_HOME}
--dbfilename=dump
--proactor_threads=${DF_PROACTOR_THREADS}
EOF
  install -m 640 -o root -g "$DF_GROUP" "$tmp" "$DF_CONFIG"
  rm -f "$tmp"
}

write_unit() {
  cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=Dragonfly Redis-compatible cache for maccms
Documentation=https://www.dragonflydb.io/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${DF_USER}
Group=${DF_GROUP}
ExecStart=${DF_BIN_LINK} --flagfile=${DF_CONFIG} --logtostderr
Restart=on-failure
RestartSec=2
WorkingDirectory=${DF_HOME}
LimitNOFILE=65535
LimitMEMLOCK=infinity
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=${DF_HOME}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

# 依次优先使用 redis-cli、Python socket，最后回退到 bash /dev/tcp。
health() {
  local value output
  value="$(password)"
  [ -n "$value" ] || return 1
  if have redis-cli; then
    output="$(REDISCLI_AUTH="$value" redis-cli -h 127.0.0.1 -p "$DF_PORT" --no-auth-warning ping 2>/dev/null || true)"
    [ "$output" = "PONG" ]
    return
  fi
  if have python3; then
    python3 - "$DF_PORT" "$value" <<'PY' >/dev/null 2>&1
import socket
import sys

port = int(sys.argv[1])
password = sys.argv[2]
s = socket.create_connection(("127.0.0.1", port), 3)
s.settimeout(3)

def command(*parts):
    payload = f"*{len(parts)}\r\n".encode()
    for part in parts:
        raw = part.encode()
        payload += f"${len(raw)}\r\n".encode() + raw + b"\r\n"
    s.sendall(payload)
    return s.recv(4096)

assert command("AUTH", password).startswith(b"+OK")
assert command("PING").startswith(b"+PONG")
PY
    return
  fi
  output="$(timeout 3 bash -c '
    exec 3<>"/dev/tcp/127.0.0.1/$1" || exit 1
    printf "*2\r\n\$4\r\nAUTH\r\n\$%s\r\n%s\r\n*1\r\n\$4\r\nPING\r\n" "${#2}" "$2" >&3
    cat <&3
  ' _ "$DF_PORT" "$value" 2>/dev/null || true)"
  printf '%s' "$output" | grep -q PONG
}

wait_health() {
  local waited=0
  while [ "$waited" -lt "$HEALTH_TIMEOUT" ]; do
    health && return 0
    waited=$((waited + 1))
    sleep 1
  done
  return 1
}

print_connect_info() {
  echo
  ok "Dragonfly 健康，maccms 可按 Redis 方式连接："
  echo "    host     : ${DF_BIND}"
  echo "    port     : ${DF_PORT}"
  echo "    password : 读取 ${DF_PASSWORD_FILE}（不在终端回显）"
  echo "    memory   : ${DF_MAXMEMORY_MB} MiB"
  echo "    threads  : ${DF_PROACTOR_THREADS}"
}

configure_service() {
  resolve_resources
  ensure_user
  ensure_dirs
  write_password
  write_config
  write_unit
}

# ============================ 子命令 ============================
cmd_install() {
  need_root
  fetch_binary "$DF_VERSION"
  link_binary "$DF_VERSION"
  configure_service
  log "资源自适应：$(total_memory_mb) MiB 内存 / $(cpu_count) CPU -> ${DF_MAXMEMORY_MB} MiB 缓存 / ${DF_PROACTOR_THREADS} 线程"
  systemctl enable "$SERVICE_NAME" >/dev/null
  systemctl restart "$SERVICE_NAME"
  if wait_health; then
    print_connect_info
  else
    journalctl -u "$SERVICE_NAME" --no-pager -n 40 || true
    die "服务启动后健康检查未通过。"
  fi
}

cmd_upgrade() {
  need_root
  [ -f "$SYSTEMD_UNIT" ] || die "未检测到服务，请先运行 install。"
  local old_version old_target
  old_version="$(installed_version)"
  if [ "$old_version" = "$(ver_num "$DF_VERSION")" ]; then
    ok "已是目标版本 $old_version，无需升级。"
    return
  fi
  [ -n "$old_version" ] || die "无法识别当前 Dragonfly 版本。"
  old_target="$(readlink -f "$DF_BIN_LINK")"
  fetch_binary "$DF_VERSION"
  link_binary "$DF_VERSION"
  systemctl restart "$SERVICE_NAME"
  if wait_health; then
    ok "升级完成：$old_version -> $(installed_version)"
    return
  fi
  warn "新版本健康检查失败，回滚到 $old_version。"
  ln -sfn "$old_target" "$DF_BIN_LINK"
  systemctl restart "$SERVICE_NAME" || true
  wait_health || warn "回滚后仍未恢复，请检查 journalctl -u ${SERVICE_NAME}。"
  die "升级失败，已执行二进制回滚。"
}

cmd_status() {
  local current_version
  resolve_resources
  current_version="$(installed_version)"
  echo "================ Dragonfly 状态 ================"
  printf '  目标版本          : %s\n' "$(ver_num "$DF_VERSION")"
  printf '  已装版本          : %s\n' "${current_version:-未安装}"
  if [ -f "$SYSTEMD_UNIT" ]; then
    printf '  systemd           : %s / %s\n' "$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)" "$(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null || true)"
  else
    printf '  systemd           : 未安装\n'
  fi
  printf '  健康检查          : %s\n' "$(health && echo PONG || echo FAILED)"
  printf '  自动/覆盖内存     : %s MiB\n' "$DF_MAXMEMORY_MB"
  printf '  自动/覆盖线程     : %s\n' "$DF_PROACTOR_THREADS"
  printf '  认证口令文件      : %s\n' "$DF_PASSWORD_FILE"
  echo "=================================================="
}

cmd_uninstall() {
  need_root
  local purge=0
  [ "${1:-}" = "--purge" ] && purge=1
  systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$SYSTEMD_UNIT" "$DF_BIN_LINK"
  systemctl daemon-reload
  rm -rf "$DF_BIN_DIR"
  if [ "$purge" = "1" ]; then
    warn "--purge：删除缓存数据与配置 $DF_HOME $DF_ETC_DIR"
    rm -rf "$DF_HOME" "$DF_ETC_DIR"
  else
    log "服务与二进制已卸载；数据和配置仍保留在 $DF_HOME / $DF_ETC_DIR。"
  fi
  ok "卸载完成。"
}

usage() {
  awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
}

main() {
  local command="${1:-}"
  shift || true
  case "$command" in
    install) cmd_install "$@" ;;
    upgrade) cmd_upgrade "$@" ;;
    status) cmd_status "$@" ;;
    uninstall) cmd_uninstall "$@" ;;
    ""|help|-h|--help) usage ;;
    *) die "未知命令：$command（用 help 看用法）" ;;
  esac
}

main "$@"
