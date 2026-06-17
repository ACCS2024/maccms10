#!/usr/bin/env bash
#
# Meilisearch 一键部署 / 升级检测 / 老数据迁移脚本（裸机二进制 + systemd）
# 为 maccms10 配套。解决「Meilisearch 被动乱升级 + 升级后 data.ms 版本不兼容拒绝启动」的问题。
#
# 核心思路：
#   1) 版本锁死——只装 $MEILI_VERSION 指定的版本，systemd 托管，绝不自动升级。
#      以后想升级，永远只改顶部 MEILI_VERSION 这一个变量，再跑 `upgrade`。
#   2) 升级检测——比对「正在跑的版本 / 已装二进制版本」与「目标版本」，一致则空转不动。
#   3) 老数据迁移——升级时走官方路径：旧版导出 dump → 老 data.ms 挪走 → 新版 --import-dump
#      导入到全新 data.ms → 起服务校验版本。任何一步失败自动回滚到旧版本+旧数据。
#
# 用法：
#   sudo bash meilisearch.sh install     # 全新安装（生成 master key，起服务）
#   sudo bash meilisearch.sh status      # 看已装/在跑/目标版本、健康、文档数、后台填什么
#   sudo bash meilisearch.sh upgrade     # 检测版本差异，需要则 dump→迁移→导入新版
#   sudo bash meilisearch.sh dump        # 手动备份一次（导出 dump 到 dump 目录）
#   sudo bash meilisearch.sh rollback    # 回滚到上一版本（用升级时留下的二进制+数据备份）
#   sudo bash meilisearch.sh uninstall   # 卸载（保留数据，除非加 --purge）
#
# 关键变量都可用环境变量覆盖，例如：
#   sudo MEILI_VERSION=v1.46.1 bash meilisearch.sh upgrade
#   sudo GH_PROXY=https://ghproxy.net/ bash meilisearch.sh install   # 国内加速
#
set -euo pipefail

# ============================ 可配置变量 ============================
# 目标版本：升级永远只改这一个（取值见 https://github.com/meilisearch/meilisearch/releases）
MEILI_VERSION="${MEILI_VERSION:-v1.47.0}"

# 监听地址：默认只听本机，maccms 与 Meili 同机时最安全（不暴露公网）。
# 如需跨机访问改 0.0.0.0，并务必配合防火墙 + master key。
MEILI_BIND="${MEILI_BIND:-127.0.0.1}"
MEILI_PORT="${MEILI_PORT:-7700}"
MEILI_ENV="${MEILI_ENV:-production}"          # production 时强制要求 master key

# 运行账号与路径
MEILI_USER="${MEILI_USER:-meilisearch}"
MEILI_GROUP="${MEILI_GROUP:-meilisearch}"
MEILI_HOME="${MEILI_HOME:-/var/lib/meilisearch}"
MEILI_DB="${MEILI_DB:-${MEILI_HOME}/data.ms}"
MEILI_DUMP_DIR="${MEILI_DUMP_DIR:-${MEILI_HOME}/dumps}"
MEILI_ETC_DIR="${MEILI_ETC_DIR:-/etc/meilisearch}"
MEILI_ENV_FILE="${MEILI_ENV_FILE:-${MEILI_ETC_DIR}/meilisearch.env}"  # systemd EnvironmentFile（含 master key，权限 600）
MEILI_BIN_DIR="${MEILI_BIN_DIR:-/opt/meilisearch/bin}"               # 版本化二进制（便于回滚）
MEILI_BIN_LINK="${MEILI_BIN_LINK:-/usr/local/bin/meilisearch}"       # 指向当前版本的软链

# systemd
SERVICE_NAME="${SERVICE_NAME:-meilisearch}"
SYSTEMD_UNIT="/etc/systemd/system/${SERVICE_NAME}.service"

# 下载源（国内可设 GH_PROXY 前缀，如 https://ghproxy.net/ 或 https://mirror.ghproxy.com/）
GH_BASE="${GH_BASE:-https://github.com/meilisearch/meilisearch/releases/download}"
GH_PROXY="${GH_PROXY:-}"

# 超时（秒）
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-60}"      # 普通启动等待健康
DUMP_TIMEOUT="${DUMP_TIMEOUT:-1800}"        # 等待 dump 任务完成（大库可调大）
IMPORT_TIMEOUT="${IMPORT_TIMEOUT:-3600}"    # 等待 --import-dump 导入完成（大库导入很慢）

# ============================ 基础工具 ============================
C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'; C_BLU=$'\033[36m'; C_RST=$'\033[0m'
log()  { printf '%s[meili]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
ok()   { printf '%s[ ok ]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$C_YLW" "$C_RST" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

need_root() {
  [ "$(id -u)" = "0" ] || die "需要 root 权限（systemd/写 /usr/local/bin/创建用户）。请用 sudo 运行。"
}

have() { command -v "$1" >/dev/null 2>&1; }

# 去掉版本号前缀 v，便于比较：v1.47.0 -> 1.47.0
ver_num() { printf '%s' "${1#v}"; }

# a == b ?
ver_eq() { [ "$(ver_num "$1")" = "$(ver_num "$2")" ]; }

# a < b ?（语义化版本比较）
ver_lt() {
  local a b
  a="$(ver_num "$1")"; b="$(ver_num "$2")"
  [ "$a" = "$b" ] && return 1
  [ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" = "$a" ]
}

arch_suffix() {
  local m; m="$(uname -m)"
  case "$m" in
    x86_64|amd64)            echo "amd64" ;;
    aarch64|arm64)           echo "aarch64" ;;
    riscv64)                 echo "riscv64" ;;
    *) die "不支持的 CPU 架构：$m（Meilisearch 官方仅提供 amd64/aarch64/riscv64 Linux 二进制）。" ;;
  esac
}

# 版本化二进制的落地路径。统一剥掉前导 v，使文件名与「meilisearch --version」(无 v)
# 和 tag(带 v) 两种来源都对得上，避免回滚软链指向错文件。
bin_path_for() { printf '%s/meilisearch-%s' "$MEILI_BIN_DIR" "$(ver_num "$1")"; }

# ============================ HTTP / API ============================
# 下载文件（带重试 + 可选 GH_PROXY 前缀）。download <url> <dest>
download() {
  local url="$1" dest="$2" final tries=0 max=4
  final="${GH_PROXY}${url}"
  while :; do
    tries=$((tries + 1))
    if have curl; then
      if curl -fL --connect-timeout 15 --retry 2 -o "$dest" "$final"; then return 0; fi
    elif have wget; then
      if wget -q -O "$dest" "$final"; then return 0; fi
    else
      die "未找到 curl 或 wget，无法下载。请先安装其一。"
    fi
    [ "$tries" -ge "$max" ] && return 1
    warn "下载失败，重试 ($tries/$max)：$final"
    sleep $((tries * 2))
  done
}

# 读取 env 文件里的 master key
master_key() {
  [ -f "$MEILI_ENV_FILE" ] || { echo ""; return; }
  sed -n 's/^MEILI_MASTER_KEY=//p' "$MEILI_ENV_FILE" | head -n1
}

base_url() { printf 'http://127.0.0.1:%s' "$MEILI_PORT"; }

# 调本机 Meili API。api <METHOD> <path> -> 把响应体打到 stdout，HTTP 码作为返回值经全局 API_HTTP_CODE 暴露
API_HTTP_CODE=0
api() {
  local method="$1" path="$2" key body
  key="$(master_key)"
  local auth=()
  [ -n "$key" ] && auth=(-H "Authorization: Bearer ${key}")
  body="$(curl -s -o /dev/null -w '%{http_code}' "${auth[@]}" -X "$method" "$(base_url)$path" 2>/dev/null || true)"
  API_HTTP_CODE="${body:-000}"
}

# 带响应体的 GET：api_get <path> -> stdout 为响应体，API_HTTP_CODE 为状态码
api_get() {
  local path="$1" key tmp code
  key="$(master_key)"
  tmp="$(mktemp)"
  local auth=()
  [ -n "$key" ] && auth=(-H "Authorization: Bearer ${key}")
  code="$(curl -s -o "$tmp" -w '%{http_code}' "${auth[@]}" "$(base_url)$path" 2>/dev/null || true)"
  API_HTTP_CODE="${code:-000}"
  cat "$tmp"; rm -f "$tmp"
}

# POST，返回响应体：api_post <path>
api_post() {
  local path="$1" key tmp code
  key="$(master_key)"
  tmp="$(mktemp)"
  local auth=()
  [ -n "$key" ] && auth=(-H "Authorization: Bearer ${key}")
  code="$(curl -s -o "$tmp" -w '%{http_code}' "${auth[@]}" -X POST "$(base_url)$path" 2>/dev/null || true)"
  API_HTTP_CODE="${code:-000}"
  cat "$tmp"; rm -f "$tmp"
}

# 极简 JSON 取值（不引 jq）：json_field <json> <key>
# 末尾 || true：字段缺失时 grep 退出非零，pipefail+set -e 会误杀脚本。
json_field() {
  { printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"?[^,\"}]*\"?" | head -n1 \
    | sed -E "s/\"$2\"[[:space:]]*:[[:space:]]*//; s/^\"//; s/\"$//"; } || true
}

# 在跑实例的版本（GET /version 的 pkgVersion）；不可达返回空
running_version() {
  local out
  out="$(api_get /version)"
  [ "$API_HTTP_CODE" = "200" ] || { echo ""; return; }
  json_field "$out" pkgVersion
}

# 已装二进制版本（软链所指）；未装返回空
installed_version() {
  [ -x "$MEILI_BIN_LINK" ] || { echo ""; return; }
  { "$MEILI_BIN_LINK" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1; } || true
}

# 等待 /health 变绿。wait_health <timeout_sec>
wait_health() {
  local timeout="${1:-$HEALTH_TIMEOUT}" i=0
  while [ "$i" -lt "$timeout" ]; do
    api GET /health
    [ "$API_HTTP_CODE" = "200" ] && return 0
    i=$((i + 1)); sleep 1
  done
  return 1
}

# ============================ 安装相关 ============================
gen_key() {
  if have openssl; then openssl rand -hex 24; else head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

ensure_user() {
  if ! id "$MEILI_USER" >/dev/null 2>&1; then
    log "创建系统用户 $MEILI_USER"
    if have useradd; then
      useradd --system --shell /usr/sbin/nologin --home-dir "$MEILI_HOME" --no-create-home "$MEILI_USER" 2>/dev/null \
        || useradd --system --home-dir "$MEILI_HOME" "$MEILI_USER"
    elif have adduser; then
      adduser -S -H -h "$MEILI_HOME" "$MEILI_USER" || true
    else
      die "无 useradd/adduser，无法创建用户 $MEILI_USER。"
    fi
  fi
}

ensure_dirs() {
  mkdir -p "$MEILI_HOME" "$MEILI_DUMP_DIR" "$MEILI_ETC_DIR" "$MEILI_BIN_DIR"
  chown -R "$MEILI_USER:$MEILI_GROUP" "$MEILI_HOME"
  chmod 750 "$MEILI_HOME"
}

# 写 EnvironmentFile（首次生成 master key；已存在则保留 key，只更新其它项）
write_env_file() {
  local key
  key="$(master_key)"
  if [ -z "$key" ]; then
    key="$(gen_key)"
    log "已生成新的 master key（请妥善保存，maccms 后台要用）"
  fi
  install -d -m 750 "$MEILI_ETC_DIR"
  # 子 shell 里收紧 umask，避免泄漏影响后续 unit 文件权限
  ( umask 077
    cat > "$MEILI_ENV_FILE" <<EOF
# Meilisearch 运行配置（由 meilisearch.sh 生成）。本文件含 master key，权限 600。
MEILI_ENV=${MEILI_ENV}
MEILI_HTTP_ADDR=${MEILI_BIND}:${MEILI_PORT}
MEILI_DB_PATH=${MEILI_DB}
MEILI_DUMP_DIR=${MEILI_DUMP_DIR}
MEILI_MASTER_KEY=${key}
MEILI_NO_ANALYTICS=true
EOF
  )
  chmod 600 "$MEILI_ENV_FILE"
  chown root:root "$MEILI_ENV_FILE"
}

write_unit() {
  cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=Meilisearch search engine (maccms)
Documentation=https://www.meilisearch.com/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${MEILI_USER}
Group=${MEILI_GROUP}
EnvironmentFile=${MEILI_ENV_FILE}
ExecStart=${MEILI_BIN_LINK}
Restart=on-failure
RestartSec=3
WorkingDirectory=${MEILI_HOME}

# 安全加固
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${MEILI_HOME}
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

# 下载并安装指定版本二进制到 $MEILI_BIN_DIR/meilisearch-<ver>；校验其自报版本与目标一致
fetch_binary() {
  local ver="$1" arch dest url tmp got
  arch="$(arch_suffix)"
  dest="$(bin_path_for "$ver")"
  if [ -x "$dest" ]; then
    got="$({ "$dest" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1; } || true)"
    if [ -n "$got" ] && ver_eq "$got" "$ver"; then
      log "二进制已就绪：$dest ($got)"; return 0
    fi
  fi
  url="${GH_BASE}/${ver}/meilisearch-linux-${arch}"
  tmp="$(mktemp)"
  log "下载 Meilisearch ${ver} (${arch}) ..."
  download "$url" "$tmp" || { rm -f "$tmp"; die "下载失败：${GH_PROXY}${url}（国内可设 GH_PROXY 加速）"; }
  chmod +x "$tmp"
  got="$({ "$tmp" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1; } || true)"
  [ -n "$got" ] || { rm -f "$tmp"; die "下载的文件无法执行/不是有效二进制。"; }
  ver_eq "$got" "$ver" || { rm -f "$tmp"; die "版本校验不符：期望 $(ver_num "$ver")，实际 $got。"; }
  mkdir -p "$MEILI_BIN_DIR"
  mv "$tmp" "$dest"; chmod 755 "$dest"
  ok "二进制就位：$dest ($got)"
}

# 软链当前版本
link_binary() {
  ln -sfn "$(bin_path_for "$1")" "$MEILI_BIN_LINK"
}

# 升级前把「当前在用的二进制」固化到版本化目录，保证回滚一定有旧版本可切。
# 对本脚本装的实例是无操作（本就在）；对外部已有实例则补存一份。
preserve_current_binary() {
  local cur_ver dest real
  cur_ver="$(installed_version)"
  [ -n "$cur_ver" ] || return 0
  dest="$(bin_path_for "$cur_ver")"
  [ -e "$dest" ] && return 0
  [ -e "$MEILI_BIN_LINK" ] || return 0
  real="$(readlink -f "$MEILI_BIN_LINK" 2>/dev/null || echo "$MEILI_BIN_LINK")"
  mkdir -p "$MEILI_BIN_DIR"
  if cp -p "$real" "$dest" 2>/dev/null; then chmod 755 "$dest" 2>/dev/null || true; fi
}

print_connect_info() {
  local key; key="$(master_key)"
  echo
  ok "Meilisearch 运行中。把下面信息填进 maccms 后台「Meilisearch」："
  echo "    主机 Host   : http://${MEILI_BIND}:${MEILI_PORT}"
  echo "    API 密钥 Key : ${key}"
  echo "    索引 index_uid : maccms_contents（默认，后台已预填）"
  echo "  填好后点「保存」→「一键初始化索引」→「全量重建」即可。"
  if [ "$MEILI_BIND" = "127.0.0.1" ]; then
    echo "  （当前仅监听本机；maccms 与 Meili 不同机时，请改 MEILI_BIND=0.0.0.0 重装并配防火墙。）"
  fi
}

# ============================ 子命令：install ============================
cmd_install() {
  need_root
  have curl || have wget || die "请先安装 curl 或 wget。"
  if [ -f "$SYSTEMD_UNIT" ] && systemctl is-active --quiet "$SERVICE_NAME"; then
    warn "检测到已安装并在运行的 Meilisearch。"
    warn "如需升级到 ${MEILI_VERSION} 请用：bash $0 upgrade（会自动迁移老数据）。"
    cmd_status
    exit 0
  fi
  log "全新安装 Meilisearch ${MEILI_VERSION}"
  ensure_user
  ensure_dirs
  fetch_binary "$MEILI_VERSION"
  link_binary "$MEILI_VERSION"
  write_env_file
  write_unit
  chown -R "$MEILI_USER:$MEILI_GROUP" "$MEILI_HOME"
  systemctl enable --now "$SERVICE_NAME"
  if wait_health "$HEALTH_TIMEOUT"; then
    ok "服务已启动，健康检查通过。版本：$(running_version)"
    print_connect_info
  else
    journalctl -u "$SERVICE_NAME" --no-pager -n 30 || true
    die "服务启动后健康检查未通过，请看上面日志。"
  fi
}

# ============================ 子命令：dump（备份）============================
# 触发一次 dump 并等待完成；结果路径写入全局 LAST_DUMP_FILE（进度日志正常打到 stdout）
LAST_DUMP_FILE=""
do_dump() {
  LAST_DUMP_FILE=""
  api GET /health
  [ "$API_HTTP_CODE" = "200" ] || die "Meilisearch 未在运行，无法导出 dump。先 systemctl start ${SERVICE_NAME}。"
  local resp uid status i=0 newest
  resp="$(api_post /dumps)"
  [ "$API_HTTP_CODE" = "202" ] || [ "$API_HTTP_CODE" = "200" ] || die "触发 dump 失败（HTTP $API_HTTP_CODE）：$resp"
  uid="$(json_field "$resp" taskUid)"
  [ -n "$uid" ] || uid="$(json_field "$resp" uid)"
  log "dump 任务已提交 taskUid=$uid，等待完成（最多 ${DUMP_TIMEOUT}s）..."
  while [ "$i" -lt "$DUMP_TIMEOUT" ]; do
    resp="$(api_get "/tasks/$uid")"
    status="$(json_field "$resp" status)"
    case "$status" in
      succeeded) break ;;
      failed|canceled) die "dump 任务 $status：$resp" ;;
    esac
    i=$((i + 1)); sleep 1
  done
  [ "$status" = "succeeded" ] || die "dump 任务超时未完成（${DUMP_TIMEOUT}s）。"
  # dump 文件名由 Meili 生成（时间戳，无空格），ls 取最新即可
  # shellcheck disable=SC2012
  newest="$(ls -1t "$MEILI_DUMP_DIR"/*.dump 2>/dev/null | head -n1 || true)"
  [ -n "$newest" ] || die "dump 任务成功但未在 $MEILI_DUMP_DIR 找到 .dump 文件。"
  LAST_DUMP_FILE="$newest"
  ok "dump 完成：$newest"
}

cmd_dump() {
  need_root
  do_dump
}

# ============================ 子命令：upgrade ============================
cmd_upgrade() {
  need_root
  [ -f "$SYSTEMD_UNIT" ] || die "未检测到已安装的 Meilisearch，请先 bash $0 install。"

  local target cur_run cur_bin cur
  target="$MEILI_VERSION"
  cur_run="$(running_version)"
  cur_bin="$(installed_version)"
  cur="${cur_run:-$cur_bin}"
  [ -n "$cur" ] || die "无法确定当前版本（服务没起且二进制不可执行）。可先 systemctl start ${SERVICE_NAME} 再试。"

  log "当前版本：${cur}（二进制 ${cur_bin:-未知} / 在跑 ${cur_run:-未跑}）  目标版本：$(ver_num "$target")"

  if ver_eq "$cur" "$target"; then
    ok "已是目标版本，无需升级（idempotent，空转退出）。"
    # 即便版本相同，也确保二进制就位与软链正确
    fetch_binary "$target"; link_binary "$target"
    return 0
  fi
  if ver_lt "$target" "$cur"; then
    warn "目标版本 $(ver_num "$target") 低于当前 ${cur}（降级）。Meilisearch 不保证 dump 能导入更老版本，可能失败。"
    warn "如确认要降级，5 秒后继续，Ctrl-C 取消..."
    sleep 5
  fi

  # 0) 固化当前二进制，保证回滚有旧版本可用
  preserve_current_binary

  # 1) 先把新版本二进制下好（失败就别动现网）
  fetch_binary "$target"

  # 2) 确保旧实例在跑，导出 dump
  if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    log "旧服务未运行，尝试启动以导出 dump ..."
    systemctl start "$SERVICE_NAME" || true
    wait_health "$HEALTH_TIMEOUT" || die "旧服务无法启动，无法安全导出 dump。若 data.ms 已损坏请用 rollback 或手工恢复。"
  fi
  local dump_file
  do_dump
  dump_file="$LAST_DUMP_FILE"
  [ -n "$dump_file" ] || die "未拿到 dump 文件路径，中止升级（现网未改动）。"

  # 3) 停服务，挪走老 data.ms（导入要求全新 db 目录）
  local ts old_bin_ver bak_db
  ts="$(date +%Y%m%d-%H%M%S)"
  old_bin_ver="${cur_bin:-$cur}"
  log "停止服务并备份老数据 ..."
  systemctl stop "$SERVICE_NAME"
  if [ -e "$MEILI_DB" ]; then
    bak_db="${MEILI_DB}.bak.${old_bin_ver}.${ts}"
    mv "$MEILI_DB" "$bak_db"
    log "老 data.ms 已备份到：$bak_db"
  fi

  # 4) 切到新版本二进制，导入 dump（在前台/后台跑一次导入实例，健康即停）
  link_binary "$target"
  log "用新版本导入 dump（最多 ${IMPORT_TIMEOUT}s，大库较慢）..."
  set -a
  # shellcheck source=/dev/null
  . "$MEILI_ENV_FILE"
  set +a
  "$MEILI_BIN_LINK" --import-dump "$dump_file" >/tmp/meili-import.log 2>&1 &
  local import_pid=$!
  local i=0 healthy=0
  while [ "$i" -lt "$IMPORT_TIMEOUT" ]; do
    if ! kill -0 "$import_pid" 2>/dev/null; then
      warn "导入进程提前退出，日志："; tail -n 30 /tmp/meili-import.log || true
      break
    fi
    api GET /health
    if [ "$API_HTTP_CODE" = "200" ]; then healthy=1; break; fi
    i=$((i + 1)); sleep 1
  done
  # 收掉这个临时导入实例
  if kill -0 "$import_pid" 2>/dev/null; then
    kill "$import_pid" 2>/dev/null || true
    wait "$import_pid" 2>/dev/null || true
  fi

  if [ "$healthy" != "1" ]; then
    warn "导入失败，开始回滚到 ${old_bin_ver} + 老数据 ..."
    rm -rf "$MEILI_DB" 2>/dev/null || true
    if [ -n "${bak_db:-}" ] && [ -e "${bak_db:-/nonexistent}" ]; then
      mv "$bak_db" "$MEILI_DB"
    fi
    link_binary "$old_bin_ver"
    chown -R "$MEILI_USER:$MEILI_GROUP" "$MEILI_HOME"
    systemctl start "$SERVICE_NAME" || true
    die "升级失败已回滚。dump 仍保留在 $dump_file，可排查后重试。导入日志 /tmp/meili-import.log。"
  fi

  # 5) 修正属主，启动正式服务校验
  chown -R "$MEILI_USER:$MEILI_GROUP" "$MEILI_HOME"
  systemctl start "$SERVICE_NAME"
  if wait_health "$HEALTH_TIMEOUT"; then
    local now; now="$(running_version)"
    if ver_eq "$now" "$target"; then
      ok "升级完成：${cur} → ${now}。老数据已迁移。备份保留：${bak_db:-无}，dump：$dump_file"
      print_connect_info
    else
      warn "服务起来了但版本是 $now（期望 $(ver_num "$target")），请检查。"
    fi
  else
    journalctl -u "$SERVICE_NAME" --no-pager -n 30 || true
    die "新版本服务启动后健康检查未通过，请看日志。可 bash $0 rollback 回滚。"
  fi
}

# ============================ 子命令：rollback ============================
cmd_rollback() {
  need_root
  local bak prev_ver
  # 备份名由本脚本生成（data.ms.bak.<ver>.<ts>，无空格），ls 取最新即可
  # shellcheck disable=SC2012
  bak="$(ls -1t "${MEILI_DB}".bak.* 2>/dev/null | head -n1 || true)"
  [ -n "$bak" ] || die "没找到可回滚的数据备份（${MEILI_DB}.bak.*）。"
  # 从备份名解析旧版本：data.ms.bak.<ver>.<ts>
  prev_ver="$(basename "$bak" | sed -E 's/^data\.ms\.bak\.([0-9]+\.[0-9]+\.[0-9]+)\..*/\1/')"
  if [ -z "$prev_ver" ] || [ ! -x "$(bin_path_for "v$prev_ver")" ]; then
    die "找到备份 $bak，但缺对应版本二进制 $(bin_path_for "v${prev_ver:-?}")，无法回滚。"
  fi
  warn "将回滚到 ${prev_ver}，用备份 $bak 覆盖当前数据。5 秒后继续，Ctrl-C 取消..."
  sleep 5
  systemctl stop "$SERVICE_NAME" || true
  rm -rf "$MEILI_DB"
  mv "$bak" "$MEILI_DB"
  link_binary "v$prev_ver"
  chown -R "$MEILI_USER:$MEILI_GROUP" "$MEILI_HOME"
  systemctl start "$SERVICE_NAME"
  if wait_health "$HEALTH_TIMEOUT"; then
    ok "已回滚到 $(running_version)"
  else
    die "回滚后健康检查未通过，请看 journalctl -u ${SERVICE_NAME}。"
  fi
}

# ============================ 子命令：status ============================
cmd_status() {
  local inst run target docs uid health_code
  inst="$(installed_version)"
  run="$(running_version)"
  target="$(ver_num "$MEILI_VERSION")"
  echo "================ Meilisearch 状态 ================"
  printf '  目标版本(脚本锁定): %s\n' "$target"
  printf '  已装二进制版本    : %s\n' "${inst:-未安装}"
  printf '  正在运行版本      : %s\n' "${run:-未运行}"
  if [ -f "$SYSTEMD_UNIT" ]; then
    printf '  systemd 服务      : %s\n' "$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo inactive)"
  else
    printf '  systemd 服务      : 未安装\n'
  fi
  api GET /health
  health_code="$API_HTTP_CODE"   # 先存住：下面 stats 调用会覆盖 API_HTTP_CODE
  printf '  /health           : HTTP %s\n' "$health_code"
  if [ "$health_code" = "200" ]; then
    uid="maccms_contents"
    docs="$(api_get "/indexes/${uid}/stats")"
    if [ "$API_HTTP_CODE" = "200" ]; then
      printf '  索引 %s 文档数: %s\n' "$uid" "$(json_field "$docs" numberOfDocuments)"
    else
      printf '  索引 %s          : 未建（装好后到后台点「一键初始化索引」）\n' "$uid"
    fi
  fi
  if [ -n "$run" ] && [ "$run" != "$target" ]; then
    warn "在跑版本与目标不一致 → 可运行：bash $0 upgrade（自动迁移老数据）"
  fi
  if [ "$health_code" = "200" ]; then print_connect_info; fi
  echo "=================================================="
}

# ============================ 子命令：uninstall ============================
cmd_uninstall() {
  need_root
  local purge=0
  [ "${1:-}" = "--purge" ] && purge=1
  systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$SYSTEMD_UNIT"; systemctl daemon-reload || true
  rm -f "$MEILI_BIN_LINK"
  rm -rf "$MEILI_BIN_DIR"
  if [ "$purge" = "1" ]; then
    warn "--purge：删除数据与配置 $MEILI_HOME $MEILI_ETC_DIR"
    rm -rf "$MEILI_HOME" "$MEILI_ETC_DIR"
  else
    log "已卸载二进制与服务；数据与配置保留在 $MEILI_HOME / $MEILI_ETC_DIR（加 --purge 才删）。"
  fi
  ok "卸载完成。"
}

# ============================ 入口 ============================
usage() {
  # 打印文件顶部的注释头（跳过 shebang，遇到第一行非注释即止），免维护行号
  awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
}

main() {
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    install)   cmd_install "$@" ;;
    upgrade)   cmd_upgrade "$@" ;;
    dump|backup) cmd_dump "$@" ;;
    rollback)  cmd_rollback "$@" ;;
    status)    cmd_status "$@" ;;
    uninstall) cmd_uninstall "$@" ;;
    ""|help|-h|--help) usage ;;
    *) die "未知命令：$cmd（用 help 看用法）" ;;
  esac
}

main "$@"
