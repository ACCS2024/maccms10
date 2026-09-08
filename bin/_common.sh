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

# ── vendor/ 自动加载完整性校验 + 自愈 ─────────────────────────────────────────
# 为什么需要:vendor/ 在 .gitignore 里,不随 git 走,是各机自行拼装的;而
# provision_code 用 rsync 整树同步,一台机器的坏 vendor 会原样传染到每台新机。
# 真实事故(2026-09 杏吧迁移):composer.lock 里有 topthink/think-view +
# think-template,但 vendor/composer/installed.json 与 autoload_psr4.php 都没有
# 它们 —— 包目录是手工塞进 vendor/topthink/ 的,自动加载器从没注册过。
# 表现是整站 500 "Driver [Think] not supported.",且 php -l 全绿、文件都在,
# 极难一眼看出。故在部署路径上强制校验。
verify_autoload() {
  local root="$1" php; php="$(php_bin)"

  if [ ! -f "$root/composer.lock" ]; then
    warn "无 composer.lock,跳过自动加载校验"
    return 0
  fi
  if [ ! -f "$root/vendor/autoload.php" ]; then
    warn "vendor/autoload.php 缺失 —— 需要 composer install"
    _repair_autoload "$root" || return 1
  fi

  local report
  report="$("$php" -r '
    $root = $argv[1];
    $lock = @json_decode(@file_get_contents("$root/composer.lock"), true);
    $instF = "$root/vendor/composer/installed.json";
    $inst = @json_decode(@file_get_contents($instF), true);
    if (!is_array($lock) || !is_array($inst)) { echo "UNREADABLE"; exit; }
    $have = [];
    foreach (($inst["packages"] ?? $inst) as $p) {
      if (isset($p["name"])) { $have[$p["name"]] = true; }
    }
    $miss = [];
    foreach (($lock["packages"] ?? []) as $p) {
      if (isset($p["name"]) && empty($have[$p["name"]])) { $miss[] = $p["name"]; }
    }
    echo $miss ? implode(",", $miss) : "OK";
  ' "$root" 2>/dev/null)"

  if [ "$report" = "UNREADABLE" ]; then
    warn "composer.lock / installed.json 读取失败,尝试重建"
    _repair_autoload "$root" || return 1
  elif [ "$report" != "OK" ] && [ -n "$report" ]; then
    warn "vendor 自动加载缺失包: $report"
    _repair_autoload "$root" || return 1
  fi

  # 仅比对清单还不够:清单对了但 psr-4 映射没生成也会 500。这里真正 new 一次
  # 类,把「能不能加载」这件事验到底。view 驱动是本项目实际栽过的那一个。
  local probe
  probe="$("$php" -r '
    $root = $argv[1];
    require "$root/vendor/autoload.php";
    $need = ["think\\view\\driver\\Think", "think\\App", "think\\Template"];
    $bad = [];
    foreach ($need as $c) { if (!class_exists($c)) { $bad[] = $c; } }
    echo $bad ? implode(",", $bad) : "OK";
  ' "$root" 2>/dev/null)"

  if [ "$probe" != "OK" ]; then
    if [ -z "$probe" ]; then
      warn "自动加载探针无法运行 —— vendor/autoload.php 本身已损坏"
    else
      warn "关键类无法自动加载: $probe"
    fi
    _repair_autoload "$root" || return 1
    probe="$("$php" -r '
      $root = $argv[1];
      require "$root/vendor/autoload.php";
      echo class_exists("think\\view\\driver\\Think") ? "OK" : "STILL_BROKEN";
    ' "$root" 2>/dev/null)"
    [ "$probe" = "OK" ] || die "vendor 自动加载修复失败。请在 $root 手动执行:
    composer install --no-dev --optimize-autoloader"
  fi

  log "vendor 自动加载完整 ✅"
}

# 用 composer 按 lock 重建 vendor;没有 composer 就明确报错,不静默放过
_repair_autoload() {
  local root="$1" composer=""
  for c in composer composer.phar /usr/local/bin/composer; do
    command -v "$c" >/dev/null 2>&1 && { composer="$c"; break; }
  done
  if [ -z "$composer" ]; then
    warn "未找到 composer,无法自动修复"
    return 1
  fi
  log "按 composer.lock 重建 vendor(composer install --no-dev)…"
  ( cd "$root" && COMPOSER_ALLOW_SUPERUSER=1 "$composer" install --no-dev --optimize-autoloader --no-interaction ) >&2 || {
    warn "composer install 失败"
    return 1
  }
  return 0
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
  verify_autoload "${MACCMS_DOCTOR_ROOT:-$PWD}" || warn "自动加载校验未通过"
}
