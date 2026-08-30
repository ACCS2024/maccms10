#!/usr/bin/env bash
# =============================================================================
# 番号站群 增量同步:生产机 178.107.181.34 -> 新机 85.149.233.11
#
# 用途:迁移快照做完之后,生产还在持续入库。切 DNS 之前跑一次(可反复跑),
#      把这段时间新增/更新的 mac_vod / mac_art 增量搬过来,并补 Meilisearch 索引。
#
# 原理:按 vod_time / art_time 取增量。这两个站是采集/接收站,任何新增或更新都会
#      刷新该字段,所以时间戳水位线足够。为防边界丢单,水位线往回退 SAFETY 秒。
#      落库用 INSERT ... ON DUPLICATE KEY UPDATE,重复跑不会产生脏数据。
#
# 用法:  bash fanhao-delta-sync.sh          # 正常增量
#        bash fanhao-delta-sync.sh --full   # 忽略水位线,全量重取(慢,兜底用)
# =============================================================================
set -euo pipefail

SRC_HOST=178.107.181.34
SRC_PORT=37155
SRC_PASS="${FANHAO_SRC_PASS:?请先 export FANHAO_SRC_PASS=<生产机 root 口令>}"
SRC_DB=fhzy1_com
SRC_DBUSER=fhzy1_com
SRC_DBPASS="${FANHAO_SRC_DBPASS:?请先 export FANHAO_SRC_DBPASS=<源库口令>}"
SRC_DBPORT=5739

DST_DB=fhzy1_com
STAGE_DB=fhzy1_src
DST_ROOTPW="${FANHAO_DST_ROOTPW:?请先 export FANHAO_DST_ROOTPW=<新机 MySQL root 口令>}"

WORK=/home/migrate-fanhao-20260828/delta
SAFETY=900            # 水位线回退秒数
PHP=/www/server/php/83/bin/php
SITE=/home/wwwroot/fhzy1.com

FULL=0
[ "${1:-}" = "--full" ] && FULL=1

mkdir -p "$WORK"
DST() { mysql -uroot -p"$DST_ROOTPW" -N -B --init-command="SET SESSION group_concat_max_len=1048576" "$@"; }
say() { echo "[delta $(date '+%H:%M:%S')] $*"; }

remote() {
  SSHPASS="$SRC_PASS" sshpass -e ssh -o StrictHostKeyChecking=no -p "$SRC_PORT" "root@$SRC_HOST" "$@"
}

for spec in "vod:vod_time:vod_id" "art:art_time:art_id"; do
  TBL="mac_${spec%%:*}"; rest="${spec#*:}"; TCOL="${rest%%:*}"; PK="${rest##*:}"

  if [ "$FULL" = "1" ]; then
    WATER=0
  else
    WATER=$(DST -e "select coalesce(max(\`$TCOL\`),0) from \`$DST_DB\`.\`$TBL\`;" 2>/dev/null)
    WATER=$(( WATER > SAFETY ? WATER - SAFETY : 0 ))
  fi
  say "$TBL 水位线 = $WATER ($(date -d @"$WATER" '+%F %T' 2>/dev/null || echo epoch))"

  # 1) 源机导出增量
  say "$TBL 源机导出中…"
  remote "mysqldump -h127.0.0.1 -P$SRC_DBPORT -u$SRC_DBUSER -p$SRC_DBPASS \
      --single-transaction --skip-lock-tables --quick --hex-blob \
      --default-character-set=utf8mb4 --no-create-info --skip-add-locks --skip-disable-keys \
      --where='$TCOL >= $WATER' $SRC_DB $TBL 2>/dev/null | gzip -1" > "$WORK/$TBL.sql.gz"
  say "$TBL 导出 $(du -h "$WORK/$TBL.sql.gz" | cut -f1)"

  # 2) 灌进暂存库(先清空该表)
  DST -e "truncate table \`$STAGE_DB\`.\`$TBL\`;" 2>/dev/null
  zcat "$WORK/$TBL.sql.gz" | mysql -uroot -p"$DST_ROOTPW" --default-character-set=utf8mb4 "$STAGE_DB" 2>/dev/null
  N=$(DST -e "select count(*) from \`$STAGE_DB\`.\`$TBL\`;" 2>/dev/null)
  say "$TBL 暂存 $N 行"
  [ "$N" = "0" ] && { say "$TBL 无增量,跳过"; continue; }

  # 3) 列交集 upsert 进正式库
  COLS=$(DST -e "select group_concat(concat('\`',a.column_name,'\`') order by a.ordinal_position)
                 from information_schema.columns a
                 join information_schema.columns b
                   on b.table_schema='$DST_DB' and b.table_name=a.table_name and b.column_name=a.column_name
                 where a.table_schema='$STAGE_DB' and a.table_name='$TBL';" 2>/dev/null)
  UPD=$(DST -e "select group_concat(concat('\`',a.column_name,'\`=values(\`',a.column_name,'\`)') order by a.ordinal_position)
                 from information_schema.columns a
                 join information_schema.columns b
                   on b.table_schema='$DST_DB' and b.table_name=a.table_name and b.column_name=a.column_name
                 where a.table_schema='$STAGE_DB' and a.table_name='$TBL' and a.column_name<>'$PK';" 2>/dev/null)

  BEFORE=$(DST -e "select count(*) from \`$DST_DB\`.\`$TBL\`;" 2>/dev/null)
  mysql -uroot -p"$DST_ROOTPW" 2>/dev/null <<SQL
SET SESSION sql_mode='NO_ENGINE_SUBSTITUTION';
INSERT INTO \`$DST_DB\`.\`$TBL\` ($COLS) SELECT $COLS FROM \`$STAGE_DB\`.\`$TBL\`
ON DUPLICATE KEY UPDATE $UPD;
SQL
  AFTER=$(DST -e "select count(*) from \`$DST_DB\`.\`$TBL\`;" 2>/dev/null)
  say "$TBL upsert 完成:$BEFORE -> $AFTER (新增 $((AFTER-BEFORE)),其余为更新)"

  # 4) 增量补 Meilisearch(只补本次动过的 id)
  IDS=$(DST -e "select group_concat(\`$PK\`) from \`$STAGE_DB\`.\`$TBL\`;" 2>/dev/null)
  echo "$IDS" > "$WORK/$TBL.ids"
done

say "补 Meilisearch 索引…"
$PHP -d memory_limit=2G -r '
chdir("'"$SITE"'"); require "vendor/autoload.php";
$app = new \think\App(); $app->initialize(); $GLOBALS["config"] = config("maccms");
$work = "'"$WORK"'";
foreach ([["mac_vod","vod","afterVodSave"],["mac_art","art","afterArtSave"]] as [$tbl,$kind,$fn]) {
    $f = "$work/$tbl.ids";
    if (!is_file($f)) { continue; }
    $ids = array_filter(array_map("intval", explode(",", trim(file_get_contents($f)))));
    if (!$ids) { echo "  $tbl: 无\n"; continue; }
    $n = 0;
    foreach ($ids as $id) { \app\common\util\MeilisearchSync::$fn($id); $n++; }
    echo "  $tbl: 已同步 $n 条\n";
}
' 2>&1 | tail -5

say "完成。目标库现状:"
DST -e "select 'vod',count(*),from_unixtime(max(vod_time)) from \`$DST_DB\`.mac_vod
        union all select 'art',count(*),from_unixtime(max(art_time)) from \`$DST_DB\`.mac_art;" 2>/dev/null
