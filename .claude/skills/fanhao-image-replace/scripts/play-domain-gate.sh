#!/usr/bin/env bash
# 安全闸:每个迁移桶各抽 N 条,验「换域名后仍返回同一份 m3u8」
Q="mysql -uroot -p5f6448cd1dd23be0 fhzy1_com -N -B"
N=${1:-4}
pass=0; fail=0

check_bucket() {  # $1=当前域名 $2=目标域名 $3=路径月正则(如 20260[78])
  echo "── $1 -> $2   (路径月 $3) ──"
  $Q -e "select vod_play_url from mac_vod
         where vod_play_url like '%$1/%'
           and vod_play_url regexp '/$3[0-9][0-9]/'
         order by rand() limit $N;" 2>/dev/null |
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    url="${line##*\$}"                       # 去掉 "HD$" 之类前缀
    new="${url//$1/$2}"
    ro=$(curl -s -o /tmp/_o -w "%{http_code}" --max-time 20 "$url" 2>/dev/null)
    rn=$(curl -s -o /tmp/_n -w "%{http_code}" --max-time 20 "$new" 2>/dev/null)
    mo=$(md5sum /tmp/_o 2>/dev/null | cut -c1-10); mn=$(md5sum /tmp/_n 2>/dev/null | cut -c1-10)
    so=$(stat -c%s /tmp/_o 2>/dev/null); sn=$(stat -c%s /tmp/_n 2>/dev/null)
    first=$(head -1 /tmp/_n 2>/dev/null | cut -c1-8)
    if [ "$rn" = "200" ] && [ "$mo" = "$mn" ] && [ "$first" = "#EXTM3U" ]; then
      v="✓同图"
    else
      v="✗不一致"
    fi
    printf "    %-46s 旧 %s/%sB  新 %s/%sB  %s\n" "$(echo "$url" | sed "s#https://[^/]*##" | cut -c1-44)" \
           "$ro" "$so" "$rn" "$sn" "$v"
  done
}

check_bucket "2605.fhbbff.com" "2607.fhbbff.com" "20260[78]"
check_bucket "2604.fhbbff.com" "2605.fhbbff.com" "202605"
check_bucket "2605.fhbbff.com" "2609.fhbbff.com" "202609"
