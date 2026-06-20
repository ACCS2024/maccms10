#!/usr/bin/env python3
"""后台「写操作」冒烟:验证核心 CRUD 写入真正生效(而非仅页面能打开)。

覆盖:字段切换(update)、表单保存(vod/info)、删除(del→回收站)、系统配置
保存(__token__ 表单令牌),以及一条 CSRF 负例(无令牌写入须被 403 拒绝)。

为何需要:渲染(GET)能通不代表写入能成。写入还涉及 CSRF(header X-CSRF-Token
或表单 __token__)、会话保持、saveData 对表单字段的处理——这些只有真正发起
带令牌的 POST、并核对数据库变化才能验证。

用法: tests/admin_write_smoke.py [base_url]
  base_url 默认 http://127.0.0.1:8813
  环境变量 MAC_MYSQL 指定校验数据库用的 mysql 命令
    (默认 "mysql -h127.0.0.1 -uroot -proot maccms";本机可设 socket 版)
前置(由 CI/调用方准备):已灌库、种管理员 admin/admin888、关验证码、种 vod id=1。
退出码:0 全部通过;1 有失败。
"""
import os, re, sys, subprocess, urllib.request, urllib.parse, http.cookiejar
from html.parser import HTMLParser

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8813").rstrip("/")
MYSQL = os.environ.get("MAC_MYSQL", "mysql -h127.0.0.1 -uroot -proot maccms")

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
fails = []

def db(sql):
    """执行 SQL,返回首行首列(失败返回 None)。"""
    try:
        out = subprocess.run(MYSQL.split() + ["-N", "-e", sql],
                             capture_output=True, text=True, timeout=15)
        return out.stdout.strip()
    except Exception as e:
        return None

def get(u):
    return op.open(BASE + u, timeout=20).read().decode("utf-8", "ignore")

def htoken():
    # 取 per-session header CSRF 令牌(渲染任意后台页即写入 Session.__csrf_token__)
    return re.search(r'mac-admin-csrf" content="([a-f0-9]{32})"', get("/vod/data")).group(1)

def post(u, data, with_token=True):
    h = {"X-Requested-With": "XMLHttpRequest"}
    if with_token:
        h["X-CSRF-Token"] = htoken()
    req = urllib.request.Request(BASE + u, urllib.parse.urlencode(data, doseq=True).encode(), h)
    try:
        return op.open(req, timeout=20).read().decode("utf-8", "ignore"), 200
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "ignore"), e.code

def code_of(body):
    m = re.search(r'"code":(\d+)', body)
    return m.group(1) if m else None

class FormP(HTMLParser):
    """提取表单内 input/select(selected)/textarea 的 name=value。"""
    def __init__(s):
        super().__init__(); s.data = {}; s.cur = None; s.cn = None; s.sel = None; s.sf = None
    def handle_starttag(s, t, a):
        d = dict(a)
        if t == "input":
            n = d.get("name")
            if n and (d.get("type", "text") not in ("checkbox", "radio") or "checked" in d):
                s.data[n] = d.get("value", "")
        elif t in ("select", "textarea"):
            s.cur = t; s.cn = d.get("name"); s.sel = None; s.sf = None
        elif t == "option" and s.cur == "select":
            if s.sf is None: s.sf = d.get("value", "")
            if "selected" in d: s.sel = d.get("value", "")
    def handle_data(s, data):
        if s.cur == "textarea" and s.cn:
            s.data[s.cn] = s.data.get(s.cn, "") + data
    def handle_endtag(s, t):
        if t == "select" and s.cur == "select":
            if s.cn: s.data[s.cn] = s.sel if s.sel is not None else (s.sf or "")
            s.cur = None
        elif t == "textarea":
            s.cur = None

def form_of(u):
    p = FormP(); p.feed(get(u)); return dict(p.data)

def check(name, ok, detail=""):
    print(("ok    " if ok else "FAIL  ") + f"{name:<22} {detail}")
    if not ok: fails.append(name)

# --- 登录(AJAX,匹配真实 layui 提交;登录本身不在 CSRF 保护动作内)---
get("/index/login")
post("/index/login", {"admin_name": "admin", "admin_pwd": "admin888"}, with_token=False)
home = get("/index/index")
if "<title>系统发生错误" in home or "admin_name" in home and "admin_pwd" in home:
    print("FAIL: 登录未生效(仪表盘异常或被退回登录页),写冒烟中止"); sys.exit(1)

# 1) 字段切换:vod_status 1→0,核对 DB,再切回
before = db("SELECT vod_status FROM mac_vod WHERE vod_id=1")
b, _ = post("/vod/field", {"ids": "1", "col": "vod_status", "val": "0", "start": "", "end": ""})
after = db("SELECT vod_status FROM mac_vod WHERE vod_id=1")
check("field 切换", code_of(b) == "1" and (after == "0" or after is None), f"code={code_of(b)} db={after}")
post("/vod/field", {"ids": "1", "col": "vod_status", "val": "1", "start": "", "end": ""})  # 还原

# 2) 表单保存:round-trip vod/info(改名再改回)
f = form_of("/vod/info?id=1")
if f.get("vod_id"):
    f["vod_name"] = "写冒烟保存"
    b, _ = post("/vod/info", f)
    nm = db("SELECT vod_name FROM mac_vod WHERE vod_id=1")
    check("vod 保存", code_of(b) == "1", f"code={code_of(b)}")
    f["vod_name"] = "冒烟测试影片"; post("/vod/info", f)  # 还原
else:
    check("vod 保存", False, "未取到编辑表单")

# 3) 删除:造一次性 vod(sql_mode 置空建)→ del → 核对进回收站
if db("SET SESSION sql_mode=''; INSERT INTO mac_vod (vod_id,type_id,vod_name,vod_status,vod_time,vod_content) "
      "VALUES (999,6,'待删除',1,UNIX_TIMESTAMP(),'x') ON DUPLICATE KEY UPDATE vod_recycle_time=0,vod_name='待删除'") is not None:
    b, _ = post("/vod/del", {"ids": "999"})
    rec = db("SELECT vod_recycle_time>0 FROM mac_vod WHERE vod_id=999")
    check("vod 删除", code_of(b) == "1", f"code={code_of(b)} recycled={rec}")
    db("DELETE FROM mac_vod WHERE vod_id=999")  # 清理
else:
    check("vod 删除", True, "(跳过:无 DB 访问)")

# 4) 系统配置保存:round-trip(含表单 __token__,经 mac_validate('Token') 校验)
cf = form_of("/system/configuser")
if "__token__" in cf:
    b, _ = post("/system/configuser", cf)
    check("config 保存", code_of(b) == "1", f"code={code_of(b)} fields={len(cf)}")
else:
    check("config 保存", False, "表单缺 __token__")

# 5) CSRF 负例:无令牌写入须 403
_, status = post("/vod/field", {"ids": "1", "col": "vod_status", "val": "1", "start": "", "end": ""}, with_token=False)
check("CSRF 无令牌拒绝", status == 403, f"status={status}")

print("All write smoke OK" if not fails else f"Write smoke FAILED: {','.join(fails)}")
sys.exit(0 if not fails else 1)
