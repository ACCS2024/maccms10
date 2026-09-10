#!/usr/bin/env python3
"""Real member/admin sessions against the disposable HTTP fixture only."""
import http.cookiejar
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1].rstrip("/")
MYSQL = shlex.split(os.environ["MAC_MYSQL"])
checks = 0


def db(sql):
    return subprocess.check_output(MYSQL + ["-N", "-e", sql], text=True, timeout=15).strip()


def verify(ok, message):
    global checks
    if not ok:
        raise RuntimeError(message)
    checks += 1


def client():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def fetch(opener, path, data=None, token=None):
    headers = {"X-Requested-With": "XMLHttpRequest"}
    if token:
        headers["X-CSRF-Token"] = token
    request = urllib.request.Request(BASE + path, None if data is None else urllib.parse.urlencode(data).encode(), headers)
    try:
        response = opener.open(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    body = response.read().decode("utf-8")
    verify(response.status < 500 and "<title>系统发生错误" not in body, "HTTP request returned an application error: " + path)
    return response.status, body


def api(opener, path, data=None, token=None):
    status, body = fetch(opener, path, data, token)
    verify(status == 200, "API request did not return 200: " + path)
    return json.loads(body)


def originals():
    return db("SELECT plog_id,user_id,plog_type,plog_points,plog_time,plog_remarks FROM mac_plog ORDER BY plog_id")


verify(db("SELECT DATABASE()") == "maccms_audit_http", "A dedicated HTTP fixture database is required")
verify(db("SELECT plog_remarks FROM mac_plog WHERE plog_id=1 AND user_id=1") == "CI fixture recharge", "Ledger fixture missing")
before = originals()
balance = db("SELECT user_points FROM mac_user WHERE user_id=1")
hidden = db("SELECT plog_user_hidden FROM mac_plog WHERE plog_id=1")
verify(hidden == "0", "Start with an unhidden fixture record")
member, admin, guest = client(), client(), client()
try:
    verify(api(guest, "/api.php/user/get_plog")["code"] == 1401, "Guest accessed a member ledger")
    login = api(member, "/index.php/user/login", {"user_name": "CI Smoke User", "user_pwd": "fixture-password"})
    verify(login["code"] == 1, "Real member login failed")
    rows = api(member, "/api.php/user/get_plog")["info"]["list"]
    verify(any(int(row["plog_id"]) == 1 for row in rows), "Authenticated ledger omitted its nonempty fixture")
    _, page = fetch(member, "/index.php/user/plog")
    verify("data-mac-user-plog" in page and "string_plog_retention_note" in page, "Member ledger template did not render")
    fetch(admin, "/madmin_ci.php/index/login")
    verify(api(admin, "/madmin_ci.php/index/login", {"admin_name": "admin", "admin_pwd": "admin888"})["code"] == 1, "Real admin login failed")
    _, page = fetch(admin, "/madmin_ci.php/plog/index")
    verify("CI fixture recharge" in page and "CI Smoke User" in page, "Admin ledger did not render its real row")
    token = re.search(r'mac-admin-csrf" content="([a-f0-9]{32})"', page)
    verify(token is not None, "Admin session CSRF token missing")
    verify(api(admin, "/madmin_ci.php/plog/del", {"ids": "1"}, token.group(1))["code"] != 1, "Admin erased the ledger")
    verify(api(member, "/api.php/user/del_plog?ids=1")["code"] != 1 and originals() == before, "GET mutated the ledger")
    verify(api(member, "/api.php/user/del_plog", {"ids": "1"})["code"] == 1, "Authenticated API hide failed")
    verify(db("SELECT plog_user_hidden FROM mac_plog WHERE plog_id=1") == "1", "Hide was not persisted")
    rows = api(member, "/api.php/user/get_plog")["info"]["list"]
    verify(all(int(row["plog_id"]) != 1 for row in rows), "API returned hidden rows")
    _, page = fetch(admin, "/madmin_ci.php/plog/index")
    verify("CI fixture recharge" in page and "CI Smoke User" in page, "Admin lost a member-hidden ledger row")
    verify(originals() == before and db("SELECT user_points FROM mac_user WHERE user_id=1") == balance, "HTTP actions changed financial fields or balance")
    print(f"Ledger HTTP: {checks} checks passed with real member/admin sessions.")
finally:
    db("UPDATE mac_plog SET plog_user_hidden=0 WHERE plog_id=1 AND user_id=1 AND plog_remarks='CI fixture recharge'")
