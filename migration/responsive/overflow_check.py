"""375px 视口下的静态溢出分析。

思路:把主题 CSS 里所有 width>375px 的固定宽规则列出来,再看 responsive.css 在
<=768px 断点里有没有覆盖同名选择器。没覆盖的 = 手机上会横向撑破的候选。
只看真实出现在渲染页面里的选择器,避免被主题里的死样式干扰。
"""
import re, sys

VIEWPORT = 375
theme_css = open(sys.argv[1], encoding='utf-8', errors='replace').read()
resp_css  = open(sys.argv[2], encoding='utf-8', errors='replace').read()
pages     = open(sys.argv[3], encoding='utf-8', errors='replace').read()

strip = lambda s: re.sub(r'/\*.*?\*/', '', s, flags=re.S)

# ① responsive.css 在 <=1200/992/768/480 断点里覆盖了哪些选择器
covered = set()
for m in re.finditer(r'@media[^{]*\{(.*?)\n\}', strip(resp_css), flags=re.S):
    for r in re.finditer(r'([^{}]+)\{([^}]*)\}', m.group(1)):
        for sel in r.group(1).split(','):
            sel = ' '.join(sel.split())
            if sel:
                covered.add(sel)
                # 末级类名也算覆盖(便于匹配 ".a .b" 与 ".b")
                last = sel.split()[-1]
                covered.add(last)

# ② 页面里真实出现的 class
present = set(re.findall(r'class="([^"]+)"', pages))
present_classes = set()
for c in present:
    present_classes.update(c.split())

# ③ 主题 CSS 里 width > 375 的规则
risky = []
for m in re.finditer(r'([^{}]+)\{([^}]*)\}', strip(theme_css)):
    sel_group, body = ' '.join(m.group(1).split()), m.group(2)
    if sel_group.startswith('@'):
        continue
    w = re.search(r'(?<![-a-zA-Z])width\s*:\s*(\d+)px', body)
    if not w or int(w.group(1)) <= VIEWPORT:
        continue
    for sel in sel_group.split(','):
        sel = ' '.join(sel.split())
        if not sel:
            continue
        last = sel.split()[-1]
        # 该选择器涉及的类名是否真的出现在页面上
        cls = set(re.findall(r'\.([a-zA-Z][a-zA-Z0-9_-]*)', sel))
        if cls and not (cls & present_classes):
            continue          # 页面里根本没有 -> 死样式,不用管
        if sel in covered or last in covered:
            continue          # 已被 responsive.css 覆盖
        risky.append((sel, int(w.group(1))))

risky = sorted(set(risky), key=lambda x: -x[1])
print('  375px 视口下仍可能横向撑破的选择器: %d 条' % len(risky))
for sel, w in risky[:25]:
    print('    %-52s %dpx' % (sel[:52], w))
if not risky:
    print('    (无 —— 页面上出现的固定宽元素都已被覆盖)')
