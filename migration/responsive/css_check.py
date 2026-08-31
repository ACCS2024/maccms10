import re, sys, os

css = open(sys.argv[1], encoding='utf-8').read()

# 1) 括号配平
o, c = css.count('{'), css.count('}')
print('  括号: { %d / } %d  %s' % (o, c, '配平' if o == c else '★不配平'))

# 2) 所有规则必须在 @media 里（保证桌面端零影响）
stripped = re.sub(r'/\*.*?\*/', '', css, flags=re.S)
depth = 0
top_level_rules = []
i = 0
buf = ''
while i < len(stripped):
    ch = stripped[i]
    if ch == '{':
        if depth == 0:
            sel = buf.strip()
            if not sel.startswith('@'):
                top_level_rules.append(sel[:60])
        depth += 1
        buf = ''
    elif ch == '}':
        depth -= 1
        buf = ''
    else:
        buf += ch
    i += 1
print('  顶层(非 @media)规则: %d  %s' % (len(top_level_rules),
      '✓ 全部在 @media 内，桌面端零影响' if not top_level_rules else '★ ' + str(top_level_rules)))

# 3) 我覆盖的类名，在主题 CSS 或渲染后的 HTML 里是否真实存在
classes = set()
for m in re.finditer(r'\.([a-zA-Z][a-zA-Z0-9_-]*)', re.sub(r'/\*.*?\*/', '', css, flags=re.S)):
    classes.add(m.group(1))
classes -= {'css', 'html', 'js'}

haystack = ''
for p in sys.argv[2:]:
    if os.path.isfile(p):
        haystack += open(p, encoding='utf-8', errors='replace').read()

missing = sorted(c for c in classes if ('.' + c) not in haystack and ('class="' + c) not in haystack
                 and ('%s"' % c) not in haystack and c not in haystack)
present = len(classes) - len(missing)
print('  覆盖的类名: %d 个，源文件/页面里存在 %d 个' % (len(classes), present))
if missing:
    print('  未匹配到(可能是我多写的，无害但无效): %s' % ', '.join(missing))
