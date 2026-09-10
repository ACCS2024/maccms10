#!/usr/bin/env python3
"""Offline supply-chain audit. Never imports/includes code from the inspected tree."""
import argparse
import base64
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import unquote

DOMAINS = (
    'maccms.la', 'maccms.com', 'maccms.cn', 'maccms.ai', 'dplayerstatic.com',
    'jquecy.com', 'jsdclivr.com', 'clondflare.com', 'bytedauce.com', 'macoms.la',
    'bdustatic.com', 'jsdelivr.vip', 'ailyunoss.com', 'ailyun-oss.com', 'aqyaqua.com', 'zhw.sh',
    '110.nz', 'ntp.asia', 'ntporg.com', 'sbindns.com', 'plusedns.com', 'mirrors163.com',
    'linuxdistro.net', 'debianhacks.net', 'fedoraforums.net', 'ubuntucommands.com',
    '3snzh72om4.apifox.cn', 'node.blob.core.windows.net',
    'gadlkd1.com', 'gfewr.com', 'ztyfv.com', 'joymeet.top', 'bobolickp92.cc', 'realfake909.net',
    'firelategg.net', 'lucycally.me', 'moxymodiy.cc', '9688hopeeasy.cc', 'flysky55.me', 'goyppg06.com',
    'tutupytua.com', 'zybbzlast.com', 'bootcdn.net', 'bootcss.com', 'staticfile.org', 'staticfile.net',
    'polyfill.io', 'polyfill.com', 'polyfill-js.cn',
    'mycj.top', 'mycj.pro',  # Retired upstream cloud loaders, not attributed malware verdicts.
    'towoo.net',  # Hidden loader observed in this fork; not attributed to XLab's campaign.
)
OBSERVED_BLOCKED_HOSTS = {'211.162.103.35'}
OBSERVED_LOADER_URL = re.compile(r'(?<![\w.])211\.162\.103\.35/static/Device/learn\.js(?:[?#]|\b)', re.I)
OBSERVED_SHA256 = {
    '6ad4fa64e5979085b38af7995979cbe18d0c82f2bf6178b5db761666dc822c1a',
    '9e31b2d470f49e6eae4b1526f892581f9abf00ed12d34d920e63c4cbc030cb34',
    'f3648d0bc2daf2a4ac69bb05b6bc9330f342df4df1f117dd93eb50e2c2ef65f9',
}
BAD_MD5 = {'b06b9f13505eb49d6b3f4bddd64b12ce', 'eb03db7ac9f10af66a1e2b16185fcadc'}
BAD_MD5.update({
    '65ac2839ab2790b6df8e80022982a2c0', '5d6c33bf931699805206b00594de5e71',
    '663706d4f3948417d05c11bbfa6cdbc9', '85cdf5139f0a0a0f7e378bc2029d662b',
    '3bff298be46f8817862bce2ac0be3176', '6acb8bbcad3b8403f4567412cc6aa144',
    '946606977dd177347122867750244ae2', '92c630062f0fe207c628b95fade34b96',
    '563f5e605ebf1db8065fd41799e71bf9', '112e2eb2a57129ef175c3f64bccbac04',
    'cd36ec10f71b89dc259eb8825e668ae3', '6e14853a6ad5e752a516290bf586d700',
    'b5dfe88131fb1b3622a487df96be84e1', '79c492bfd8a35039249bacc6a31d7122',
    '2e7a42c9be6fc3840df867cb19c7afa5', 'a688afd342cee9feb74c61503fb0b895',
    '85f3d29a8fd59e00fec83743664fb2b5', 'fef497841554fff318b740dff7df3a49',
    'dfd1fbf0a98e0984da9516311ccc1f05', 'da594309691161f6e999984c26e1a10f',
    '18b699375c76328b433145bdac02ec49', 'd3b0b6496747ee77ab15e5f5d9583a67',
})
MARKERS = ('system_optimization_signature', '138ae887806f', 'xxSJRox', 'MfXKwV', 'ptbnNbK')
DOMAIN_RE = re.compile(r'(?<![\w.-])(?:[a-z0-9-]+\.)*(?:' + '|'.join(re.escape(x) for x in DOMAINS) + r')\.?(?![\w.-])', re.I)
# Exclude audit sources, documentation and fixtures, not production templates or dependencies.
SKIP_DIRS = {'.git', '.github', '.claude', 'node_modules', '__pycache__', 'docs', 'tests', '说明文档'}
SKIP_PREFIXES = ('tools/audit/', 'tools/security/', 'deploy/', 'migration/')
TEXT_EXTENSIONS = {'.php', '.phtml', '.phar', '.php3', '.php4', '.php5', '.php7', '.php8', '.inc',
                   '.js', '.mjs', '.cjs', '.html', '.htm', '.css', '.json', '.ini', '.conf', '.svg', '.py', '.sh', '.cgi', '.pl'}
TRUSTED_DETECTORS = {'security_check.php', 'tools/security/maccms_audit.py'}
DYNAMIC_PATHS = {'static/js/playerconfig.js', 'static_new/js/playerconfig.js', '.user.ini', '.env'}
COMPOSER_GENERATED = {'vendor/autoload.php'} | {'vendor/composer/' + name for name in (
    'autoload_classmap.php', 'autoload_files.php', 'autoload_namespaces.php', 'autoload_psr4.php',
    'autoload_real.php', 'autoload_static.php', 'installed.php', 'installed.json', 'platform_check.php',
)}
PHP_RE = re.compile(r'\.(?:php\d*|phtml|phar|inc)(?:\.|$)', re.I)
EXPORT_EXTENSIONS = {'.sql', '.txt', '.csv', '.json', '.jsonl', '.ndjson'}
MAX_BYTES = 32 * 1024 * 1024
LEGACY_FILES = {'application/extra/active.php', 'application/extra/system.php',
                'static/js/update.js', 'static_new/js/update.js',
                'application/data/update/database.php', 'application/admin/view/index/update.html',
                'application/admin/view/mycj', 'static_new/mycj',
                'template/m1938pc3_v2/help/static/js/js-sdk-pro.min.js',
                'template/m1938pc3_v2/js/js-sdk-pro.min.js'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def finding(path, rule, detail='', severity='block'):
    return {'path': str(path), 'rule': rule, 'detail': detail, 'severity': severity}


def uncomment(text, hash_comments=True):
    """Preserve quoted strings and their escapes while removing PHP/JS/CSS/HTML comments."""
    pattern = r'''("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|(/\*[\s\S]*?\*/|<!--[\s\S]*?-->|(?<!\\)//[^\n\r]*'''
    pattern += r'|\#[^\n\r]*)' if hash_comments else ')'
    return re.sub(pattern, lambda m: m.group(1) or '\n' * m.group(0).count('\n'), text)


def decoded_variants(text):
    """Bounded common encodings only; never eval JavaScript/PHP or unpack executable code."""
    seen = {text}
    pending = [text]
    for _ in range(3):
        following = []
        for value in pending:
            variants = [html.unescape(unquote(value)),
                        re.sub(r'\\(?:x([0-9a-f]{2})|u00([0-9a-f]{2}))',
                               lambda m: chr(int(m.group(1) or m.group(2), 16)), value, flags=re.I),
                        re.sub(r"(['\"])\s*(?:\.|\+)\s*(['\"])", '', value)]
            for token in re.findall(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])', value):
                if len(token) > 2 * 1024 * 1024:
                    continue
                try:
                    decoded = base64.b64decode(token + '=' * (-len(token) % 4), validate=True)
                    if decoded and sum(32 <= c <= 126 or c in (9, 10, 13) for c in decoded) / len(decoded) > .80:
                        variants.append(decoded.decode('utf-8', 'replace'))
                except ValueError:
                    pass
            for token in re.findall(r'(?<![a-f0-9])[a-f0-9]{24,}(?![a-f0-9])', value, re.I):
                if len(token) % 2 == 0 and len(token) <= 2 * 1024 * 1024:
                    variants.append(bytes.fromhex(token).decode('utf-8', 'replace'))
            for variant in variants:
                if variant not in seen and len(seen) < 1000:
                    seen.add(variant)
                    following.append(variant)
        pending = following
        if not pending:
            break
    return seen


def scan_content(relative, data, raw=False):
    results = []
    if hashlib.md5(data).hexdigest() in BAD_MD5:
        results.append(finding(relative, 'known-malware-hash'))
    if digest(data) in OBSERVED_SHA256:
        results.append(finding(relative, 'observed-hidden-loader-hash', 'Exact old asset identified by offline analysis of this fork'))
    text = data.decode('utf-8', 'replace')
    for marker in MARKERS:
        if marker in text:
            results.append(finding(relative, 'malware-marker', marker))
    hash_comments = any(x.lower() in {'.php', '.phtml', '.inc', '.py', '.sh', '.conf', '.ini'} for x in Path(relative).suffixes)
    source = text if raw else uncomment(text, hash_comments=hash_comments)
    # A protocol-relative URL in unquoted HTML is data, never a JS // comment.
    if any(x.lower() in {'.html', '.htm', '.svg', '.php'} for x in Path(relative).suffixes):
        html_source = re.sub(r'<!--[\s\S]*?-->|/\*[\s\S]*?\*/', '', text)
        html_urls = re.findall(r'\b(?:src|href|data-src)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', html_source, re.I)
        source += '\n' + '\n'.join(''.join(parts) for parts in html_urls)
    # Exempt only exact bare host literals in the named deny-list array, never URLs.
    if relative == 'application/common.php':
        def clean_deny_list(match):
            return re.sub(r"(['\"])([^'\"]+)\1", lambda m: "''" if m.group(2) in set(DOMAINS) | OBSERVED_BLOCKED_HOSTS else m.group(0), match.group(0))
        source = re.sub(r'\$blocked\s*=\s*\[[^;]*?\];', clean_deny_list, source)
    domains = set()
    for variant in decoded_variants(source):
        domains.update(x.group(0).lower().rstrip('.') for x in DOMAIN_RE.finditer(variant))
        if OBSERVED_LOADER_URL.search(variant) and not any(x['rule'] == 'observed-hidden-loader-url' for x in results):
            results.append(finding(relative, 'observed-hidden-loader-url', '211.162.103.35/static/Device/learn.js'))
        for marker in MARKERS:
            if marker in variant and marker not in text:
                results.append(finding(relative, 'encoded-malware-marker', marker))
    if domains:
        results.append(finding(relative, 'upstream-or-c2-domain', ', '.join(sorted(domains))))
    return results


def excluded(relative, profile):
    if profile != 'source':
        return False  # Even upload/docs/shell.php and tools/security/shell.php are audited.
    parts = Path(relative).parts
    if any(x in SKIP_DIRS for x in parts) or relative.startswith(SKIP_PREFIXES):
        return True
    if relative in TRUSTED_DETECTORS:
        return True  # Historical detector contains IOC patterns; not a production endpoint.
    if profile == 'source' and (parts[0].startswith('thinkphp_legacy_') or parts[0] in {'runtime', 'upload'}):
        return True
    return False


def paths_under(root, profile):
    errors = []
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=errors.append):
        relative_dir = Path(directory).relative_to(root)
        for name in list(dirs):
            path = Path(directory) / name
            relative = (relative_dir / name).as_posix()
            if path.is_symlink():
                if relative != 'app' or os.readlink(path) != 'application':
                    yield relative, path, 'symlink'
                dirs.remove(name)
            elif excluded(relative + '/', profile):
                dirs.remove(name)
        for name in names:
            path = Path(directory) / name
            relative = (relative_dir / name).as_posix()
            if excluded(relative, profile):
                continue
            if path.is_symlink():
                yield relative, path, 'symlink'
            elif path.is_file():
                yield relative, path, 'file'
            else:
                yield relative, path, 'special-file'
    for error in errors:
        path = Path(error.filename or root)
        relative = str(path.relative_to(root)) if is_inside(path, root) else 'unreadable-directory'
        yield relative, path, 'unreadable-directory'


def load_inventory(path):
    if not path:
        return {}
    value = json.loads(Path(path).read_text())
    if not isinstance(value, dict) or not isinstance(value.get('files'), dict):
        raise ValueError('Inventory must contain a files object with relative path -> SHA256')
    for name, sha in value['files'].items():
        if not isinstance(name, str) or Path(name).is_absolute() or '..' in Path(name).parts or not re.fullmatch(r'[a-f0-9]{64}', str(sha)):
            raise ValueError('Invalid inventory entry')
    return value['files']


def write_private_json(path, value):
    path = Path(path)
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        raise ValueError('Report/inventory path must not contain a symlink')
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, prefix='.audit-', delete=False) as handle:
        temporary = Path(handle.name)
        try:
            json.dump(value, handle, ensure_ascii=True, sort_keys=True, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()


def data_configs(root, parser, php):
    extra = root / 'application/extra'
    if extra.is_symlink() or (root / 'application').is_symlink():
        return []  # Already blocked by the tree walker; never traverse it for parsing.
    files = sorted(p for p in extra.glob('*.php') if p.is_file() and not p.is_symlink())
    if not files:
        return []
    if not parser:
        return [finding('application/extra', 'data-parser-required', 'Pass the trusted DataConfig.php with --data-parser')]
    parser = Path(parser).resolve(strict=True)
    # Load only the independently supplied trusted parser. Read inspected PHP as data.
    program = "require $argv[1]; $bad=[]; foreach(array_slice($argv,2) as $f){try{\\app\\common\\util\\DataConfig::read($f);}catch(\\Throwable $e){$bad[]=basename($f);}} echo json_encode($bad);"
    php_command = [php, '-n']
    probe = subprocess.run(php_command + ['-r', "exit(function_exists('token_get_all') ? 0 : 1);"],
                           capture_output=True, timeout=10)
    if probe.returncode != 0:
        php_command += ['-d', 'extension=tokenizer']
    result = subprocess.run(php_command + ['-r', program, str(parser), *map(str, files)], capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return [finding('application/extra', 'data-parser-failed', 'Trusted parser did not complete; no inspected config was executed')]
    try:
        invalid = json.loads(result.stdout)
        if not isinstance(invalid, list) or not all(isinstance(x, str) for x in invalid):
            raise ValueError()
    except ValueError:
        return [finding('application/extra', 'data-parser-failed', 'Invalid trusted parser response')]
    return [finding('application/extra/' + name, 'executable-or-invalid-data-config') for name in invalid]


def scan_export(path, relative):
    """Read SQL/text exports in overlapping chunks, including encoded stored payloads."""
    results, carry = [], b''
    sha, md5 = hashlib.sha256(), hashlib.md5()
    with path.open('rb') as handle:
        while True:
            chunk = handle.read(4 * 1024 * 1024)
            if not chunk:
                break
            sha.update(chunk)
            md5.update(chunk)
            results.extend(scan_content(relative, carry + chunk, raw=True))
            carry = chunk[-256 * 1024:]
    if md5.hexdigest() in BAD_MD5:
        results.append(finding(relative, 'known-malware-hash'))
    unique = {(x['path'], x['rule'], x['detail']): x for x in results}
    return list(unique.values()), sha.hexdigest()


def scan_tree(root, profile, baseline=None, approved=None, parser=None, php='php', verify=False, allow_missing=()):
    results, inventory = [], {}
    baseline, approved = baseline or {}, approved or {}
    results.extend(finding(name, 'retired-or-malware-path') for name in sorted(LEGACY_FILES) if os.path.lexists(root / name))
    for relative, path, kind in paths_under(root, profile):
        if kind != 'file':
            results.append(finding(relative, kind, 'Not followed or executed'))
            continue
        executable = bool(PHP_RE.search(path.name)) or (path.suffix == '' and relative == 'think')
        if profile == 'deployed' and (relative == 'install.php' or relative.startswith('thinkphp/') or relative.startswith('thinkphp_legacy_')):
            results.append(finding(relative, 'retired-deployment-path'))
        if profile == 'deployed' and relative.startswith('upload/') and executable:
            results.append(finding(relative, 'php-in-upload'))
        if profile == 'exported' or (profile == 'deployed' and path.suffix.lower() in EXPORT_EXTENSIONS):
            if profile == 'exported' and path.suffix.lower() in {'.gz', '.zip', '.xz', '.bz2', '.7z', '.rar'}:
                results.append(finding(relative, 'compressed-export-not-supported', 'Unpack with trusted tools into a separate offline directory before auditing'))
                continue
            found, sha = scan_export(path, relative)
            results.extend(found)
            inventory[relative] = sha
            if not executable:
                if verify and relative in baseline and relative not in COMPOSER_GENERATED and not relative.startswith('application/extra/') and approved.get(relative) != sha and baseline[relative] != sha:
                    results.append(finding(relative, 'deployed-source-mismatch'))
                continue
        interesting = executable or any(x.lower() in TEXT_EXTENSIONS for x in path.suffixes) or path.name in {'.user.ini', '.htaccess'}
        if not interesting:
            continue
        size = path.stat().st_size
        if size > MAX_BYTES:
            results.append(finding(relative, 'scan-size-limit', 'Code/config asset exceeds 32 MiB; inspect separately'))
            continue
        try:
            data = path.read_bytes()
        except OSError:
            results.append(finding(relative, 'unreadable-file'))
            continue
        sha = digest(data)
        inventory[relative] = sha
        if not (profile == 'deployed' and relative in TRUSTED_DETECTORS and baseline.get(relative) == sha):
            results.extend(scan_content(relative, data))
        if path.name in {'.user.ini', '.htaccess'}:
            directives = data.decode('utf-8', 'replace')
            if re.search(r'^\s*(?:php_value\s+)?auto_(?:prepend|append)_file\s*(?:=|\s)\s*[\w/"\'.]', directives, re.I | re.M):
                results.append(finding(relative, 'php-auto-include-directive'))
            if path.name == '.htaccess' and re.search(r'^\s*(?:SetHandler|AddHandler|AddType)\s+.*(?:php|cgi)', directives, re.I | re.M):
                results.append(finding(relative, 'executable-handler-override'))
        if profile == 'deployed' and executable and not relative.startswith(('application/extra/', 'runtime/')):
            entry_copy = '/' not in relative and sha == baseline.get('admin.php')
            approval = approved.get(relative) == sha
            if relative not in baseline and not entry_copy and not approval:
                results.append(finding(relative, 'unapproved-executable', 'Review code and add its SHA256 to a separate approval inventory'))
        if profile == 'deployed' and relative.startswith('vendor/') and relative in baseline and relative not in COMPOSER_GENERATED and sha != baseline[relative]:
            results.append(finding(relative, 'vendor-source-mismatch', 'Preserve evidence and rebuild vendor in a clean directory from the trusted lockfile'))
        elif verify and relative in baseline and relative not in DYNAMIC_PATHS | COMPOSER_GENERATED and not relative.startswith('application/extra/'):
            if sha != baseline[relative] and approved.get(relative) != sha:
                results.append(finding(relative, 'deployed-source-mismatch'))
    if profile != 'exported':
        results.extend(data_configs(root, parser, php))
    if verify:
        optional = set(allow_missing) | DYNAMIC_PATHS | {'admin.php', 'install.php', 'bin/deploy-155.sh'}
        for relative in sorted(set(baseline) - set(inventory) - optional):
            if not relative.startswith('application/extra/') and relative not in COMPOSER_GENERATED:
                results.append(finding(relative, 'missing-deployed-source'))
    if profile == 'source':
        for name in TRUSTED_DETECTORS:
            path = root / name
            if path.is_file() and not path.is_symlink():
                inventory[name] = digest(path.read_bytes())
    return results, inventory


def is_inside(path, root):
    return path == root or root in path.parents


def quarantine_known(root, destination):
    """Only retired paths with explicit names. Unknown/custom code is never moved."""
    raw_destination = Path(destination)
    if not raw_destination.is_absolute():
        raise ValueError('Quarantine destination must be absolute')
    destination = raw_destination.resolve()
    if is_inside(destination, root):
        raise ValueError('Quarantine must be outside the inspected webroot')
    if any(p.is_symlink() for p in [raw_destination, *raw_destination.parents]):
        raise ValueError('Quarantine destination contains a symlink')
    candidates = set(LEGACY_FILES)
    if (root / 'application/data/install/install.lock').is_file():
        candidates.add('install.php')
    candidates.update(p.name for p in root.iterdir() if p.name == 'thinkphp' or re.fullmatch(r'thinkphp_legacy_\d{8}', p.name))
    existing = [root / name for name in sorted(candidates) if os.path.lexists(root / name)]
    if not existing:
        return None
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.stat().st_mode & 0o077 or destination.stat().st_uid != os.geteuid():
        raise ValueError('Quarantine parent must be owned by the audit user and have mode 0700')
    batch = Path(tempfile.mkdtemp(prefix='maccms-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-', dir=destination))
    manifest = {'schema': 1, 'webroot': str(root), 'created_utc': datetime.now(timezone.utc).isoformat(), 'files': [], 'moves': []}
    manifest_path = batch / 'manifest.json'
    def persist():
        temporary = batch / '.manifest.tmp'
        temporary.write_text(json.dumps(manifest, ensure_ascii=True, indent=2) + '\n')
        temporary.chmod(0o600)
        os.replace(temporary, manifest_path)
    for source in existing:
        relative = source.relative_to(root)
        if source.is_symlink() or any((root / Path(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts))):
            raise ValueError('Known legacy path contains a symlink; manual evidence collection required')
        files = [source] if source.is_file() else list(source.rglob('*'))
        for path in files:
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise ValueError('Legacy directory contains a link/special file; manual evidence collection required')
            if path.is_file():
                metadata = path.stat()
                manifest['files'].append({'path': path.relative_to(root).as_posix(), 'sha256': digest(path.read_bytes()),
                    'size': metadata.st_size, 'mode': stat.S_IMODE(metadata.st_mode), 'uid': metadata.st_uid,
                    'gid': metadata.st_gid, 'mtime_ns': metadata.st_mtime_ns})
        target = batch / 'files' / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        move = {'path': relative.as_posix(), 'state': 'planned'}
        manifest['moves'].append(move)
        persist()
        shutil.move(str(source), str(target))
        move['state'] = 'moved'
        persist()
    return str(manifest_path)


def host_audit(root):
    """Inspect an offline host root or current host; never execute its utilities/services."""
    locations = ('etc/udev/rules.d', 'usr/lib/udev/rules.d', 'lib/udev/rules.d', 'etc/ld.so.preload',
                 'etc/nginx', 'www/server/nginx/conf', 'etc/cron.d', 'etc/cron.daily', 'etc/cron.hourly',
                 'etc/crontab', 'var/spool/cron', 'etc/systemd/system', 'usr/lib/systemd/system', 'lib/systemd/system',
                 'var/adm', 'usr/lib/nginx/modules', 'usr/local/nginx/modules', 'www/server/nginx/modules',
                 'usr/lib/libutilkeybd.so', 'usr/local/lib/libutilkeybd.so', 'lib/libutilkeybd.so')
    results, inventory, seen = [], {}, set()
    for relative in locations:
        base = root / relative
        if not os.path.lexists(base):
            continue
        if any((root / Path(*Path(relative).parts[:i])).is_symlink() for i in range(1, len(Path(relative).parts) + 1)):
            inventory[relative] = {'status': 'symlink-path-not-followed'}
            continue
        paths = [base] if not base.is_dir() else [base, *base.rglob('*')]
        for path in paths:
            rel = path.relative_to(root).as_posix()
            if rel in seen:
                continue
            seen.add(rel)
            if path.is_symlink():
                inventory[rel] = {'symlink': os.readlink(path)}
                continue
            if not path.is_file():
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    results.append(finding(rel, 'host-scan-size-limit'))
                    continue
                data = path.read_bytes()
            except OSError:
                results.append(finding(rel, 'host-unreadable-file'))
                continue
            inventory[rel] = {'sha256': digest(data), 'size': len(data)}
            results.extend(scan_content(rel, data, raw=True))
            if path.name in {'module.so', 'libutilkeybd.so', 'ring04h_office_bin'}:
                results.append(finding(rel, 'review-reported-payload-name', 'Reported payload name; compare hash and provenance offline'))
            text = '\n'.join(line for line in data.decode('utf-8', 'replace').splitlines() if not line.lstrip().startswith('#'))
            if relative == 'etc/ld.so.preload' and text.strip():
                results.append(finding(rel, 'review-ld-preload', 'Nonempty preload list; verify every library offline'))
            if re.search(r'\bload_module\s+[^;]+;', text):
                results.append(finding(rel, 'review-nginx-module', 'Verify configured module files against trusted package hashes'))
            if re.search(r'(?:RUN\s*\+?=|ExecStart\w*\s*=|^\s*(?:@\w+|[\d*/,-]+\s+[\d*/,-]+)).*(?:\b(?:curl|wget|base64)\b|/(?:tmp|dev/shm)/)', text, re.M):
                results.append(finding(rel, 'review-persistence-command', 'Downloader/decoder/temporary path in persistence configuration'))
    return results, inventory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='.')
    parser.add_argument('--profile', choices=('source', 'deployed', 'host', 'exported'), default='source')
    parser.add_argument('--baseline')
    parser.add_argument('--approved')
    parser.add_argument('--write-baseline')
    parser.add_argument('--data-parser')
    parser.add_argument('--php', default='php')
    parser.add_argument('--verify-source', action='store_true')
    parser.add_argument('--allow-missing', action='append', default=[], help='Reviewed intentionally absent PHP path (e.g. API-only deployment boundary)')
    parser.add_argument('--quarantine-known', metavar='ABSOLUTE_DIR')
    parser.add_argument('--json', metavar='REPORT_PATH')
    args = parser.parse_args(argv)
    try:
        root_argument = Path(args.root).absolute()
        if root_argument.is_symlink():
            raise ValueError('Root must not be a symlink')
        root = root_argument.resolve(strict=True)
        if not root.is_dir():
            raise ValueError('Root must be a directory')
        if args.profile == 'deployed' and not args.baseline:
            raise ValueError('Deployed audit requires an independently generated source baseline')
        if args.quarantine_known and args.profile != 'deployed':
            raise ValueError('Quarantine is only available with the deployed profile')
        baseline = load_inventory(args.baseline)
        approved = load_inventory(args.approved)
        if args.profile == 'deployed' and args.data_parser and is_inside(Path(args.data_parser).resolve(), root):
            raise ValueError('Deployed audit needs a trusted DataConfig parser outside the inspected webroot')
        for output in (args.json, args.write_baseline):
            if output and args.profile != 'host' and is_inside(Path(output).resolve(), root):
                raise ValueError('Write reports/baselines outside the inspected root')
        if args.write_baseline and args.profile != 'source':
            raise ValueError('Only a source audit may produce a baseline')
        quarantined_attack = [name for name in LEGACY_FILES if name.startswith('application/extra/') and os.path.lexists(root / name)]
        manifest = quarantine_known(root, args.quarantine_known) if args.quarantine_known else None
        if args.profile == 'host':
            findings, inventory = host_audit(root)
        else:
            findings, inventory = scan_tree(root, args.profile, baseline, approved, args.data_parser, args.php, args.verify_source, args.allow_missing)
        if manifest:
            findings.extend(finding(name, 'quarantined-malware-path', 'Preserved outside webroot; investigate host persistence before deployment') for name in quarantined_attack)
        report = {'schema': 1, 'root': str(root), 'profile': args.profile, 'ok': not findings,
                  'findings': findings, 'quarantine_manifest': manifest,
                  'limits': 'Known indicators and policy checks only; a compromised host must be rebuilt from trusted media.'}
        if args.profile == 'host':
            report['inventory'] = inventory
        if args.json:
            write_private_json(args.json, report)
        if args.write_baseline:
            if not findings:
                write_private_json(args.write_baseline, {'schema': 1, 'files': inventory})
        for issue in findings:
            print(json.dumps(issue, ensure_ascii=True))
        print('MACCMS audit: {} ({} findings)'.format('FAIL' if findings else 'PASS', len(findings)))
        if manifest:
            print('Evidence manifest: ' + manifest)
        return 1 if findings else 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('MACCMS audit failed: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
