#!/usr/bin/env python3
"""Validate Apache against a fake document root; never request real repository secrets."""
import base64
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time


ENTRY = '''<?php
require '/source/vendor/autoload.php';
$request = \\think\\Request::__make(new \\think\\App('/tmp/apache-audit-app/'));
header('Content-Type: application/json');
echo json_encode(['entry' => basename(__FILE__), 'route' => $request->pathinfo(),
    'query' => $_GET, 'post' => $_POST, 'method' => $_SERVER['REQUEST_METHOD'],
    'uri' => $_SERVER['REQUEST_URI'], 'authorization' => $request->header('authorization'),
    'php' => PHP_VERSION], JSON_THROW_ON_ERROR);
'''
SCRIPT = "<?php echo 'UPLOAD_' . 'EXECUTED'; file_put_contents('/tmp/apache-audit-executed', 'fixture'); ?>"


def main():
    root = Path(__file__).resolve().parents[1]
    baseline = '--baseline' in sys.argv
    images = [arg for arg in sys.argv[1:] if arg != '--baseline'] or (['maccms-audit-production84:20260910'] if baseline else ['maccms-audit-apache83:20260910', 'maccms-audit-apache84:20260910'])
    with tempfile.TemporaryDirectory(prefix='maccms-apache-boundary-') as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        def write(name, content):
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, str):
                target.write_text(content)
            else:
                target.write_bytes(content)
            target.chmod(0o644)
        for entry in ['index.php', 'api.php', 'admin.php', 'admin_audit_renamed.php', 'install.php']:
            write(entry, ENTRY)
        for name in ['.env', '.env.backup', '.git/config', '.git/HEAD', 'composer.lock', 'composer.json',
                     'composer.phar', 'security_check.php', 'README.md', 'think', 'backup.zip', 'backup/config.txt',
                     'application/extra/example.php', 'application/fixture.txt', 'runtime/session/example',
                     'vendor/package/source.css', 'config/example.txt', 'extend/example.js', 'migration/example.txt',
                     'docker/example.txt', 'tests/example.txt', 'tools/example.txt', 'route/example.txt',
                     'docs/example.txt', 'deploy/example.txt', 'thinkphp_legacy_20260618/example.txt',
                     'template/audit/settings.php', 'template/audit/settings.json', 'template/audit/html/view.html',
                     'addons/audit/config.php', 'addons/audit/info.ini', 'addons/audit/view/private.html',
                     'static_new/app.js.bak', 'upload/leak.sql', 'upload/shell.php.jpg',
                     'template/audit/assets/source.php.css', 'template/audit/assets/source.sql.css', 'upload/secret.ini.txt']:
            write(name, 'PRIVATE_FIXTURE_SENTINEL')
        for extension in ['php', 'PHP', 'php8', 'phtml', 'phar', 'phps', 'cgi', 'shtml']:
            write('upload/payload.' + extension, SCRIPT)
        write('upload/override/.htaccess', '<Files "masquerade.jpg">\nSetHandler application/x-httpd-php\n</Files>\n')
        write('upload/override/masquerade.jpg', SCRIPT)
        image = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lZsAAAAASUVORK5CYII=')
        for name in ['upload/vod/picture.png', 'upload/user/avatar.webp', 'template/audit/images/logo.png', 'addons/audit/logo.png']:
            write(name, image)
        for name in ['static_new/js/app.js', 'static/addons/aicontent/js/aicontent.js',
                     'template/audit/asset/js/theme.js', 'template/audit/vendor/jquery/jquery.js', 'addons/audit/assets/plugin.js']:
            write(name, 'PUBLIC_SCRIPT_FIXTURE')
        for name in ['template/audit/asset/css/theme.css', 'addons/audit/assets/plugin.css', 'static_new/style.css']:
            write(name, 'PUBLIC_STYLE_FIXTURE')
        for name in ['static/ueditor/config.json', 'template/audit/asset/lottie/logo.json']:
            write(name, '{"fixture":"public"}')
        for name in ['static_new/ueditor/dialogs/preview/preview.html', 'static/player/index.html', 'vod/detail/1.html', '404.html', 'template/audit/help/help.html', 'addons/audit/assets/dialog.html']:
            write(name, '<p>PUBLIC_HTML_FIXTURE</p>')
        for name in ['robots.txt', 'sitemap.xml', 'baidu_audit_verify.txt', '.well-known/acme-challenge/audit-token']:
            write(name, 'PUBLIC_TEXT_FIXTURE')
        for name in ['upload/help/mac10.zip', 'upload/docs/manual.pdf', 'upload/docs/sheet.xlsx', 'upload/video/movie.mkv']:
            write(name, 'PUBLIC_DOWNLOAD_FIXTURE')
        (directory / 'static_new/empty').mkdir()
        # Container-visible targets are intentional; Apache must reject both file and directory symlinks.
        (directory / 'upload/linked-env.jpg').symlink_to('/var/www/html/.env')
        (directory / 'static_new/linked-internal').symlink_to('/var/www/html/application', target_is_directory=True)
        for image_name in images:
            name = 'maccms-apache-boundary-' + secrets.token_hex(5)
            try:
                subprocess.run(['docker', 'run', '--rm', '-d', '--network', 'none', '--name', name,
                                '-v', str(directory) + ':/var/www/html:ro', '-v', str(root) + ':/source:ro',
                                image_name], check=True, stdout=subprocess.DEVNULL)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    result = subprocess.run(['docker', 'exec', name, 'php', '-r',
                        '$c=curl_init("http://127.0.0.1/index.php");curl_setopt($c,CURLOPT_RETURNTRANSFER,true);'
                        '$r=curl_exec($c);if(!is_string($r)||!str_contains($r,"index.php")){echo curl_getinfo($c,CURLINFO_RESPONSE_CODE).":".substr((string)$r,0,900);exit(1);}'],
                        capture_output=True, text=True)
                    if result.returncode == 0:
                        break
                    time.sleep(0.1)
                else:
                    logs = subprocess.run(['docker', 'logs', '--tail', '3', name], capture_output=True, text=True)
                    raise RuntimeError('Isolated Apache failed to start: ' + result.stdout + result.stderr + logs.stderr)
                subprocess.run(['docker', 'exec', name, 'php', '/source/tests/deployment_audit_apache.php', *(['baseline'] if baseline else [])], check=True, timeout=90)
            finally:
                subprocess.run(['docker', 'stop', '-t', '2', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


if __name__ == '__main__':
    main()
