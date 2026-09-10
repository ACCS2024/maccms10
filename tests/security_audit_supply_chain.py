#!/usr/bin/env python3
"""Only disposable fixtures; no application bootstrap or external network."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('maccms_audit', REPO / 'tools/security/maccms_audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class SupplyChainAudit(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='maccms-supply-chain-')
        self.base = Path(self.temporary.name)
        self.root = self.base / 'site'
        self.root.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value.encode() if isinstance(value, str) else value)
        return path

    def scan(self, profile='deployed', baseline=None, approved=None, verify=False):
        return audit.scan_tree(self.root, profile, baseline, approved,
            REPO / 'application/common/util/DataConfig.php', verify=verify)[0]

    def test_plain_base64_hex_and_split_domains(self):
        url = 'https://code.jquecy.com/payload.js'
        payloads = [url, base64.b64encode(url.encode()).decode(), url.encode().hex(),
            ''.join('\\x%02x' % c for c in url.encode()),
            ''.join('\\u%04x' % c for c in url.encode()),
            "https://code.jqu' + 'ecy.com/payload.js", 'https%3A%2F%2Fcode.jquecy.com%2Fpayload.js',
            base64.b64encode(base64.b64encode(url.encode())).decode()]
        for value in payloads:
            with self.subTest(value=value):
                result = audit.scan_content('template/private/assets/theme.js', ('var data = "' + value + '";').encode())
                self.assertIn('upstream-or-c2-domain', [x['rule'] for x in result])
        for html in ['<script src=//code.jquecy.com/a.js></script>', '<iframe SRC=https://mycj.top/player>']:
            self.assertIn('upstream-or-c2-domain', [x['rule'] for x in audit.scan_content('page.html', html.encode())])
        encoded = base64.b64encode(url.encode()).decode()
        for prefix in ['var hash=/#/;', r'var protocol=/https?:\/\//;']:
            self.assertIn('upstream-or-c2-domain', [x['rule'] for x in audit.scan_content('jquery.js', (prefix + 'var payload="' + encoded + '";').encode())])

    def test_harmless_docs_and_exact_deny_list_are_not_connections(self):
        self.write('docs/security/report.md', 'https://code.jquecy.com/payload.js')
        self.write('tests/fixture.js', 'https://code.jquecy.com/payload.js')
        self.write('application/common.php', "<?php // https://code.jquecy.com/ historical report\n$blocked = ['jquecy.com', 'maccms.la'];")
        self.assertEqual([], self.scan('source'))
        self.write('application/common.php', "<?php $blocked=['jquecy.com', 'https://code.jquecy.com/payload'];")
        self.assertIn('upstream-or-c2-domain', [x['rule'] for x in self.scan('source')])

    def test_markers_in_comments_and_known_hash(self):
        self.assertEqual('malware-marker', audit.scan_content('private.js', b'/*138ae887806f*/')[0]['rule'])
        harmless = b'non-executable sample stand-in'
        with patch.object(audit, 'BAD_MD5', {audit.hashlib.md5(harmless).hexdigest()}):
            self.assertEqual('known-malware-hash', audit.scan_content('file.php', harmless)[0]['rule'])

    def test_data_config_preserved_and_never_executed(self):
        normal = "<?php return ['autoload'=>false,'hooks'=>['base64_decode_label'=> '" + ('plugin-data' * 400) + "']];"
        self.write('application/extra/addons.php', normal)
        self.assertEqual([], self.scan())
        sentinel = self.base / 'executed'
        evil = "<?php file_put_contents(" + repr(str(sentinel)) + ",'bad'); return [];"
        self.write('application/extra/addons.php', evil)
        self.assertIn('executable-or-invalid-data-config', [x['rule'] for x in self.scan()])
        self.assertFalse(sentinel.exists())
        self.assertEqual(evil, (self.root / 'application/extra/addons.php').read_text())

    def test_private_theme_extra_php_and_upload_script_block(self):
        self.write('template/private/assets/theme.js', "var u='https://cdn.jsdelivr.net/npm/local.js';")
        self.assertEqual([], self.scan())
        self.write('template/private/assets/injected.js', "var u='https://code.jquecy.com/a';")
        self.write('upload/image.php.jpg', '<?php echo "harmless fixture";')
        self.write('application/index/controller/Orphan.php', '<?php echo "orphan";')
        rules = {x['rule'] for x in self.scan()}
        self.assertTrue({'upstream-or-c2-domain', 'php-in-upload', 'unapproved-executable'} <= rules)
        self.write('template/private/assets/home.js.download', "var u='https://code.jquecy.com/b';")
        self.assertTrue(any(x['path'].endswith('.js.download') for x in self.scan()))
        for directory in ['upload/docs', 'upload/tests', 'tools/security', 'deploy', 'template/private/tests']:
            self.write(directory + '/shell.php', '<?php echo "harmless stand-in";')
        blocked = {x['path'] for x in self.scan() if x['rule'] == 'unapproved-executable'}
        self.assertTrue({'upload/docs/shell.php', 'upload/tests/shell.php', 'tools/security/shell.php',
            'deploy/shell.php', 'template/private/tests/shell.php'} <= blocked)

    def test_exact_approval_and_renamed_admin(self):
        body = b'<?php /* benign entry stand-in */'
        self.write('adm_random.php', body)
        self.assertEqual([], self.scan(baseline={'admin.php': audit.digest(body)}))
        self.write('template/private/settings.php', '<?php return [];')
        sha = audit.digest(b'<?php return [];')
        self.assertEqual([], self.scan(baseline={'admin.php': audit.digest(body)}, approved={'template/private/settings.php': sha}))
        self.write('template/private/settings.php', '<?php return [1];')
        self.assertIn('unapproved-executable', [x['rule'] for x in self.scan(approved={'template/private/settings.php': sha})])

    def test_postdeployment_checks_actual_bytes_and_missing_source(self):
        body = b'<?php return [];'
        self.write('application/example.php', body)
        baseline = {'application/example.php': audit.digest(body), 'config/required.php': audit.digest(body)}
        self.assertIn('missing-deployed-source', {x['rule'] for x in self.scan(baseline=baseline, verify=True)})
        self.write('config/required.php', body)
        self.assertEqual([], self.scan(baseline=baseline, verify=True))
        self.write('application/example.php', b'<?php return [1];')
        self.assertIn('deployed-source-mismatch', {x['rule'] for x in self.scan(baseline=baseline, verify=True)})
        self.write('static/home.js', 'var injected=1;')
        self.assertTrue(any(x['path'] == 'static/home.js' and x['rule'] == 'deployed-source-mismatch'
            for x in self.scan(baseline={'static/home.js': audit.digest(b'var original=1;')}, verify=True)))

    def test_vendor_package_mutation_blocks_before_deployment(self):
        self.write('vendor/package/Client.php', '<?php return "modified";')
        self.write('vendor/composer/ClassLoader.php', '<?php return "modified loader";')
        self.write('vendor/composer/installed.php', '<?php return ["fixture"=>1];')
        baseline = {name: audit.digest(b'<?php return "trusted";') for name in
            ['vendor/package/Client.php', 'vendor/composer/ClassLoader.php', 'vendor/composer/installed.php']}
        mutations = {x['path'] for x in self.scan(baseline=baseline) if x['rule'] == 'vendor-source-mismatch'}
        self.assertEqual({'vendor/package/Client.php', 'vendor/composer/ClassLoader.php'}, mutations)
        self.assertIn('vendor/composer/installed.php', audit.COMPOSER_GENERATED)

    def test_symlinks_never_followed(self):
        outside = self.base / 'private.php'
        outside.write_text('<?php return [];')
        (self.root / 'linked.php').symlink_to(outside)
        self.assertEqual(['symlink'], [x['rule'] for x in self.scan()])

    def test_auto_prepend_and_handler_overrides(self):
        self.write('.user.ini', 'open_basedir=/home/wwwroot/site/:/tmp/\n')
        self.assertEqual([], self.scan())
        self.write('.user.ini', 'auto_prepend_file=/tmp/implant.php\n')
        self.write('upload/.htaccess', 'AddType application/x-httpd-php .jpg\n')
        self.assertTrue({'php-auto-include-directive', 'executable-handler-override'} <= {x['rule'] for x in self.scan()})

    def test_quarantine_preserves_evidence_and_never_touches_normal_config(self):
        self.write('application/extra/active.php', 'stand-in malware evidence')
        self.write('application/extra/addons.php', '<?php return [];')
        self.write('template/private/custom.php', '<?php return [];')
        self.write('install.php', 'retired installer')
        self.write('application/data/install/install.lock', 'installed')
        self.write('thinkphp_legacy_20260618/start.php', 'old framework')
        destination = self.base / 'quarantine'
        manifest = Path(audit.quarantine_known(self.root, destination))
        data = json.loads(manifest.read_text())
        entries = {x['path']: x for x in data['files']}
        self.assertEqual(audit.digest(b'stand-in malware evidence'), entries['application/extra/active.php']['sha256'])
        self.assertEqual('stand-in malware evidence', (manifest.parent / 'files/application/extra/active.php').read_text())
        self.assertFalse((self.root / 'application/extra/active.php').exists())
        self.assertFalse((self.root / 'install.php').exists())
        self.assertTrue((self.root / 'application/extra/addons.php').exists())
        self.assertTrue((self.root / 'template/private/custom.php').exists())
        self.assertEqual(0o600, manifest.stat().st_mode & 0o777)
        self.assertTrue(all(x['state'] == 'moved' for x in data['moves']))

    def test_quarantine_refuses_webroot_relative_and_symlink_destinations(self):
        self.write('application/extra/active.php', 'evidence')
        for destination in [self.root / 'quarantine', Path('relative')]:
            with self.assertRaises(ValueError):
                audit.quarantine_known(self.root, destination)
        (self.base / 'linked').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            audit.quarantine_known(self.root, self.base / 'linked/outside')
        self.assertTrue((self.root / 'application/extra/active.php').exists())

    def test_host_audit_only_reads_persistence(self):
        self.write('etc/udev/rules.d/99-example.rules', 'ACTION=="add", RUN+="/tmp/loader"')
        self.write('etc/ld.so.preload', '/opt/lib/custom.so')
        self.write('etc/nginx/nginx.conf', 'load_module modules/ngx_custom.so;')
        self.write('etc/systemd/system/example.service', '[Service]\nExecStart=/bin/sh -c "curl https://example.invalid/file"')
        self.write('etc/cron.d/example', '* * * * * root /tmp/job')
        results, inventory = audit.host_audit(self.root)
        self.assertTrue({'review-persistence-command', 'review-ld-preload', 'review-nginx-module'} <= {x['rule'] for x in results})
        self.assertIn('etc/nginx/nginx.conf', inventory)
        self.assertTrue((self.root / 'etc/ld.so.preload').exists())
        self.write('var/adm/ring04h_office_bin', b'\x7fELF benign stand-in')
        self.assertIn('review-reported-payload-name', {x['rule'] for x in audit.host_audit(self.root)[0]})

    def test_exported_sql_and_text_are_scanned_without_execution(self):
        payload = base64.b64encode(b'https://code.jquecy.com/x.js').decode()
        self.write('database.sql', "INSERT INTO settings VALUES ('" + payload + "');")
        self.write('row.txt', 'https://code.jquecy.com/plain.js')
        self.write('rows.json', '{"name":"safe","text":"content"}')
        found = audit.scan_tree(self.root, 'exported')[0]
        paths = {x['path'] for x in found if x['rule'] == 'upstream-or-c2-domain'}
        self.assertEqual({'database.sql', 'row.txt'}, paths)
        self.write('archived.sql.gz', 'not expanded')
        self.assertIn('compressed-export-not-supported', {x['rule'] for x in audit.scan_tree(self.root, 'exported')[0]})

    def test_scanner_covers_the_runtime_deny_list(self):
        source = audit.uncomment((REPO / 'application/common.php').read_text())
        body = audit.re.search(r'\$blocked\s*=\s*\[([^;]*?)\];', source).group(1)
        domains = set(audit.re.findall(r"'([a-z0-9.-]+)'", audit.uncomment(body)))
        self.assertTrue(domains <= set(audit.DOMAINS) | audit.OBSERVED_BLOCKED_HOSTS, 'Update offline IOC policy together with the runtime deny list')

    def test_observed_loader_url_does_not_label_all_ip_content_as_malware(self):
        self.assertEqual([], audit.scan_content('config.json', b'{"server":"211.162.103.35"}'))
        self.assertIn('observed-hidden-loader-url', {x['rule'] for x in audit.scan_content('old.js', b'var src="http://211.162.103.35/static/Device/learn.js";')})
        self.assertIn('upstream-or-c2-domain', {x['rule'] for x in audit.scan_content('old.js', b'var src="https://code.jquecy.com./payload.js";')})
        self.assertEqual([], audit.scan_content('ok.js', b'var src="https://code.jquecy.com.evil.invalid/";'))

    def test_cli_blocks_even_after_quarantining_an_attack_path(self):
        self.write('application/extra/active.php', 'stand-in evidence')
        baseline = self.base / 'baseline.json'
        baseline.write_text('{"files":{}}')
        report = self.base / 'audit.json'
        result = audit.main(['--root', str(self.root), '--profile', 'deployed', '--baseline', str(baseline),
            '--data-parser', str(REPO / 'application/common/util/DataConfig.php'),
            '--quarantine-known', str(self.base / 'quarantine'), '--json', str(report)])
        self.assertEqual(1, result)
        self.assertIn('quarantined-malware-path', {x['rule'] for x in json.loads(report.read_text())['findings']})
        self.assertFalse((self.root / 'application/extra/active.php').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
