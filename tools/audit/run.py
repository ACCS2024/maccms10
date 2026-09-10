#!/usr/bin/env python3
"""Run pinned analyzers without loading site configuration; findings are never silently baselined."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    tool = root / 'tools/audit'
    php = os.environ.get('PHP_BINARY', 'php')
    targets = ['application', 'addons', 'extend', 'config', 'route', 'index.php',
               'api.php', 'admin.php', 'install.php', 'bin', 'deploy', 'migration']
    commands = {
        'phpstan': [php, str(tool / 'vendor/bin/phpstan'), 'analyse', '-c', str(tool / 'phpstan.neon'),
                    '--no-progress', '--error-format=json', '--memory-limit=2G'],
        'phpcompatibility': [php, '-d', 'memory_limit=2G', str(tool / 'vendor/bin/phpcs'),
                            '--standard=' + str(tool / 'vendor/phpcompatibility/php-compatibility/PHPCompatibility'),
                            '--runtime-set', 'testVersion', '8.3-8.4', '--extensions=php',
                            '--ignore=*/extend/upyun/vendor/*', '--report=json', *targets],
    }
    summary = {}
    for name, command in commands.items():
        with (args.output / (name + '.json')).open('w') as output, (args.output / (name + '.stderr')).open('w') as errors:
            result = subprocess.run(command, cwd=root, stdout=output, stderr=errors, timeout=600)
        try:
            report = json.loads((args.output / (name + '.json')).read_text())
            totals = report['totals']
            if not isinstance(totals, dict) or 'files' not in report:
                raise ValueError('Analyzer did not return its result schema')
            if name == 'phpstan' and totals.get('errors', 0):
                raise ValueError('PHPStan reported a global analysis failure')
            if name == 'phpcompatibility' and not report['files']:
                raise ValueError('PHPCompatibility returned an empty scan')
        except (ValueError, KeyError) as error:
            raise RuntimeError(name + ' did not complete: ' + str(error)) from error
        summary[name] = {'exit': result.returncode, 'totals': totals}
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    # Findings need triage; this command never labels tool warnings a clean audit.
    return 1 if any(item['exit'] != 0 for item in summary.values()) else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print('Static audit incomplete: ' + str(error), file=sys.stderr)
        sys.exit(2)
