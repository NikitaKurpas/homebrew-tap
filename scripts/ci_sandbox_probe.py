"""Disposable CI only; add sandbox restrictions without changing app security."""
import json
import os
from pathlib import Path
import subprocess
import sys

if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'macOS':
    raise SystemExit('Disposable macOS GitHub Actions runner required.')
app = str(Path(sys.argv[1]).resolve(strict=True))
# Native Homebrew macOS mach-lookup allowlist, inspected at ef90f724ff.
names = ['com.apple.mobileassetd.v2', 'com.apple.sysmond', 'com.apple.lsd.mapdb',
         'com.apple.bsd.dirhelper', 'com.apple.system.opendirectoryd.libinfo',
         'com.apple.system.opendirectoryd.membership', 'com.apple.PowerManagement.control',
         'com.apple.SecurityServer', 'com.apple.networkd', 'com.apple.ocspd',
         'com.apple.trustd.agent', 'com.apple.SystemConfiguration.DNSConfiguration',
         'com.apple.SystemConfiguration.configd']
lookup = '(deny mach-lookup)\n(allow mach-lookup (xpc-service-name "com.apple.MTLCompilerService")\n'
lookup += '\n'.join('(global-name ' + json.dumps(name) + ')' for name in names) + ')\n'
cases = [('direct', None),
         ('additional-sandbox-only', '(version 1) (debug deny) (allow default)'),
         ('additional-homebrew-mach-lookup-policy', '(version 1) (debug deny)\n' + lookup + '(allow default)')]
for label, profile in cases:
    command = [app, '--help']
    if profile:
        command = ['/usr/bin/sandbox-exec', '-p', profile, *command]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        print(json.dumps({'case': label, 'returncode': result.returncode,
                          'signal': -result.returncode if result.returncode < 0 else None,
                          'help_present': 'Dedicated Secure Enclave' in result.stdout,
                          'stderr': result.stderr[:3000]}, sort_keys=True))
    except subprocess.TimeoutExpired:
        print(json.dumps({'case': label, 'timeout': True}))
# Keep the existing brew test unchanged and mandatory after this diagnostic.
