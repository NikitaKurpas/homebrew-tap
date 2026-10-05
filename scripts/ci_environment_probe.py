"""Diagnostic only: run before the unchanged failing brew test on disposable CI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'macOS':
    raise SystemExit('This probe runs only on a disposable macOS GitHub Actions runner.')
binary = Path(sys.argv[1]).resolve(strict=True)
with tempfile.TemporaryDirectory(prefix='keylet-test-environment-') as directory:
    root = Path(directory)
    home = root/'home'
    home.mkdir()
    variants = [
        ('direct-pipes', {}, None),
        ('redirected-home', {'HOME': str(home), 'XDG_CONFIG_HOME': str(home/'.config')}, None),
        ('temporary-cwd', {}, str(root)),
        ('redirected-home-and-cwd', {'HOME': str(home), 'XDG_CONFIG_HOME': str(home/'.config')}, str(root)),
    ]
    for name, changes, cwd in variants:
        try:
            child = subprocess.run([str(binary), '--help'], env=dict(os.environ, **changes),
                                   cwd=cwd, capture_output=True, text=True, timeout=20)
            print(json.dumps({'case': name, 'returncode': child.returncode,
                              'signal': -child.returncode if child.returncode < 0 else None,
                              'help_present': 'Dedicated Secure Enclave' in child.stdout,
                              'stderr': child.stderr[:2000]}, sort_keys=True))
        except subprocess.TimeoutExpired:
            print(json.dumps({'case': name, 'timeout': True}))
# This script is diagnostic. It never replaces or suppresses the original brew test.
