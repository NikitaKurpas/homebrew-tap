"""Read only recent Keylet crash metadata on disposable macOS CI."""
import json
import os
from pathlib import Path
import time

if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'macOS':
    raise SystemExit('Disposable macOS GitHub Actions runner required.')
roots = [Path.home()/'Library/Logs/DiagnosticReports', Path('/Library/Logs/DiagnosticReports')]
decoder = json.JSONDecoder()
found = False
for root in roots:
    for directory in [root, root/'Retired']:
        if not directory.is_dir():
            continue
        for path in directory.iterdir():
            if not path.name.lower().startswith('keylet') or path.suffix != '.ips':
                continue
            try:
                if time.time() - path.stat().st_mtime > 600 or path.stat().st_size > 2_000_000:
                    continue
                text = path.read_text()
                header, offset = decoder.raw_decode(text)
                body, _ = decoder.raw_decode(text, offset + len(text[offset:]) - len(text[offset:].lstrip()))
            except (OSError, ValueError, TypeError):
                continue
            if not isinstance(body, dict) or body.get('procName', '').lower() != 'keylet':
                continue
            found = True
            result = {'process': 'keylet'}
            for section, keys in {'exception': ['type', 'signal'], 'termination': ['namespace', 'code', 'indicator']}.items():
                values = body.get(section, {})
                result[section] = {key: values[key] for key in keys if isinstance(values, dict) and isinstance(values.get(key), (str, int))}
            # Only startup/abort library diagnostic text; omit unrelated ASI.
            asi = body.get('asi', {})
            if isinstance(asi, dict):
                result['startup_reason'] = {k: str(v)[:3000] for k, v in asi.items() if k in ['libsystem_secinit.dylib', 'libsystem_c.dylib']}
            index = body.get('faultingThread')
            threads = body.get('threads', [])
            if isinstance(index, int) and isinstance(threads, list) and 0 <= index < len(threads):
                result['faultingFrames'] = [{k: frame.get(k) for k in ['symbol', 'imageIndex', 'imageOffset']} for frame in threads[index].get('frames', [])[:8]]
            print(json.dumps(result, sort_keys=True))
if not found:
    print('No recent user/system Keylet IPS report; use the scoped unified log below.')
