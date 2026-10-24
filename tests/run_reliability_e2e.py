"""One-command isolated live regression. Uses installed tools; no user credentials."""
import json
import os
import signal
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

root = Path(__file__).resolve().parents[1]
info = None
(root/'scratch').mkdir(exist_ok=True)
info_path = root/'scratch'/('m3-run-'+uuid.uuid4().hex+'.json')
try:
    result = subprocess.run([sys.executable, str(root/'tests/start_reliability_environment.py')],
        cwd=root, capture_output=True, text=True, timeout=120,
        env={**os.environ, 'SEALED_TEST_INFO_FILE': str(info_path)})
    # Never echo fixture generation output or an environment containing credentials.
    if result.returncode:
        raise RuntimeError('Disposable environment did not start; inspect scratch/m3-environment.json logs.')
    info = json.loads(info_path.read_text())
    environment = {**os.environ, 'SEALED_TEST_FIXTURE': info['fixture'],
        'NEXT_PUBLIC_API_URL': info['origin'], 'SEALED_TEST_ORIGIN': info['origin']}
    result = subprocess.run(['node', str(root/'node_modules/ts-node/dist/bin.js'), '--transpile-only',
        str(root/'tests/reliability_e2e.ts')], cwd=root, env=environment, capture_output=True, text=True, timeout=180)
    print(result.stdout)
    if result.returncode:
        print(result.stderr)
        raise RuntimeError('Isolated live regression failed.')
finally:
    if info is None and info_path.exists():
        info = json.loads(info_path.read_text())
    if info:
        for key in ('frontendPid', 'backendPid'):
            if os.name == 'nt':
                subprocess.run(['taskkill', '/PID', str(info[key]), '/T', '/F'], capture_output=True)
            else:
                try: os.kill(info[key], signal.SIGTERM)
                except ProcessLookupError: pass

        # Delete only the newly generated, contained disposable directory. Detach
        # the dependency junction first; never traverse into installed packages.
        directory = Path(info['directory']).resolve()
        if directory.parent != (root/'scratch').resolve() or not directory.name.startswith('sealed-demo-'):
            raise RuntimeError('Refusing cleanup outside the owned demo directory.')
        link = directory/'frontend/node_modules'
        if link.exists():
            if link.resolve() != (root/'frontend/node_modules').resolve():
                raise RuntimeError('Unexpected dependency link; refusing cleanup.')
            if os.name == 'nt': os.rmdir(link)
            else: link.unlink()
        shutil.rmtree(directory)
        info_path.unlink(missing_ok=True)
        print('PASS: only owned demo processes and disposable files cleaned up.')
