"""Start an isolated M3 browser environment. All credentials are synthetic.

Outputs only URLs/paths. Existing databases, pins, identities, and servers are not
changed. Uses installed dependencies via a junction; no package installation.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[1]
(root/'scratch').mkdir(exist_ok=True)
directory = Path(tempfile.mkdtemp(prefix='sealed-demo-', dir=root/'scratch'))
result = subprocess.run(['node', str(root/'node_modules/ts-node/dist/bin.js'), '--transpile-only', str(root/'tests/create_reliability_fixture.ts')], cwd=root, capture_output=True, text=True, check=True)
fixture = json.loads(result.stdout)
fixture_path = directory/'fixture.json'; fixture_path.write_text(json.dumps(fixture))
auth = directory/'auth.json'; auth.write_text(json.dumps({'username': fixture['account']['username'], 'accessKey': fixture['accessKey']}))
frontend = directory/'frontend'
shutil.copytree(root/'frontend', frontend, ignore=shutil.ignore_patterns('node_modules', '.next', '.env*', 'tsconfig.tsbuildinfo'))
link = frontend/'node_modules'
if os.name == 'nt':
    subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(root/'frontend/node_modules')], capture_output=True, check=True)
else: link.symlink_to(root/'frontend/node_modules', target_is_directory=True)
def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return str(listener.getsockname()[1])
web_port = os.environ.get('SEALED_TEST_WEB_PORT') or free_port()
api_port = os.environ.get('SEALED_TEST_API_PORT') or free_port()
origin = 'http://127.0.0.1:'+web_port; api = 'http://127.0.0.1:'+api_port
(frontend/'.env.local').write_text('NEXT_PUBLIC_INVESTIGATOR_SIGNING_KEYS='+fixture['packet']['signingPublicKey']+'\nBACKEND_INTERNAL_URL='+api+'\n')
environment = {**os.environ, 'DATABASE_URL': 'sqlite:///'+str(directory/'test.db'),
    'SEALED_TEST_FIXTURE': str(fixture_path), 'SEALED_AUTH_FILE': str(auth),
    'SEALED_ALLOWED_ORIGINS': origin, 'PYTHONPATH': str(root), 'NEXT_TELEMETRY_DISABLED': '1', 'SEALED_DEMO': '1'}
flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
api_log = (directory/'api.log').open('w'); web_log = (directory/'web.log').open('w')
backend = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'tests.reliability_server:app', '--host', '127.0.0.1', '--port', api_port, '--no-access-log'], cwd=directory, env=environment, stdout=api_log, stderr=api_log, creationflags=flags)
web = subprocess.Popen(['node', str(root/'frontend/node_modules/next/dist/bin/next'), 'dev', '--webpack', '--hostname', '127.0.0.1', '--port', web_port], cwd=frontend, env=environment, stdout=web_log, stderr=web_log, creationflags=flags)
info = {'directory': str(directory), 'fixture': str(fixture_path), 'origin': origin, 'api': api, 'backendPid': backend.pid, 'frontendPid': web.pid}
(Path(os.environ.get('SEALED_TEST_INFO_FILE', str(root/'scratch/m3-environment.json')))).write_text(json.dumps(info))
for url in [api+'/health', origin+'/']:
    for attempt in range(60):
        try:
            with urllib.request.urlopen(url, timeout=15) as response:
                if response.status == 200: break
        except Exception:
            if backend.poll() is not None or web.poll() is not None: raise RuntimeError('Isolated service exited; inspect its local log.')
            time.sleep(1)
    else: raise RuntimeError('Isolated service did not become ready.')
print(json.dumps({'ready': True, 'origin': origin, 'api': api, 'directory': str(directory)}))
