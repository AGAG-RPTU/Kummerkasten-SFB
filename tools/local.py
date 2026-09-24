#!/usr/bin/env python3
"""Use the Kummerkasten from this git checkout instead of the website.

Pages, scripts and keys.json come from the checkout on your computer, which
you can read and verify; only the encrypted API traffic goes to the site.
Altered JavaScript on the server then cannot reach your passphrase or
codeword. Needs only Python 3.

    git clone https://github.com/AGAG-RPTU/Kummerkasten-SFB
    cd Kummerkasten-SFB
    tools/local.py https://kummerkasten.coxeter.de/
    # then open http://localhost:8770/staff (or /write, /conversation)
"""

import argparse
import http.server
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
PUBLIC = ROOT / 'public'
DEFAULT_PORT = 8770
MAX_BODY = 262144           # MAX_REQUEST_BYTES in private/app.php
TIMEOUT = 60
TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json',
    '.png': 'image/png',
}


def git(*args):
    return subprocess.run(['git', '-C', str(ROOT), *args], capture_output=True, text=True).stdout.strip()


# The same headers as on the site, CSP included (see public/.htaccess).
def security_headers():
    text = (PUBLIC / '.htaccess').read_text()
    return [(name, value) for name, value in re.findall(r'^\s*Header always set (\S+) "(.*)"\s*$', text, re.M)
            if name != 'Strict-Transport-Security']


class Handler(http.server.BaseHTTPRequestHandler):
    site = None
    headers_to_send = []
    commit = ''

    def send(self, status, body, content_type):
        self.send_response(status)
        for name, value in self.headers_to_send:
            self.send_header(name, value)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    # Pages and scripts from the checkout; clean URLs as on the site.
    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path == '/version.txt':
            self.send(200, self.commit.encode(), 'text/plain; charset=utf-8')
            return
        if path == '/':
            path = '/index.html'
        elif re.fullmatch(r'/[a-z]+', path):
            path += '.html'
        file = (PUBLIC / path.lstrip('/')).resolve()
        if PUBLIC not in file.parents or file.suffix not in TYPES or not file.is_file():
            self.send(404, b'not found', 'text/plain; charset=utf-8')
            return
        self.send(200, file.read_bytes(), TYPES[file.suffix])

    # API calls go to the site unchanged; they carry only ciphertext and signatures.
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        if self.path != '/api.php' or length > MAX_BODY:
            self.send(404, b'not found', 'text/plain; charset=utf-8')
            return
        request = urllib.request.Request(self.site + 'api.php', data=self.rfile.read(length),
                                         headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                self.send(response.status, response.read(), 'application/json')
        except urllib.error.HTTPError as err:
            self.send(err.code, err.read(), 'application/json')
        except (urllib.error.URLError, TimeoutError) as err:
            self.send(502, f'{{"error": "site unreachable: {err}"}}'.encode(), 'application/json')

    def log_message(self, *args):
        pass        # requests carry nothing worth logging


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('site', help='address of the Kummerkasten, e.g. https://kummerkasten.coxeter.de/')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    sys.stdout.reconfigure(line_buffering=True)
    Handler.site = args.site if args.site.endswith('/') else args.site + '/'
    Handler.headers_to_send = security_headers()
    Handler.commit = git('rev-parse', 'HEAD')

    # Say which code runs and whether it matches the site, so the user can judge.
    modified = git('status', '--porcelain', '--', 'public')
    try:
        with urllib.request.urlopen(Handler.site + 'version.txt', timeout=TIMEOUT) as response:
            deployed = response.read().decode().strip()
    except (urllib.error.URLError, TimeoutError):
        deployed = ''
    print(f'Serving commit {Handler.commit[:7]} of this checkout'
          + (' WITH LOCAL CHANGES in public/' if modified else ''))
    if deployed and deployed != Handler.commit:
        print(f'Note: the site runs {deployed[:7]}. Check out that commit if pages misbehave.')
    print(f'API calls go to {Handler.site}api.php')
    print(f'Open http://localhost:{args.port}/staff (Ctrl-C to stop)')

    server = http.server.ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    sys.exit(main())
