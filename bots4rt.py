#!/usr/bin/env python3
import os
import sys
import json
import random
import threading
import time
import re
import urllib.parse
import base64
import tempfile
from queue import Queue
from html.parser import HTMLParser
from functools import wraps

try:
    import requests
    import telebot
    from bs4 import BeautifulSoup
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
except ImportError:
    print("\033[91m[!] Missing dependencies. Install with: pip install requests pyTelegramBotAPI beautifulsoup4 pycryptodome\033[0m")
    sys.exit(1)

CONFIG_FILE = "user_token_id.json"
USER_PATH_FILE = "user_list.txt"
LFI_PATH_FILE = "lfi.txt"
REPORT_FILE = "report.json"
KEY_FILE = "secret.key"
USER_STORE_FILE = "users.enc"

DEFAULT_PATHS = [
    ".git/config", ".git/HEAD", ".svn/entries", ".hg/hgrc", ".bzr/branch",
    ".vscode/sftp.json", "vscode/sftp.json", ".ftpconfig", "ftpconfig",
    ".env", "env", "wp-config.php", "wp-config.php.bak", "config.php",
    "configuration.php", ".my.cnf", "my.cnf", "database.yml",
    ".aws/credentials", "aws/credentials", ".azure/credentials", "azure/credentials",
    ".s3cfg", "s3cfg", "secrets.yml", "credentials.json", ".netrc", "netrc",
    ".npmrc", "npmrc", "auth.json", "composer.json", "composer.lock",
    "package.json", "yarn.lock", "settings.py", ".settings.php",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/id_ecdsa", ".ssh/id_ed25519",
    ".ssh/authorized_keys", ".ssh/config",
    "backup.zip", "backup.tar.gz", "dump.sql", "db.sql", "database.sql",
    "db_backup.sql", ".mysql_history", ".psql_history",
    ".htaccess", ".htpasswd", "web.config",
    "error_log", "access_log", "debug.log", ".log", "application.log",
    "server.log", "catalina.out", "tomcat.log", "httpd.pid", "mysql.err",
    "mysql.log", "postgresql.log", "redis.log", "mongod.log", "elasticsearch.log",
    "php_errors.log", "php_errorlog", "error.log",
    "wp-content/debug.log", "wp-config-sample.php", ".env.example",
    "storage/logs/laravel.log", "app/config/parameters.yml",
    "config/database.php", ".flaskenv", "runtime/logs/app.log",
    "app/etc/local.xml", "includes/config.php", "joomla.xml", "magento_version",
    "version.php", "VERSION", "RELEASE", "CHANGELOG.txt", "LICENSE.txt",
    "sftp-config.json", "project.json", "workspace.xml", ".idea/workspace.xml",
    ".vscode/launch.json",
    "docker-compose.yml", "docker-compose.override.yml", ".dockerignore",
    "Dockerfile", ".gitlab-ci.yml", ".travis.yml", "bitbucket-pipelines.yml",
    "Jenkinsfile", "Procfile",
    ".npmignore", "bower.json", "Gruntfile.js", "gulpfile.js",
    "webpack.config.js", "vue.config.js", "nuxt.config.js", "next.config.js",
    "angular.json", "package-lock.json", "Gemfile", "Gemfile.lock",
    "Podfile", "Cartfile", "cargo.toml", "Cargo.lock", "go.mod", "go.sum",
    ".python-version", "Pipfile", "Pipfile.lock", "poetry.lock",
    "pyproject.toml", "requirements.txt", "dev-requirements.txt",
    ".ruby-version", ".bundle/config", ".yardopts", ".rspec",
    ".env.local", ".env.dev", ".env.prod", ".env.staging", ".env.test",
    ".env.dist", "config.env", "settings.env", "application.yml",
    "application.properties", "bootstrap.yml", "bootstrap.properties",
    "log4j.properties", "log4j2.xml", "logback.xml", "logging.properties",
    ".gitattributes", ".gitmodules", ".gitignore_global", ".gitconfig",
    ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile",
    ".cshrc", ".tcshrc", ".kshrc", ".history", ".viminfo", ".lesshst",
    ".wget-hsts", ".curlrc", ".wgetrc",
    "npm-debug.log", "yarn-debug.log", "yarn-error.log",
    "etc/passwd", "etc/shadow", "etc/hosts", "etc/hostname", "etc/issue",
    "etc/motd", "etc/group", "etc/network/interfaces",
    "proc/self/environ", "proc/self/cmdline",
    "install.php", "setup.php", "update.php", "migrate.php", "cron.php",
    "cli.php", "shell.php", "cmd.php", "exec.php", "system.php", "eval.php",
    "phpinfo.php", "info.php", "test.php", "test.html", "demo.php",
    "example.php", "sample.php",
    "backup.tar.bz2", "backup.7z", "www.zip", "public.zip", "html.zip",
    "htdocs.zip", "website.zip", "site.zip", "data.zip", "sql.zip",
    "mysql.zip", "postgres.zip", "database.zip", "db.zip", "dump.zip",
    "export.sql", "export.zip", "import.sql", "import.zip",
    "dump.sql.gz", "dump.sql.bz2", "database.sql.gz", "database.sql.bz2",
    "backup.sql.gz", "backup.sql.bz2", "dump.rar", "backup.rar",
    "site.rar", "www.rar", "site.7z", "data.7z",
    "README.md", "INSTALL.md", "UPGRADE.txt", "SECURITY.md"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/120.0 Firefox/120.0",
]

HEADERS_TEMPLATE = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0"
}

LFI_PARAMS = ["file", "page", "include", "path", "doc", "folder", "root", "view", "content", "document", "url", "data", "inc", "load", "read", "dir", "show", "location"]

class SecureStorage:
    def __init__(self, filename, key_file=KEY_FILE):
        self.filename = filename
        self.key_file = key_file
        self.key = self._load_key()
    def _load_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        key = get_random_bytes(32)
        with open(self.key_file, 'wb') as f:
            f.write(key)
        return key
    def encrypt(self, data_dict):
        json_data = json.dumps(data_dict).encode('utf-8')
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(json_data, AES.block_size))
        with open(self.filename, 'wb') as f:
            f.write(iv + ct_bytes)
    def decrypt(self):
        if not os.path.exists(self.filename):
            return {}
        with open(self.filename, 'rb') as f:
            data = f.read()
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return json.loads(pt.decode('utf-8'))

class Config:
    def __init__(self):
        self.token = None
        self.owner_id = None
        self.load_or_ask()
    def load_or_ask(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                self.token = data.get("token")
                self.owner_id = data.get("chat_id")
                if self.token:
                    return
        print("First time setup. Enter your bot token and your Telegram user ID (optional).")
        self.token = input("Bot token: ").strip()
        self.owner_id = input("Your Telegram user ID (optional): ").strip()
        with open(CONFIG_FILE, "w") as f:
            json.dump({"token": self.token, "chat_id": self.owner_id}, f)
        print("Config saved.")

config = Config()
bot = telebot.TeleBot(config.token)
user_storage = SecureStorage(USER_STORE_FILE)

user_paths = []
lfi_payloads = []
crawl_enabled = True
path_lock = threading.Lock()
lfi_lock = threading.Lock()
scan_semaphore = threading.Semaphore(5)
active_scans = {}

def load_user_paths():
    global user_paths
    with path_lock:
        if os.path.exists(USER_PATH_FILE):
            with open(USER_PATH_FILE, "r") as f:
                user_paths = [line.strip() for line in f if line.strip()]
        else:
            user_paths = []

def load_lfi_payloads():
    global lfi_payloads
    with lfi_lock:
        if os.path.exists(LFI_PATH_FILE):
            with open(LFI_PATH_FILE, "r") as f:
                lfi_payloads = [line.strip() for line in f if line.strip()]
        else:
            lfi_payloads = []

load_user_paths()
load_lfi_payloads()

def normalize_paths(paths):
    expanded = set()
    for p in paths:
        expanded.add(p)
        if p.startswith('.'):
            expanded.add(p[1:])
        else:
            expanded.add('.' + p)
    return list(expanded)

DEFAULT_PATHS = normalize_paths(DEFAULT_PATHS)

def get_headers():
    headers = HEADERS_TEMPLATE.copy()
    headers['User-Agent'] = random.choice(USER_AGENTS)
    return headers

def is_alive(url, timeout=3):
    try:
        r = requests.get(url, timeout=timeout, headers=get_headers())
        return r.status_code < 500
    except:
        return False

def check_path(base_url, path, results, timeout=5):
    full_url = base_url.rstrip('/') + '/' + path.lstrip('/')
    try:
        r = requests.get(full_url, timeout=timeout, headers=get_headers(), allow_redirects=True)
        if r.status_code == 200:
            results.append(("FILE", full_url))
        elif r.status_code == 403:
            results.append(("FORBIDDEN", full_url))
    except:
        pass

def scan_site_paths(base_url, paths, threads=10):
    results = []
    q = Queue()
    for p in paths:
        q.put(p)
    def worker():
        while True:
            path = q.get()
            if path is None:
                break
            check_path(base_url, path, results)
            q.task_done()
    workers = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.start()
        workers.append(t)
    q.join()
    for _ in workers:
        q.put(None)
    for t in workers:
        t.join()
    return results

def crawl_site(start_url, max_pages=30, depth=2):
    visited = set()
    to_visit = [(start_url, 0)]
    found_urls = []
    while to_visit and len(visited) < max_pages:
        url, d = to_visit.pop(0)
        if d > depth:
            continue
        if url in visited:
            continue
        visited.add(url)
        try:
            r = requests.get(url, timeout=5, headers=get_headers())
            if r.status_code != 200:
                continue
            soup = BeautifulSoup(r.text, 'html.parser')
            found_urls.append(url)
            for link in soup.find_all('a', href=True):
                href = link['href']
                full = urllib.parse.urljoin(url, href)
                if full.startswith(('http://', 'https://')):
                    if full not in visited and full not in [v for v,_ in to_visit]:
                        to_visit.append((full, d+1))
        except:
            continue
    return found_urls

def detect_base64(text):
    pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    matches = re.findall(pattern, text)
    decoded = []
    for m in matches:
        try:
            dec = base64.b64decode(m).decode('utf-8', errors='ignore')
            if any(c.isprintable() for c in dec):
                decoded.append((m, dec[:200]))
        except:
            pass
    return decoded

def analyze_html(url, html):
    issues = []
    soup = BeautifulSoup(html, 'html.parser')
    if re.search(r'admin|dashboard|control', html, re.I):
        issues.append("Admin panel keywords found")
    if soup.find('input', {'type': 'file'}):
        issues.append("File upload form found")
    if 'base64' in html.lower():
        b64 = detect_base64(html)
        if b64:
            issues.append(f"Base64 data found: {b64[0][1] if b64 else ''}")
    if soup.find('input', {'type': 'password'}):
        issues.append("Login form found")
    return issues

def test_lfi_on_url(url, payloads):
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    vulnerable = []
    for param in query.keys():
        if param.lower() in LFI_PARAMS:
            for payload in payloads:
                new_query = query.copy()
                new_query[param] = [payload]
                new_qs = urllib.parse.urlencode(new_query, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
                try:
                    r = requests.get(test_url, timeout=5, headers=get_headers())
                    if 'root:x:' in r.text or 'bin/bash' in r.text or 'etc/passwd' in r.text:
                        vulnerable.append((param, payload, test_url))
                except:
                    pass
    return vulnerable

def scan_site(site):
    report = {"site": site, "files": [], "crawl_issues": [], "lfi": []}
    if not site.startswith(('http://', 'https://')):
        urls_to_try = ['http://' + site, 'https://' + site]
    else:
        urls_to_try = [site]
    base = None
    for url in urls_to_try:
        if is_alive(url):
            base = url
            break
    if not base:
        return None
    paths_to_scan = DEFAULT_PATHS.copy()
    with path_lock:
        if user_paths:
            paths_to_scan.extend(user_paths)
    files_found = scan_site_paths(base, paths_to_scan)
    if files_found:
        report["files"] = files_found
    if crawl_enabled:
        crawled = crawl_site(base)
        for page in crawled:
            try:
                r = requests.get(page, timeout=5, headers=get_headers())
                if r.status_code == 200:
                    issues = analyze_html(page, r.text)
                    if issues:
                        report["crawl_issues"].append({"url": page, "issues": issues})
                    with lfi_lock:
                        current_lfi = lfi_payloads.copy()
                    if current_lfi:
                        lfi_res = test_lfi_on_url(page, current_lfi)
                        if lfi_res:
                            report["lfi"].extend([{"url": page, "param": p, "payload": pay, "test_url": testu} for p, pay, testu in lfi_res])
            except:
                continue
    return report

def send_long_message(chat_id, text, parse_mode=None):
    if len(text) <= 4096:
        bot.send_message(chat_id, text, parse_mode=parse_mode)
    else:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(text)
            temp_path = f.name
        with open(temp_path, 'rb') as f:
            bot.send_document(chat_id, f, caption="Results (long message)")
        os.unlink(temp_path)

def scan_thread(sites, chat_id):
    with scan_semaphore:
        try:
            bot.send_message(chat_id, f"Started scanning {len(sites)} sites...")
            all_reports = []
            for site in sites:
                bot.send_message(chat_id, f"Scanning {site} ...")
                rep = scan_site(site)
                if rep is None:
                    bot.send_message(chat_id, f"{site} is unreachable.")
                else:
                    all_reports.append(rep)
                    msg = f"Results for {site}:\n"
                    if rep["files"]:
                        msg += "Sensitive files:\n" + "\n".join([f"{t}: {u}" for t,u in rep["files"]]) + "\n"
                    if rep["crawl_issues"]:
                        msg += "Crawl issues:\n"
                        for item in rep["crawl_issues"]:
                            msg += f"{item['url']}: {', '.join(item['issues'])}\n"
                    if rep["lfi"]:
                        msg += "LFI vulnerabilities:\n"
                        for l in rep["lfi"]:
                            msg += f"{l['test_url']} (param: {l['param']}, payload: {l['payload']})\n"
                    if not rep["files"] and not rep["crawl_issues"] and not rep["lfi"]:
                        msg += "Nothing found."
                    send_long_message(chat_id, msg)
            with open(REPORT_FILE, "w") as f:
                json.dump(all_reports, f, indent=2)
            bot.send_document(chat_id, open(REPORT_FILE, 'rb'), caption="Full JSON report")
        except Exception as e:
            bot.send_message(chat_id, f"Error during scan: {str(e)}")
        finally:
            if chat_id in active_scans:
                del active_scans[chat_id]

def polling_with_retry():
    while True:
        try:
            bot.infinity_polling(timeout=60, long_polling_timeout=60)
        except Exception as e:
            print(f"Polling error: {e}, retrying in 5 seconds...")
            time.sleep(5)

@bot.message_handler(commands=['start'])
def send_welcome(message):
    help_text = """
Welcome to Web Scanner Bot.

Commands:
- Send URLs (space separated) to scan them.
- crawl on/off : enable/disable crawling (default on)
- status : show current settings
- payloads : get sample LFI payloads (Google search link)

Created By @Red_Rooted_ghost
    """
    bot.reply_to(message, help_text)
    data = user_storage.decrypt()
    users = data.get("users", [])
    if message.chat.id not in users:
        users.append(message.chat.id)
        user_storage.encrypt({"users": users})

@bot.message_handler(func=lambda m: m.text and m.text.lower().startswith('crawl'))
def set_crawl(message):
    global crawl_enabled
    arg = message.text.strip().lower()[5:].strip()
    if arg == 'on':
        crawl_enabled = True
        bot.reply_to(message, "Crawling enabled.")
    elif arg == 'off':
        crawl_enabled = False
        bot.reply_to(message, "Crawling disabled.")
    else:
        bot.reply_to(message, f"Crawl is currently {'on' if crawl_enabled else 'off'}")

@bot.message_handler(func=lambda m: m.text and m.text == 'status')
def status(message):
    with path_lock:
        pcount = len(user_paths)
    with lfi_lock:
        lcount = len(lfi_payloads)
    status_msg = f"""
Settings:
- Crawl enabled: {crawl_enabled}
- Custom paths: {pcount}
- LFI payloads: {lcount}
- Default paths: {len(DEFAULT_PATHS)}
    """
    bot.reply_to(message, status_msg)

@bot.message_handler(func=lambda m: m.text and m.text == 'payloads')
def payloads_help(message):
    msg = "Sample LFI payloads (Google search):\nhttps://www.google.com/search?q=LFI+payloads+github"
    bot.reply_to(message, msg)

@bot.message_handler(func=lambda m: True)
def handle_sites(message):
    chat_id = message.chat.id
    if chat_id in active_scans:
        bot.reply_to(message, "You already have a scan in progress. Please wait.")
        return
    text = message.text.strip()
    sites = text.split()
    if not sites:
        bot.reply_to(message, "Send space-separated URLs.")
        return
    t = threading.Thread(target=scan_thread, args=(sites, chat_id))
    active_scans[chat_id] = t
    t.start()

if __name__ == "__main__":
    print("Bot started. Waiting for messages...")
    polling_with_retry()
