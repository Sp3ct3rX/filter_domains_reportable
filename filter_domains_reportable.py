#!/usr/bin/env python3
# ------------------------------------------------------------
# Project: filter domains reportable
# Author: Sp3ct3r X
# Contact: sp3ct3r@example.com
# GPG-Fingerprint: ABCD 1234 EFGH 5678 IJKL 90MN OPQR STUV WXYZ 1234
# License: Proprietary (All rights reserved) or MIT (choose)
# Note: Verify digital signature: gpg --verify file.sig file
# ------------------------------------------------------------
"""
filter_domains_reportable.py

Async domain filter with colored verbose logs, tqdm progress and HTML report output.

Requirements:
    pip install aiohttp aiofiles colorama jinja2 tqdm

Usage:
    python filter_domains_reportable.py --input sample.txt --apikey YOURKEY \
        --out-kept kept.csv --out-rej rejected.csv --concurrency 20 --rate 10 \
        --cache cache.json --report report.html --verbose

This Script Created by Sp3ct3r X 
"""

import argparse
import asyncio
import aiohttp
import aiofiles
import json
import time
import urllib.parse
from pathlib import Path
from typing import Optional, Dict, Tuple
import re
import random
from datetime import datetime, timezone
import logging
from jinja2 import Template
from colorama import init as colorama_init, Fore, Style
from tqdm import tqdm

colorama_init(autoreset=True)

# ----------------- Logging helpers -----------------
plain_logger = logging.getLogger("plain")
plain_logger.setLevel(logging.INFO)
if not plain_logger.handlers:
    ph = logging.FileHandler("run_plain.log", encoding='utf-8')
    ph.setFormatter(logging.Formatter("%(asctime)s\t%(levelname)s\t%(message)s"))
    plain_logger.addHandler(ph)

def colored_log(level: str, msg: str, *, also_plain: bool = True):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    level_l = (level or "info").lower()
    if level_l == 'info':
        color = Fore.CYAN
        if also_plain: plain_logger.info(msg)
    elif level_l == 'success':
        color = Fore.GREEN
        if also_plain: plain_logger.info("SUCCESS: " + msg)
    elif level_l in ('warn', 'warning'):
        color = Fore.YELLOW
        if also_plain: plain_logger.warning(msg)
    elif level_l == 'error':
        color = Fore.RED
        if also_plain: plain_logger.error(msg)
    elif level_l == 'debug':
        color = Fore.MAGENTA
        if also_plain: plain_logger.debug(msg)
    else:
        color = Fore.WHITE
        if also_plain: plain_logger.info(msg)
    print(f"{color}{Style.BRIGHT}[{level_l.upper()}] {ts} - {msg}{Style.RESET_ALL}")

# ----------------- Helpers -----------------
DOMAIN_RE = re.compile(r'^(?:https?://)?(?:www\.)?([^/:?#]+)')

def extract_domain(s: str) -> Optional[str]:
    if not s:
        return None
    s = s.strip()
    m = DOMAIN_RE.match(s)
    if m:
        return m.group(1).lower()
    try:
        p = urllib.parse.urlparse(s if s.startswith('http') else ('http://' + s))
        return p.hostname.lower() if p.hostname else None
    except Exception:
        return None

def passes_filters(api_obj: dict) -> Tuple[bool, str]:
    try:
        def getv(k):
            if not api_obj:
                return None
            for kk in (k, k.lower(), k.upper()):
                if kk in api_obj:
                    return api_obj.get(kk)
            return api_obj.get(k, None)

        tf_raw = getv('majesticTF')
        mozspam_raw = getv('mozSpam')
        mozda_raw = getv('mozDA')

        def to_num(x):
            if x is None or x == '':
                return None
            try:
                return float(x)
            except:
                try:
                    return float(str(x).strip())
                except:
                    return None

        majesticTF = to_num(tf_raw)
        mozSpam = to_num(mozspam_raw)
        mozDA = to_num(mozda_raw)

        if majesticTF is None or majesticTF < 40:
            return False, f'majesticTF<{40} ({majesticTF})'
        if mozSpam is not None and mozSpam > 30:
            return False, f'mozSpam>{30} ({mozSpam})'
        if mozDA is None or mozDA < 20:
            return False, f'mozDA<{20} ({mozDA})'
        return True, ''
    except Exception as e:
        return False, f'filter_exception:{e}'

# ----------------- Async DomainFilter class -----------------
class DomainFilter:
    def __init__(self, apikey: str, concurrency: int = 20, rate_per_sec: float = 10.0, cache_path: str = 'cache.json', session_timeout: int = 30):
        self.apikey = apikey
        self.sema = asyncio.Semaphore(concurrency)
        self.rate_per_sec = rate_per_sec
        self.cache_path = Path(cache_path)
        self.session_timeout = session_timeout
        self._lock = asyncio.Lock()
        self._last_call = 0.0
        self._token_interval = 1.0 / max(rate_per_sec, 0.0001)
        self.cache: Dict[str, dict] = {}
        if self.cache_path.exists():
            try:
                self.cache = json.loads(self.cache_path.read_text(encoding='utf-8') or '{}')
                colored_log('info', f"Loaded cache with {len(self.cache)} entries from {self.cache_path}")
            except Exception:
                self.cache = {}

    async def save_cache(self):
        async with self._lock:
            try:
                self.cache_path.write_text(json.dumps(self.cache, ensure_ascii=False, indent=2), encoding='utf-8')
                colored_log('info', f"Saved cache to {self.cache_path} ({len(self.cache)} entries)")
            except Exception as e:
                colored_log('error', f"Failed to write cache: {e}")

    async def throttle(self):
        now = time.monotonic()
        wait = self._last_call + self._token_interval - now
        if wait > 0:
            await asyncio.sleep(wait + random.uniform(0, 0.01))
        self._last_call = time.monotonic()

    async def fetch_api(self, session: aiohttp.ClientSession, domain: str) -> Dict:
        if domain in self.cache:
            return {'cached': True, 'data': self.cache[domain]}
        url = f"https://ns522084.ip-158-69-124.net/api/checkDomain.php?apikey={self.apikey}&domain={urllib.parse.quote(domain)}&app=sdg"
        tries = 0
        max_tries = 4
        backoff_base = 1.5
        while tries < max_tries:
            tries += 1
            try:
                await self.throttle()
                async with session.get(url, timeout=self.session_timeout) as r:
                    text = await r.text()
                    try:
                        data = json.loads(text)
                    except Exception:
                        # try to extract first JSON object if noise around it
                        try:
                            start = text.find('{')
                            end = text.rfind('}')
                            if start != -1 and end != -1 and end > start:
                                data = json.loads(text[start:end+1])
                            else:
                                data = {}
                        except Exception:
                            data = {}
                    self.cache[domain] = data
                    return {'cached': False, 'data': data, 'status': r.status}
            except asyncio.TimeoutError:
                colored_log('warn', f"Timeout for {domain} (try {tries}/{max_tries})")
            except aiohttp.ClientError as e:
                colored_log('warn', f"Client error for {domain}: {e} (try {tries}/{max_tries})")
            except Exception as e:
                colored_log('warn', f"Other error for {domain}: {e} (try {tries}/{max_tries})")
            await asyncio.sleep((backoff_base ** tries) + random.uniform(0, 0.5))
        return {'cached': False, 'data': None, 'error': 'failed_after_retries'}

    async def process_domain(self, session: aiohttp.ClientSession, domain: str) -> Tuple[str, dict, bool, str]:
        async with self.sema:
            colored_log('debug', f"Processing domain: {domain}")
            result = await self.fetch_api(session, domain)
            if result.get('data') is None:
                colored_log('error', f"API failed for {domain}: {result.get('error')}")
                return domain, {}, False, f"api_error:{result.get('error')}"
            api_obj = result.get('data') or {}
            ok, reason = passes_filters(api_obj)
            if ok:
                colored_log('success', f"Kept: {domain} (majesticTF={api_obj.get('majesticTF')}, mozSpam={api_obj.get('mozSpam')}, mozDA={api_obj.get('mozDA')})")
            else:
                colored_log('warn', f"Rejected: {domain} -> {reason}")
            return domain, api_obj, ok, reason

# ----------------- HTML report template and writer -----------------
HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Domain Filter Report - {{ ts }}</title>
  <style>
    body { font-family: Arial, Helvetica, sans-serif; margin: 16px; }
    h1 { color:#2b6cb0; }
    table { width:100%; border-collapse: collapse; margin-bottom: 18px; }
    th, td { padding: 8px 10px; border: 1px solid #ddd; text-align:left; font-size:13px;}
    th { background:#f4f6fb; color:#333; }
    tr.success { background: #e6ffed; }        /* light green */
    tr.reject { background: #fff7e6; }         /* light yellow */
    tr.error { background: #ffecec; }          /* light red */
    tr.alt { background:#fbfbfc; }
    .small { font-size:12px; color:#666; }
    .reason { font-weight:600; color:#444; }
    .meta { margin-bottom: 12px; }
    .badge { display:inline-block; padding:4px 8px; border-radius:6px; font-size:12px; color:#fff; }
    .badge.kept { background:#38a169; } /* green */
    .badge.rej { background:#d69e2e; }  /* gold */
    .badge.err { background:#e53e3e; }  /* red */
    pre { white-space: pre-wrap; word-wrap: break-word; max-height: 240px; overflow:auto; }
  </style>
</head>
<body>
  <h1>Domain Filter Report</h1>
  <div class="meta small">Generated: {{ ts }} &nbsp; | &nbsp; Total checked: {{ total }} &nbsp; | &nbsp; Kept: <span class="badge kept">{{ kept_count }}</span> &nbsp; Rejected: <span class="badge rej">{{ rej_count }}</span></div>

  <h2>Kept (passed all filters)</h2>
  <table>
    <thead><tr><th>#</th><th>domain</th><th>majesticTF</th><th>mozSpam</th><th>mozDA</th><th>raw</th></tr></thead>
    <tbody>
    {% for r in kept %}
      <tr class="success"><td>{{ loop.index }}</td><td>{{ r.domain }}</td><td>{{ r.majesticTF }}</td><td>{{ r.mozSpam }}</td><td>{{ r.mozDA }}</td><td><pre>{{ r.raw }}</pre></td></tr>
    {% endfor %}
    </tbody>
  </table>

  <h2>Rejected (with reasons)</h2>
  <table>
    <thead><tr><th>#</th><th>domain</th><th>reason</th><th>majesticTF</th><th>mozSpam</th><th>mozDA</th></tr></thead>
    <tbody>
    {% for r in rej %}
      {% set cls = 'reject' %}
      {% if 'api_error' in r.reason %}{% set cls='error' %}{% endif %}
      <tr class="{{ cls }}"><td>{{ loop.index }}</td><td>{{ r.domain }}</td><td class="reason">{{ r.reason }}</td><td>{{ r.majesticTF }}</td><td>{{ r.mozSpam }}</td><td>{{ r.mozDA }}</td></tr>
    {% endfor %}
    </tbody>
  </table>

  <h2>Notes / Legend</h2>
  <p class="small">Rows colored green =&gt; Kept. Yellow =&gt; Rejected by filters. Red =&gt; API/parse errors.</p>
</body>
</html>
"""

def write_html_report(out_html_path: str, kept_rows: list, rej_rows: list):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tpl = Template(HTML_TEMPLATE)
    html = tpl.render(ts=ts, total=len(kept_rows)+len(rej_rows), kept=kept_rows, rej=rej_rows, kept_count=len(kept_rows), rej_count=len(rej_rows))
    Path(out_html_path).write_text(html, encoding='utf-8')
    colored_log('info', f"HTML report written to {out_html_path}")

# ----------------- Main flow (with robust checks, tqdm progress) -----------------
async def run_filter(input_file: str, apikey: str, out_kept: str, out_rejected: str,
                     concurrency: int, rate: float, cache_file: str, report_html: str, verbose: bool):

    df = DomainFilter(apikey=apikey, concurrency=concurrency, rate_per_sec=rate, cache_path=cache_file)
    conn = aiohttp.TCPConnector(limit=0)
    timeout = aiohttp.ClientTimeout(total=None)
    kept_rows = []
    rej_rows = []
    errors = 0

    input_path = Path(input_file)
    if not input_path.exists():
        colored_log('error', f"Input file not found: {input_file}")
        return

    # read input
    raw_lines = []
    async with aiofiles.open(input_file, mode='r', encoding='utf-8', errors='ignore') as f:
        async for line in f:
            if line.strip():
                raw_lines.append(line.strip())
    if not raw_lines:
        colored_log('error', f"Input file is empty: {input_file}")
        return

    # extract domains
    domains = []
    for line in raw_lines:
        d = extract_domain(line)
        if d:
            domains.append(d)
    if not domains:
        colored_log('error', "No valid domains parsed from input file (check format).")
        return

    # dedupe preserving order
    seen = set()
    uniq = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            uniq.append(d)

    total = len(uniq)
    colored_log('info', f"Unique domains to check: {total} (concurrency={concurrency}, rate={rate}/s)")

    kept_path = Path(out_kept)
    rej_path = Path(out_rejected)
    kept_f = kept_path.open('w', encoding='utf-8')
    kept_f.write("domain,majesticTF,mozSpam,mozDA,raw\n")
    rej_f = rej_path.open('w', encoding='utf-8')
    rej_f.write("domain,reason,majesticTF,mozSpam,mozDA,raw\n")

    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        tasks = [asyncio.create_task(df.process_domain(session, domain)) for domain in uniq]

        pbar = tqdm(total=total, unit="dom") if verbose else None

        for coro in asyncio.as_completed(tasks):
            try:
                domain, api_obj, ok, reason = await coro
            except Exception as e:
                errors += 1
                colored_log('error', f"Unhandled exception for a task: {e}")
                if pbar:
                    pbar.update(1)
                continue

            majesticTF = api_obj.get('majesticTF') if api_obj else ''
            mozSpam = api_obj.get('mozSpam') if api_obj else ''
            mozDA = api_obj.get('mozDA') if api_obj else ''
            raw = json.dumps(api_obj, ensure_ascii=False)

            if ok:
                kept_f.write(f"{domain},{majesticTF},{mozSpam},{mozDA},{raw}\n")
                kept_rows.append({'domain': domain, 'majesticTF': majesticTF, 'mozSpam': mozSpam, 'mozDA': mozDA, 'raw': raw})
            else:
                rej_f.write(f"{domain},{reason},{majesticTF},{mozSpam},{mozDA},{raw}\n")
                rej_rows.append({'domain': domain, 'reason': reason, 'majesticTF': majesticTF, 'mozSpam': mozSpam, 'mozDA': mozDA, 'raw': raw})
                if reason and reason.startswith('api_error'):
                    errors += 1

            if pbar:
                pbar.update(1)
            else:
                processed = len(kept_rows) + len(rej_rows)
                if total <= 50:
                    colored_log('info', f"[{processed}/{total}] processed: {domain}")
                elif processed % max(1, total//20) == 0:
                    colored_log('info', f"[{processed}/{total}] processed")

    kept_f.close()
    rej_f.close()

    await df.save_cache()

    write_html_report(report_html, kept_rows, rej_rows)

    summary_path = Path(report_html).with_suffix('.summary.txt')
    with open(summary_path, 'w', encoding='utf-8') as sf:
        sf.write(f"Generated: {datetime.now(timezone.utc).isoformat()}Z\n")
        sf.write(f"Total checked: {len(kept_rows)+len(rej_rows)}\n")
        sf.write(f"Kept: {len(kept_rows)}\n")
        sf.write(f"Rejected: {len(rej_rows)}\n")
        sf.write(f"API errors: {errors}\n")

    colored_log('info', f"Summary written to {summary_path}")
    colored_log('success', f"Process complete. Kept: {len(kept_rows)}, Rejected: {len(rej_rows)}, Errors: {errors}")

# ----------------- CLI -----------------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--input', '-i', required=True, help='Input file with domains or URLs, one per line')
    p.add_argument('--apikey', required=True, help='API key for domain check API')
    p.add_argument('--out-kept', default='kept.csv')
    p.add_argument('--out-rejected', default='rejected.csv')
    p.add_argument('--concurrency', type=int, default=20)
    p.add_argument('--rate', type=float, default=10.0, help='max requests per second')
    p.add_argument('--cache', default='cache.json')
    p.add_argument('--report', default='report.html')
    p.add_argument('--verbose', action='store_true', help='Enable verbose console output and progress bar')
    return p.parse_args()

if __name__ == '__main__':
    args = parse_args()
    try:
        asyncio.run(run_filter(args.input, args.apikey, args.out_kept, args.out_rejected,
                               args.concurrency, args.rate, args.cache, args.report, args.verbose))
    except KeyboardInterrupt:
        colored_log('error', 'Interrupted by user')


