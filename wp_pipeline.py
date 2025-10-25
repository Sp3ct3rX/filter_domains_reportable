#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wp_pipeline.py

Two subcommands:
  - preprocess : normalize huge URL:user:pass file -> unique domain list (one per line)
  - detect     : detect WordPress domains from a cleaned domain list with resume, sqlite cache,
                 scoring-based detection, parking detection, and auto-sleep-on-block.

Usage examples:
  python3 wp_pipeline.py preprocess --input big_input.txt --out domains_uniq.txt --workers 4 --dedupe
  python3 wp_pipeline.py detect --input domains_uniq.txt --out wp_urls.txt --db wp_cache.db --concurrency 80 --rate 20 --timeout 10 --limit 48000 --sleep-on-block 900 --verbose

Requires:
  pip install aiohttp aiofiles aiosqlite tldextract tqdm colorama
"""
import argparse
import asyncio
import aiofiles
import aiohttp
import aiosqlite
import json
import time
import random
import re
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from colorama import init as colorama_init, Fore, Style
from tqdm import tqdm

colorama_init(autoreset=True)

# ---------- Helpers ----------
def now_ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def log(level: str, msg: str):
    colmap = {'info': Fore.CYAN, 'success': Fore.GREEN, 'warn': Fore.YELLOW, 'error': Fore.RED, 'debug': Fore.MAGENTA}
    col = colmap.get(level, Fore.WHITE)
    print(f"{col}{Style.BRIGHT}[{level.upper()}] {now_ts()} - {msg}{Style.RESET_ALL}")

# ---------- Domain extraction & normalization ----------
# Prefer tldextract for correct eTLD+1 extraction; fallback to simple heuristic.
try:
    import tldextract
    def get_registrable(domain_or_url: str) -> Optional[str]:
        if not domain_or_url:
            return None
        domain_or_url = domain_or_url.strip()
        # if includes protocol or path, parse and take hostname
        if '://' in domain_or_url or '/' in domain_or_url:
            try:
                p = urllib.parse.urlparse(domain_or_url if '://' in domain_or_url else 'http://' + domain_or_url)
                host = p.hostname or domain_or_url
            except:
                host = domain_or_url
        else:
            host = domain_or_url
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
        return host.lower()
except Exception:
    log('warn', "tldextract not available; using fallback registrable domain extractor (may be less accurate).")
    def get_registrable(domain_or_url: str) -> Optional[str]:
        if not domain_or_url:
            return None
        s = domain_or_url.strip()
        # remove protocol
        if '://' in s:
            try:
                s = urllib.parse.urlparse(s).hostname or s
            except:
                pass
        # remove path/port
        s = s.split('/')[0].split(':')[0]
        parts = s.split('.')
        if len(parts) >= 2:
            # naive: last two labels
            return (parts[-2] + '.' + parts[-1]).lower()
        return s.lower()

# ---------- Preprocess command ----------
async def preprocess_command(input_path: str, out_path: str, dedupe: bool = True):
    """
    Read input lines like URL:user:pass and emit one registrable domain per line.
    Uses streaming, memory-friendly approach.
    """
    input_p = Path(input_path)
    if not input_p.exists():
        log('error', f"Input not found: {input_path}")
        return
    out_p = Path(out_path)
    tmp_out = out_p.with_suffix('.tmp')
    seen = set()
    count = 0
    async with aiofiles.open(input_path, mode='r', encoding='utf-8', errors='ignore') as inf:
        async with aiofiles.open(tmp_out, mode='w', encoding='utf-8') as outf:
            async for line in inf:
                line = line.strip()
                if not line:
                    continue
                # Expect format URL:user:pass (but safe-guard)
                parts = line.split(':')
                if len(parts) >= 1:
                    url_part = parts[0].strip()
                else:
                    url_part = line
                dom = get_registrable(url_part)
                if not dom:
                    continue
                if dedupe:
                    if dom in seen:
                        continue
                    seen.add(dom)
                await outf.write(dom + '\n')
                count += 1
                if count % 10000 == 0:
                    log('info', f"Processed {count} lines...")
    # atomically move
    tmp_out.replace(out_p)
    log('success', f"Preprocess done. Output: {out_p}  ({len(seen) if dedupe else count} lines)")

# ---------- Detection: database schema & utilities ----------
CREATE_DOMAINS_SQL = """
CREATE TABLE IF NOT EXISTS domains (
  domain TEXT PRIMARY KEY,
  processed INTEGER DEFAULT 0, -- 0=not processed, 1=done
  score INTEGER DEFAULT 0,
  final_url TEXT,
  status TEXT,
  evidence TEXT,
  last_checked TEXT
);
"""

# keywords and patterns for parking/for-sale detection
PARKING_KEYWORDS = [
    'parked', 'domain for sale', 'this domain is for sale', 'buy this domain',
    'domain parking', 'sedo', 'parkingcrew', 'godaddy', 'namecheap', 'tucows',
    'buy domain', 'auction', 'parkingpage', 'this domain may be for sale'
]
PARKING_HOST_INDICATORS = [
    'sedo.com', 'parkingcrew.net', 'parkingcrew.com', 'sedocdn', 'domainsponsor', 'dorik', 'parklogic',
    'parking', 'domaincontrol', 'bnc.lt', 'pages.dreamhost', 'sitelutions'
]

# detection scoring thresholds and weights (tune if necessary)
WEIGHTS = {
    'wp_json_valid': 6,
    'wp_content_link': 4,
    'wp_login_form': 4,
    'xmlrpc_status': 3,
    'meta_generator': 2,
    'header_pingback': 2,
}
THRESHOLD = 5  # must reach to be positive

USER_AGENT = "Mozilla/5.0 (compatible; WP-Detector/1.0; +https://example.com/bot)"
HEAD_READ_BYTES = 65536
SMALL_READ = 4096

# helper to mark block conditions
def is_blocking_status(status: int, body_snippet: str) -> bool:
    if status == 429:
        return True
    b = (body_snippet or '').lower()
    if 'captcha' in b or 'access denied' in b or 'please verify' in b or 'are you human' in b:
        return True
    return False

def looks_like_parking(host: str, body_snippet: str) -> bool:
    b = (body_snippet or '').lower()
    for kw in PARKING_KEYWORDS:
        if kw in b:
            return True
    # final host check
    for ph in PARKING_HOST_INDICATORS:
        if ph in host.lower():
            return True
    return False

# is_valid_wp_json similar to earlier
def is_valid_wp_json(obj) -> bool:
    if not isinstance(obj, dict):
        return False
    for key in ('routes', 'namespaces', 'authentication'):
        if key in obj:
            return True
    return False

# ---------- Detector class (async) ----------
class Throttled:
    def __init__(self, rate_per_sec: float, timeout: int):
        self._lock = asyncio.Lock()
        self._last = 0.0
        self._interval = 1.0 / max(rate_per_sec, 0.0001)
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.connector = aiohttp.TCPConnector(limit=0)

    async def wait_token(self):
        async with self._lock:
            now = time.monotonic()
            wait = self._last + self._interval - now
            if wait > 0:
                await asyncio.sleep(wait + random.uniform(0, 0.01))
            self._last = time.monotonic()

async def ensure_db(db_path: str):
    db = await aiosqlite.connect(db_path)
    await db.execute(CREATE_DOMAINS_SQL)
    await db.commit()
    return db

# core detect function for one host (scoring-based)
async def detect_host(session: aiohttp.ClientSession, th: Throttled, host: str):
    """
    Returns dict with result: {is_wp:bool, score:int, final_url, evidence:list, parking:bool, block_suspected:bool}
    """
    evidence = []
    score = 0
    final_url = None
    block_suspected = False
    headers = {'User-Agent': USER_AGENT, 'Accept': '*/*'}

    schemes = ['https', 'http']
    for scheme in schemes:
        root = f"{scheme}://{host}/"

        # 1) wp-json (strongest)
        try:
            await th.wait_token()
            url = f"{scheme}://{host}/wp-json/"
            async with session.get(url, headers=headers, allow_redirects=True, timeout=th.timeout) as r:
                status = r.status
                text = ''
                try:
                    text = await r.text()
                except:
                    text = ''
                evidence.append({'url': url, 'status': status})
                if is_blocking_status(status, text):
                    block_suspected = True
                if status == 200:
                    try:
                        js = json.loads(text)
                        if is_valid_wp_json(js):
                            evidence.append({'reason': 'wp-json_valid'})
                            score += WEIGHTS['wp_json_valid']
                            final_url = str(r.url)
                            # high-confidence -> return early
                            return {'is_wp': True, 'score': score, 'final_url': final_url, 'evidence': evidence, 'parking': False, 'block': block_suspected}
                    except:
                        pass
        except Exception as e:
            evidence.append({'url': url, 'error': str(e)})

        # 2) HEAD /wp-content/ (cheap)
        try:
            await th.wait_token()
            wc = f"{scheme}://{host}/wp-content/"
            async with session.head(wc, headers=headers, allow_redirects=True, timeout=th.timeout) as r2:
                s2 = r2.status
                evidence.append({'url': wc, 'status': s2})
                if s2 in (200, 301, 302, 403):
                    score += WEIGHTS['wp_content_link']
                    evidence.append({'reason': 'wp-content_head'})
        except Exception as e:
            evidence.append({'url': wc, 'error': str(e)})

        # 3) xmlrpc.php & wp-login.php checks
        for endpoint in ('/xmlrpc.php', '/wp-login.php'):
            try:
                await th.wait_token()
                ep = f"{scheme}://{host}{endpoint}"
                async with session.get(ep, headers=headers, allow_redirects=True, timeout=th.timeout) as r3:
                    s3 = r3.status
                    snippet = ''
                    try:
                        snippet = (await r3.content.read(SMALL_READ)).decode('utf-8', errors='ignore')
                    except:
                        snippet = ''
                    evidence.append({'url': ep, 'status': s3})
                    if is_blocking_status(s3, snippet):
                        block_suspected = True
                    if endpoint == '/xmlrpc.php' and s3 in (200, 405):
                        score += WEIGHTS['xmlrpc_status']
                        evidence.append({'reason': f'xmlrpc_{s3}'})
                    if endpoint == '/wp-login.php' and s3 in (200, 302):
                        # check for login form markers
                        if 'wp-login' in snippet.lower() or 'name="log"' in snippet.lower() or 'id="loginform"' in snippet.lower():
                            score += WEIGHTS['wp_login_form']
                            evidence.append({'reason': 'wp-login-form'})
            except Exception as e:
                evidence.append({'url': ep, 'error': str(e)})

        # 4) root GET limited bytes: check for wp-content links & meta generator & parking indicators
        try:
            await th.wait_token()
            async with session.get(root, headers=headers, allow_redirects=True, timeout=th.timeout) as r4:
                s4 = r4.status
                body = ''
                try:
                    body = (await r4.content.read(HEAD_READ_BYTES)).decode('utf-8', errors='ignore')
                except:
                    body = ''
                evidence.append({'url': root, 'status': s4})
                if is_blocking_status(s4, body):
                    block_suspected = True
                # detect wp-content links more reliably (href/src containing wp-)
                if re.search(r'["\'](?:https?:)?//[^"\']*/[^"\']*wp-(?:content|includes)[^"\']*["\']', body, re.IGNORECASE):
                    score += WEIGHTS['wp_content_link']
                    evidence.append({'reason': 'wp-content-in-html'})
                # meta generator
                mg = re.search(r'<meta[^>]*name=["\']?generator["\']?[^>]*content=["\']?([^"\'>]+)', body, re.IGNORECASE)
                if mg and 'wordpress' in (mg.group(1) or '').lower():
                    score += WEIGHTS['meta_generator']
                    evidence.append({'reason': f'meta_generator:{mg.group(1)}'})
                # header x-pingback
                for hn, hv in r4.headers.items():
                    if not hv:
                        continue
                    if hn.lower() == 'x-pingback' and 'xmlrpc.php' in str(hv).lower():
                        score += WEIGHTS['header_pingback']
                        evidence.append({'reason': 'header_x_pingback'})
                # parking detection by content / final host
                final = str(r4.url)
                final_url = final
                if looks_like_parking(final, body):
                    evidence.append({'reason': 'parking_detected'})
                    return {'is_wp': False, 'score': score, 'final_url': final_url, 'evidence': evidence, 'parking': True, 'block': block_suspected}
                # assign final_url if not set
                if not final_url:
                    final_url = final
        except Exception as e:
            evidence.append({'url': root, 'error': str(e)})

        # if at any point score >= threshold we can claim WP
        if score >= THRESHOLD:
            return {'is_wp': True, 'score': score, 'final_url': (final_url or root), 'evidence': evidence, 'parking': False, 'block': block_suspected}

    # final decision after both schemes
    return {'is_wp': score >= THRESHOLD, 'score': score, 'final_url': (final_url or f"https://{host}/"), 'evidence': evidence, 'parking': False, 'block': block_suspected}

# ---------- Detection command (main) ----------
async def detect_command(input_path: str, out_path: str, db_path: str,
                         concurrency: int = 80, rate: float = 20.0, timeout: int = 10,
                         limit: int = 48000, sleep_on_block: int = 900, verbose: bool = False):
    """
    Read cleaned domain list (one registrable domain per line), detect WP domains, write final URLs
    to out_path (one per line). Uses sqlite DB to store progress and resume.
    """
    # prepare DB
    db = await ensure_db(db_path)

    # ensure output file exists (or create)
    out_p = Path(out_path)
    if not out_p.exists():
        out_p.touch()

    # load existing found final URLs to avoid duplicates
    seen_final = set()
    async with aiofiles.open(str(out_p), mode='r', encoding='utf-8', errors='ignore') as f:
        async for line in f:
            seen_final.add(line.strip())

    # create throttled session and aiohttp session
    th = Throttled(rate_per_sec=rate, timeout=timeout)
    headers = {'User-Agent': USER_AGENT, 'Accept': '*/*'}

    # producer: stream the input file and for each domain insert into DB if missing and enqueue if not processed
    q = asyncio.Queue(maxsize=concurrency * 4)

    async def producer():
        inserted = 0
        queued = 0
        async with aiofiles.open(input_path, mode='r', encoding='utf-8', errors='ignore') as inf:
            async for line in inf:
                d = line.strip()
                if not d:
                    continue
                # check DB to skip processed
                async with db.execute("SELECT processed FROM domains WHERE domain = ?", (d,)) as cur:
                    row = await cur.fetchone()
                if row:
                    # already in db; if processed==1 skip
                    if row[0] == 1:
                        continue
                else:
                    # insert placeholder (processed=0)
                    await db.execute("INSERT OR REPLACE INTO domains(domain, processed) VALUES (?,0)", (d,))
                    await db.commit()
                    inserted += 1
                # enqueue for processing (we still check processed status in workers)
                await q.put(d)
                queued += 1
                if queued % 1000 == 0 and verbose:
                    log('info', f"Queued {queued} domains...")
                # if limit near reached, we still enqueue all but workers will stop at limit
        # after input done, put sentinel
        for _ in range(concurrency):
            await q.put(None)
        if verbose:
            log('info', f"Producer finished. new inserts: {inserted}, queued: {queued}")

    # worker
    consecutive_block_counter = 0
    BLOCK_THRESHOLD = 10  # if 10 consecutive blocking events, sleep
    found_counter = 0

    async def worker_task(idx: int):
        nonlocal consecutive_block_counter, found_counter
        async with aiohttp.ClientSession(connector=th.connector, timeout=th.timeout, headers=headers) as session:
            while True:
                d = await q.get()
                if d is None:
                    q.task_done()
                    break
                # check if already processed (race conditions possible)
                async with db.execute("SELECT processed FROM domains WHERE domain = ?", (d,)) as cur:
                    row = await cur.fetchone()
                if row and row[0] == 1:
                    q.task_done()
                    continue
                try:
                    res = await detect_host(session, th, d)
                except Exception as e:
                    log('error', f"Worker {idx}: exception {e} for {d}")
                    # transient exception -> requeue a few times? for simplicity mark as not processed and move on
                    await db.execute("UPDATE domains SET processed=1, status=?, last_checked=? WHERE domain=?", (f"exception:{e}", now_ts(), d))
                    await db.commit()
                    q.task_done()
                    continue

                # if block suspected increment counter
                if res.get('block'):
                    consecutive_block_counter += 1
                else:
                    consecutive_block_counter = 0

                # parking detection override (if parking true -> non-wp)
                if res.get('parking'):
                    await db.execute("UPDATE domains SET processed=1, score=?, final_url=?, status=?, evidence=?, last_checked=? WHERE domain=?",
                                     (res.get('score') or 0, res.get('final_url'), 'parking', json.dumps(res.get('evidence')), now_ts(), d))
                    await db.commit()
                    if verbose:
                        log('info', f"Worker {idx}: {d} detected as parking -> skipped")
                    q.task_done()
                    continue

                # successful detection
                is_wp = bool(res.get('is_wp'))
                score = int(res.get('score') or 0)
                final_url = res.get('final_url') or f"https://{d}/"
                evidence = res.get('evidence') or []

                # if blocked heavily, store and sleep (persist DB then sleep)
                if consecutive_block_counter >= BLOCK_THRESHOLD:
                    log('warn', f"Detected {consecutive_block_counter} consecutive blocking events. Saving DB and sleeping for {sleep_on_block} seconds...")
                    await db.commit()
                    await asyncio.sleep(sleep_on_block)
                    consecutive_block_counter = 0

                # Save to DB
                await db.execute("UPDATE domains SET processed=1, score=?, final_url=?, status=?, evidence=?, last_checked=? WHERE domain=?",
                                 (score, final_url, ('wp' if is_wp else 'not_wp'), json.dumps(evidence, ensure_ascii=False), now_ts(), d))
                await db.commit()

                # if WP and not seen, append to out file
                if is_wp:
                    # check final host to ensure not redirect to parking/reg page
                    parsed = urllib.parse.urlparse(final_url)
                    host_final = parsed.hostname or ''
                    # if final host looks like parking providers, treat as not WP
                    parking_flag = looks_like_parking(host_final, ' '.join(str(x) for x in evidence))
                    if parking_flag:
                        if verbose:
                            log('info', f"Worker {idx}: {d} final_url {final_url} looks like parking -> skipping")
                    else:
                        if final_url not in seen_final:
                            async with aiofiles.open(out_path, mode='a', encoding='utf-8') as outf:
                                await outf.write(final_url.rstrip('/') + "\n")
                            seen_final.add(final_url)
                            found_counter += 1
                            if verbose:
                                log('success', f"[{found_counter}] WP -> {final_url} (score={score})")
                else:
                    if verbose:
                        log('debug', f"Worker {idx}: {d} -> not WP (score={score})")

                q.task_done()

                # stop when limit reached across workers
                if found_counter >= limit:
                    # flush queue by pushing None sentinels for everyone
                    for _ in range(concurrency):
                        await q.put(None)
                    break

    # run producer + workers
    prod = asyncio.create_task(producer())
    workers = [asyncio.create_task(worker_task(i)) for i in range(concurrency)]
    await asyncio.gather(prod)
    await q.join()
    # cancel workers if still alive
    for w in workers:
        try:
            w.cancel()
        except:
            pass

    await db.close()
    log('success', f"Detection finished. Found WP: {len(seen_final)} (limit {limit}). Output: {out_path}")

# ---------- CLI & main ----------
def build_parser():
    p = argparse.ArgumentParser(prog='wp_pipeline.py', description='Preprocess and detect WordPress domains pipeline.')
    sub = p.add_subparsers(dest='cmd', required=True)

    # preprocess
    pp = sub.add_parser('preprocess', help='Extract registrable domains from big input file.')
    pp.add_argument('--input', '-i', required=True, help='Input file (URL:user:pass per line)')
    pp.add_argument('--out', '-o', required=True, help='Output clean domain file (one registrable domain per line)')
    pp.add_argument('--dedupe', action='store_true', default=True, help='Deduplicate output')
    pp.add_argument('--workers', type=int, default=4, help='(Unused) for future parallel parsing')

    # detect
    pd = sub.add_parser('detect', help='Detect WordPress domains from cleaned domain list.')
    pd.add_argument('--input', '-i', required=True, help='Input cleaned domain list (one registrable domain per line)')
    pd.add_argument('--out', '-o', required=True, help='Output text file: final WP URLs (one per line)')
    pd.add_argument('--db', default='wp_cache.db', help='SQLite DB path for resume/cache')
    pd.add_argument('--concurrency', type=int, default=80)
    pd.add_argument('--rate', type=float, default=20.0, help='max requests per second total')
    pd.add_argument('--timeout', type=int, default=10)
    pd.add_argument('--limit', type=int, default=48000)
    pd.add_argument('--sleep-on-block', type=int, default=900, help='seconds to sleep when block detected (default 900s = 15min)')
    pd.add_argument('--queue-size', type=int, default=800, help='internal queue size')
    pd.add_argument('--max-input', type=int, default=None, help='only read first N lines from input')
    pd.add_argument('--https-first', action='store_true', help='try https first (currently default behavior)')
    pd.add_argument('--verbose', action='store_true')

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.cmd == 'preprocess':
        asyncio.run(preprocess_command(args.input, args.out, dedupe=args.dedupe))
    elif args.cmd == 'detect':
        # ensure output exists
        Path(args.out).touch(exist_ok=True)
        asyncio.run(detect_command(args.input, args.out, args.db, concurrency=args.concurrency,
                                   rate=args.rate, timeout=args.timeout, limit=args.limit,
                                   sleep_on_block=args.sleep_on_block, verbose=args.verbose))
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

