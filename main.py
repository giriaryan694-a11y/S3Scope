#!/usr/bin/env python3
# S3Scope - S3 Bucket Recon Tool (patched main rewrite)
# Original by Aryan Giri — main() logic rewritten per user requests.

import re
import argparse
import requests
import json
import sys
import os
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

# UI libs
try:
    from colorama import init as colorama_init
    from termcolor import colored
    import pyfiglet
except ImportError:
    print("[-] Missing dependencies. Please run: pip install requests beautifulsoup4 colorama termcolor pyfiglet")
    sys.exit(1)

# -------------------- INIT --------------------
colorama_init(autoreset=True)
requests.packages.urllib3.disable_warnings()

# -------------------- BANNER --------------------
def print_banner():
    try:
        ascii_art = pyfiglet.figlet_format("S3Scope", font="slant")
        print(colored(ascii_art, "cyan", attrs=["bold"]))
    except Exception:
        print(colored("S3Scope", "cyan"))
    print(colored("S3 Bucket Recon & Visibility Tool", "yellow"))
    print(colored("Made By Aryan Giri\n", "green", attrs=["bold"]))

# -------------------- CONSTANTS --------------------
AWS_REGIONS = [
    "us-east-1","us-east-2","us-west-1","us-west-2",
    "ap-south-1","ap-northeast-1","ap-northeast-2","ap-northeast-3",
    "ap-southeast-1","ap-southeast-2","ca-central-1",
    "eu-central-1","eu-west-1","eu-west-2","eu-west-3",
    "eu-north-1","me-south-1","sa-east-1","af-south-1"
]
AWS_LOGIC_REF = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteEndpoints.html"

S3_REGEX = re.compile(
    r"""
    https?://
    (?:
        (?P<virt>[a-z0-9\-\.]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com
      |
        s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/(?P<path>[a-z0-9\-\.]+)
      |
        (?P<site1>[a-z0-9\-\.]+)\.s3-website-[a-z0-9-]+\.amazonaws\.com
      |
        (?P<site2>[a-z0-9\-\.]+)\.s3-website\.[a-z0-9-]+\.amazonaws\.com
    )
    """,
    re.IGNORECASE | re.VERBOSE
)

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/115.0 Safari/537.36 S3Scope")
DEFAULT_HEADERS = {"User-Agent": DEFAULT_UA}

ASSET_TAG_ATTRS = [
    ("script", "src"), ("link", "href"), ("img", "src"),
    ("img", "data-src"), ("img", "srcset"), ("source", "src"),
    ("video", "src"), ("audio", "src"), ("iframe", "src"),
    ("div", "data-src"),
]

DEBUG_DIR = "s3scope_debug"

# -------------------- HELPERS --------------------
def parse_headers(header_list):
    headers = {}
    for h in header_list or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers

def parse_cookies(cookie_string):
    cookies = {}
    if cookie_string:
        for c in cookie_string.split(";"):
            if "=" in c:
                k, v = c.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies

def fetch(url, headers, cookies):
    try:
        r = requests.get(url, headers=headers, cookies=cookies, timeout=10, verify=False)
        return r.text or ""
    except requests.exceptions.RequestException:
        return ""
    except Exception:
        return ""

def extract_assets_from_html(html, base_url):
    soup = BeautifulSoup(html or "", "html.parser")
    assets = set()
    for tag, attr in ASSET_TAG_ATTRS:
        for node in soup.find_all(tag):
            val = node.get(attr)
            if not val:
                if attr == "srcset" and node.get("srcset"):
                    val = node.get("srcset")
                else:
                    continue
            if isinstance(val, str) and "," in val:
                parts = [p.strip().split(" ")[0] for p in val.split(",")]
            else:
                parts = [val.strip()]
            for p in parts:
                if not p or p.startswith("data:"):
                    continue
                assets.add(urljoin(base_url, p))
    # inline JS links
    inline_js = " ".join([s.get_text() for s in soup.find_all("script") if not s.get("src")])
    for match in re.findall(r"https?://[^\s'\"()<>]+", inline_js):
        if not match.startswith("data:"):
            assets.add(match)
    # css url(...) matches
    for match in re.findall(r"url\(['\"]?(.*?)['\"]?\)", html or "", re.IGNORECASE):
        if match and not match.startswith("data:"):
            assets.add(urljoin(base_url, match))
    return assets

def extract_s3_buckets_from_text(text):
    buckets = set()
    if not text:
        return buckets
    for m in re.finditer(S3_REGEX, text):
        g = m.groupdict()
        if g.get("virt"):
            buckets.add(g["virt"].lower())
        elif g.get("path"):
            buckets.add(g["path"].lower())
        elif g.get("site1"):
            buckets.add(g["site1"].lower())
        elif g.get("site2"):
            buckets.add(g["site2"].lower())
    return buckets

def guess_endpoints_for_bucket(bucket):
    guesses = []
    guesses.append(("REST (virtual-hosted)", f"https://{bucket}.s3.amazonaws.com"))
    guesses.append(("REST (path-style)", f"https://s3.amazonaws.com/{bucket}"))
    for region in AWS_REGIONS:
        guesses.append(("WEBSITE (http) - dash-style", f"http://{bucket}.s3-website-{region}.amazonaws.com"))
        guesses.append(("WEBSITE (http) - dot-style", f"http://{bucket}.s3-website.{region}.amazonaws.com"))
        guesses.append(("WEBSITE (https) - dash heuristic", f"https://{bucket}.s3-website-{region}.amazonaws.com"))
        guesses.append(("WEBSITE (https) - dot heuristic", f"https://{bucket}.s3-website.{region}.amazonaws.com"))
        guesses.append(("REST (path-style region)", f"https://s3-{region}.amazonaws.com/{bucket}"))
    return guesses

def head_then_get(url, headers, cookies):
    try:
        r = requests.head(url, headers=headers, cookies=cookies, timeout=6, allow_redirects=True, verify=False)
        status = r.status_code
        if status in (400, 405, 501, 0):
            r2 = requests.get(url, headers=headers, cookies=cookies, timeout=10, allow_redirects=True, verify=False)
            return r2.status_code, r2.text or ""
        return status, None
    except requests.exceptions.Timeout:
        return "TIMEOUT", None
    except requests.exceptions.ConnectionError:
        return "UNREACHABLE", None
    except Exception:
        return "ERROR", None

def analyze_bucket_response(status, body):
    if status == "TIMEOUT":
        return "TIMEOUT"
    if status == "UNREACHABLE":
        return "UNREACHABLE"
    if status == "ERROR":
        return "ERROR"
    try:
        code = int(status)
    except Exception:
        return str(status)
    if code == 200:
        if body:
            b = body.lower()
            if "<listbucketresult" in b:
                return "PUBLIC (200) - LISTABLE (objects present)" if "<contents>" in b else "PUBLIC (200) - LISTABLE (empty)"
            if "index of /" in b or "<title>index of" in b:
                return "PUBLIC (200) - DIRECTORY LISTING"
        return "PUBLIC (200)"
    if code == 403:
        return "RESTRICTED (403)"
    if code == 404:
        return "NOT FOUND (404)"
    if code == 301 or code == 302:
        return f"REDIRECT ({code})"
    return f"UNKNOWN ({code})"

def concurrent_check(urls, headers, cookies, threads=8, debug=False, debug_dir=None):
    results = {}
    unique_urls = list(dict.fromkeys(urls))
    with ThreadPoolExecutor(max_workers=threads) as ex:
        future_map = {ex.submit(head_then_get, u, headers, cookies): u for u in unique_urls}
        for fut in as_completed(future_map):
            u = future_map[fut]
            try:
                status, body = fut.result()
            except Exception:
                status, body = "ERROR", None
            friendly = analyze_bucket_response(status, body)
            results[u] = friendly
            if debug and debug_dir and body:
                os.makedirs(os.path.join(debug_dir, "responses"), exist_ok=True)
                safe_name = re.sub(r"[^0-9A-Za-z_\-\.]", "_", u)[:120]
                try:
                    with open(os.path.join(debug_dir, "responses", f"{safe_name}.txt"), "w", encoding="utf-8") as fh:
                        fh.write(f"URL: {u}\nSTATUS: {status}\n\n")
                        fh.write(body[:20000])
                except Exception:
                    pass
    return results

def crawl_site(start_url, headers, cookies, max_depth=0, debug=False, debug_dir=None):
    start_url = urldefrag(start_url)[0]
    parsed = urlparse(start_url)
    base_netloc = parsed.netloc
    visited = set([start_url])
    queue = deque([(start_url, 0)])
    contents = {start_url: fetch(start_url, headers, cookies)}
    if debug and debug_dir:
        os.makedirs(debug_dir, exist_ok=True)
        try:
            with open(os.path.join(debug_dir, "crawled_pages.json"), "w", encoding="utf-8") as fh:
                json.dump({start_url: (contents[start_url][:1000] if contents[start_url] else "")}, fh, indent=2)
        except Exception:
            pass
    while queue:
        url, depth = queue.popleft()
        if depth >= max_depth:
            continue
        html = contents.get(url) or ""
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a.get("href")
            if not href:
                continue
            full = urljoin(url, href)
            full = urldefrag(full)[0]
            p = urlparse(full)
            if p.netloc != base_netloc:
                continue
            if full in visited:
                continue
            visited.add(full)
            qhtml = fetch(full, headers, cookies)
            contents[full] = qhtml
            if debug and debug_dir:
                cp = os.path.join(debug_dir, "crawled_pages.json")
                try:
                    if os.path.exists(cp):
                        with open(cp, "r", encoding="utf-8") as fh:
                            try:
                                data = json.load(fh)
                            except Exception:
                                data = {}
                    else:
                        data = {}
                    data[full] = qhtml[:1000] if qhtml else ""
                    with open(cp, "w", encoding="utf-8") as fh:
                        json.dump(data, fh, indent=2)
                except Exception:
                    pass
            queue.append((full, depth + 1))
    return contents

def ensure_dir_for_file(fname):
    directory = os.path.dirname(fname)
    if directory:
        os.makedirs(directory, exist_ok=True)

def write_txt(results, fname):
    ensure_dir_for_file(fname)
    gen_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    with open(fname, "w", encoding="utf-8") as f:
        f.write("S3Scope Report\n")
        f.write("Made By Aryan Giri\n")
        f.write(f"Generated: {gen_ts}\n\n")
        for r in results:
            f.write("-" * 60 + "\n")
            f.write(f"Bucket Name : {r['bucket']}\n")
            f.write(f"Type        : {r['type']}\n")
            f.write(f"URL         : {r['url']}\n")
            f.write(f"Access      : {r['access']}\n")
        f.write("\nReference: " + AWS_LOGIC_REF + "\n")

def write_json(results, fname):
    ensure_dir_for_file(fname)
    gen_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = {"generated": gen_ts, "tool": "S3Scope", "author": "Aryan Giri", "results": results, "reference": AWS_LOGIC_REF}
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

def write_html(results, fname):
    ensure_dir_for_file(fname)
    gen_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    with open(fname, "w", encoding="utf-8") as f:
        f.write("<!doctype html><html><head><meta charset='utf-8'>")
        f.write("<title>S3Scope Report</title></head><body>")
        f.write("<h1>S3Scope Report</h1>")
        f.write("<p>Made By Aryan Giri</p>")
        f.write(f"<p>Generated: {gen_ts}</p>")
        f.write("<table border='1' cellpadding='6' cellspacing='0'>")
        f.write("<tr><th>Bucket</th><th>Type</th><th>URL</th><th>Access</th></tr>")
        for r in results:
            f.write("<tr>")
            f.write(f"<td>{r['bucket']}</td>")
            f.write(f"<td>{r['type']}</td>")
            f.write(f"<td><a href='{r['url']}'>{r['url']}</a></td>")
            f.write(f"<td>{r['access']}</td>")
            f.write("</tr>")
        f.write("</table>")
        f.write(f"<p>Reference: <a href='{AWS_LOGIC_REF}'>{AWS_LOGIC_REF}</a></p>")
        f.write("</body></html>")

def print_summary(results):
    counts = {"PUBLIC":0,"LISTABLE":0,"RESTRICTED":0,"NOT FOUND":0,"TIMEOUT":0,"UNREACHABLE":0,"ERROR":0,"NOT CHECKED":0,"OTHER":0}
    for r in results:
        a = r.get("access","")
        if "LISTABLE" in a: counts["LISTABLE"] += 1
        elif "PUBLIC" in a: counts["PUBLIC"] += 1
        elif "RESTRICTED" in a: counts["RESTRICTED"] += 1
        elif "NOT FOUND" in a or "NOTFOUND" in a: counts["NOT FOUND"] += 1
        elif "TIMEOUT" in a: counts["TIMEOUT"] += 1
        elif "UNREACHABLE" in a: counts["UNREACHABLE"] += 1
        elif "ERROR" in a: counts["ERROR"] += 1
        elif "NOT CHECKED" in a: counts["NOT CHECKED"] += 1
        else: counts["OTHER"] += 1
    print("\n" + colored("="*50,"cyan"))
    print(colored("S3Scope Summary","cyan",attrs=["bold"]))
    print(colored("="*50,"cyan"))
    print(colored(f"PUBLIC (200):         {counts['PUBLIC']}", "green"))
    print(colored(f"LISTABLE (public):    {counts['LISTABLE']}", "green", attrs=["bold"]))
    print(colored(f"RESTRICTED (403):     {counts['RESTRICTED']}", "red"))
    print(colored(f"NOT FOUND (404):      {counts['NOT FOUND']}", "yellow"))
    print(colored(f"TIMEOUT/UNREACH:      {counts['TIMEOUT'] + counts['UNREACHABLE']}", "yellow"))
    print(colored(f"ERROR:                {counts['ERROR']}", "red"))
    print(colored(f"NOT CHECKED:          {counts['NOT CHECKED']}", "yellow"))
    print(colored(f"OTHER / UNKNOWN:      {counts['OTHER']}", "yellow"))
    print(colored("="*50 + "\n","cyan"))

# -------------------- MAIN --------------------
def main():
    print_banner()

    parser = argparse.ArgumentParser(description="S3Scope - Passive discovery & logical guessing for AWS S3 buckets",
                                     epilog="Passive only: no object listing, no writes. Use responsibly.")
    parser.add_argument("-u","--url", required=True, help="Target URL (http/https)")
    parser.add_argument("--header", action="append", help="Custom header (Key: Value)")
    parser.add_argument("--cookies", help="Cookies (k=v; k2=v2)")
    parser.add_argument("--ua", help="Override User-Agent")
    parser.add_argument("--crawl-depth", type=int, default=0, help="Internal crawl depth (0 = only the given page)")
    parser.add_argument("--threads", type=int, default=12, help="Concurrent threads for access checks")
    parser.add_argument("--output", help="Output filename (only saved when provided)")
    parser.add_argument("--format", choices=["txt","json","html"], default="txt", help="Output format")
    parser.add_argument("--no-guess", action="store_true", help="Do not generate guessed endpoints (use discovered only)")
    parser.add_argument("--only-guess", action="store_true", help="Run hostname-based guessing only (skip extraction)")
    parser.add_argument("--no-check", action="store_true", help="Do not perform network checks; only list URLs")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode (save scanned assets)")
    args = parser.parse_args()

    if args.no_guess and args.only_guess:
        print(colored("[-] --no-guess and --only-guess are mutually exclusive.", "red"))
        sys.exit(1)
    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        print(colored("[-] Please provide a valid http/https URL.", "red"))
        sys.exit(1)

    headers = DEFAULT_HEADERS.copy()
    headers.update(parse_headers(args.header))
    if args.ua:
        headers["User-Agent"] = args.ua
    cookies = parse_cookies(args.cookies)

    parsed = urlparse(args.url)
    clean_netloc = parsed.netloc.split(':')[0]
    # hostname-based guess set (sanitized)
    host_guesses = {clean_netloc, clean_netloc.split('.')[0], clean_netloc.replace('.', '-')}
    host_guesses = {h for h in host_guesses if len(h) > 2}

    debug_dir = None
    if args.debug:
        debug_dir = DEBUG_DIR
        os.makedirs(debug_dir, exist_ok=True)
        print(colored(f"[*] Debug enabled — writing to ./{debug_dir}/", "yellow"))

    # Discovery phase
    discovered_buckets = set()
    visited_pages = []
    all_html_texts = []

    if args.only_guess:
        print(colored("[*] Running in --only-guess mode (skipping extraction).", "yellow"))
        discovered_buckets.update(host_guesses)
        if args.debug:
            try:
                with open(os.path.join(debug_dir, "only_guess.txt"), "w", encoding="utf-8") as fh:
                    for bg in sorted(discovered_buckets):
                        fh.write(bg + "\n")
            except Exception:
                pass
    else:
        if args.crawl_depth > 0:
            print(colored(f"[*] Crawling {args.url} (depth={args.crawl_depth}) for internal assets...", "yellow"))
            crawl_map = crawl_site(args.url, headers, cookies, max_depth=args.crawl_depth, debug=args.debug, debug_dir=debug_dir)
            visited_pages = list(crawl_map.keys())
            all_html_texts = list(crawl_map.values())
            print(colored(f"[*] Crawled {len(visited_pages)} page(s).", "yellow"))
        else:
            print(colored(f"[*] Fetching {args.url} (no crawl)...", "yellow"))
            html = fetch(args.url, headers, cookies)
            visited_pages = [args.url]
            all_html_texts = [html]

        # Extract assets and fetch relevant assets
        assets = set()
        for i, text in enumerate(all_html_texts):
            base = visited_pages[i] if i < len(visited_pages) else args.url
            assets.update(extract_assets_from_html(text, base))

        if args.debug:
            try:
                with open(os.path.join(debug_dir, "assets_list.txt"), "w", encoding="utf-8") as fh:
                    for a in sorted(assets):
                        fh.write(a + "\n")
            except Exception:
                pass

        # fetch non-binary assets
        fetched_asset_contents = []
        fetched_asset_urls = []
        assets_to_fetch = assets - set(visited_pages)
        for a in assets_to_fetch:
            path = urlparse(a).path
            ext = path.split(".")[-1].lower() if "." in path else ""
            if ext in ("png","jpg","jpeg","gif","webp","svg","ico","mp4","mp3","ogg","woff","ttf"):
                continue
            txt = fetch(a, headers, cookies)
            if txt:
                fetched_asset_contents.append(txt)
                fetched_asset_urls.append(a)

        if args.debug:
            try:
                with open(os.path.join(debug_dir, "fetched_asset_urls.txt"), "w", encoding="utf-8") as fh:
                    for u in fetched_asset_urls:
                        fh.write(u + "\n")
            except Exception:
                pass

        all_texts_for_s3 = set(all_html_texts)
        all_texts_for_s3.update(fetched_asset_contents)
        for t in all_texts_for_s3:
            discovered_buckets.update(extract_s3_buckets_from_text(t))

    # Bucket selection rules (NO auto-guessing unless --only-guess)
    if not discovered_buckets:
        if args.only_guess:
            # already populated from host_guesses
            pass
        elif args.no_guess:
            print(colored("[!] No direct S3 bucket references found and --no-guess set. Exiting.", "red"))
            sys.exit(0)
        else:
            # no auto-guessing by default — tell user how to enable
            print(colored("[!] No direct S3 bucket references found.", "red", attrs=["bold"]))
            print(colored("[*] To run hostname-based guessing use: --only-guess", "yellow"))
            sys.exit(0)
    else:
        print(colored(f"[+] Found {len(discovered_buckets)} distinct bucket name(s) to analyze.", "green", attrs=["bold"]))
        # Do NOT merge host guesses automatically in default mode; guessing only with --only-guess.

    # Build mapping
    mapping = []
    for bucket in sorted(discovered_buckets):
        if args.only_guess:
            for etype, url in guess_endpoints_for_bucket(bucket):
                mapping.append((bucket, etype, url))
        else:
            # default: only REST endpoints from discovered names (no guessing)
            mapping.append((bucket, "REST (virtual-hosted)", f"https://{bucket}.s3.amazonaws.com"))
            mapping.append((bucket, "REST (path-style)", f"https://s3.amazonaws.com/{bucket}"))

    # Deduplicate while preserving order
    uniq_endpoints = []
    uniq_map = []
    seen = set()
    for b, etype, url in mapping:
        if url not in seen:
            seen.add(url)
            uniq_endpoints.append(url)
            uniq_map.append((b, etype, url))

    # Split REST vs guessed to print REST first (guessed only if --only-guess)
    rest_results = []
    guessed_results = []
    for b, etype, url in uniq_map:
        if etype.startswith("REST"):
            rest_results.append((b, etype, url))
        else:
            guessed_results.append((b, etype, url))

    # Print REST placeholders
    if rest_results:
        print(colored("-"*60, "magenta"))
        print(colored("Direct REST endpoints (from discovered bucket names):", "green", attrs=["bold"]))
        print(colored("-"*60 + "\n", "magenta"))
    for b, etype, url in rest_results:
        print(colored(f"[ ] {b}  {etype}  {url}", "cyan"))

    # Print guessed header only when --only-guess used
    if args.only_guess and guessed_results:
        print(colored("-"*60, "magenta"))
        print(colored("Guessed S3 buckets by logic (hostname-based):", "yellow", attrs=["bold"]))
        print(colored(AWS_LOGIC_REF, "cyan"))
        print(colored("-"*60 + "\n", "magenta"))
        for b, etype, url in guessed_results:
            print(colored(f"[ ] {b}  {etype}  {url}", "cyan"))

    if args.no_check:
        print(colored("[*] --no-check enabled — skipping network HEAD/GET checks. Results will show NOT CHECKED.", "yellow"))
        checks = {u: "NOT CHECKED" for u in uniq_endpoints}
    else:
        print(colored(f"\n[*] Checking {len(uniq_endpoints)} endpoints concurrently (threads={args.threads})...", "yellow"))
        checks = concurrent_check(uniq_endpoints, headers, cookies, threads=args.threads, debug=args.debug, debug_dir=debug_dir)

    # Aggregate results
    results = []
    if rest_results:
        print("\n" + colored("== Direct REST results ==", "green", attrs=["bold"]))
    for b, etype, url in rest_results:
        access = checks.get(url, "ERROR")
        results.append({"bucket": b, "type": etype, "url": url, "access": access})
        color = "green" if "PUBLIC" in access or "LISTABLE" in access else "red" if "RESTRICTED" in access else "yellow"
        print(colored("-"*60, "magenta"))
        print(colored(f"Bucket Name : {b}", "green", attrs=["bold"]))
        print(colored(f"Type        : {etype}", "green"))
        print(colored(f"URL         : {url}", "cyan"))
        print(colored(f"Access      : {access}", color))

    if args.only_guess and guessed_results:
        print("\n" + colored("== Guessed endpoint results ==", "yellow", attrs=["bold"]))
        for b, etype, url in guessed_results:
            access = checks.get(url, "ERROR")
            results.append({"bucket": b, "type": etype, "url": url, "access": access})
            color = "green" if "PUBLIC" in access or "LISTABLE" in access else "red" if "RESTRICTED" in access else "yellow"
            print(colored("-"*60, "magenta"))
            print(colored(f"Bucket Name : {b}", "green", attrs=["bold"]))
            print(colored(f"Type        : {etype}", "yellow"))
            print(colored(f"URL         : {url}", "cyan"))
            print(colored(f"Access      : {access}", color))

    print(colored("-"*60, "magenta"))
    print_summary(results)

    # Output only if requested
    if args.output:
        out_fname = args.output
        try:
            if args.format == "json": write_json(results, out_fname)
            elif args.format == "html": write_html(results, out_fname)
            else: write_txt(results, out_fname)
            print(colored(f"[+] Report written: {out_fname}", "green"))
            if args.debug:
                try:
                    with open(os.path.join(debug_dir, "final_results.json"), "w", encoding="utf-8") as fh:
                        json.dump(results, fh, indent=2)
                except Exception:
                    pass
        except Exception as e:
            print(colored(f"[-] Failed to write report: {e}", "red"))
    else:
        print(colored("[*] No --output provided — report not saved. Use --output <file> to save results.", "yellow"))

if __name__ == "__main__":
    main()
