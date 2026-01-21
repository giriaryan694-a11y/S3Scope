# S3Scope - AWS S3 Bucket Recon & Visibility Tool

S3Scope is a passive AWS S3 bucket discovery and visibility tool. It helps researchers and pentesters identify S3 bucket endpoints, perform logical hostname-based guessing, and optionally check bucket accessibility. This tool is designed for reconnaissance without writing to S3 buckets and emphasizes clear output and enhanced visibility.

---

## Features

* **Passive S3 Discovery:** Extracts potential S3 bucket references from web pages and internal assets.
* **Hostname-based Guessing:** Generates likely S3 endpoints from domain names.
* **Endpoint Checking:** Concurrently checks S3 endpoint accessibility (optional).
* **Recursive Crawling:** Optional internal link crawling for asset discovery.
* **Flexible Output:** TXT, JSON, and HTML report generation.
* **Debug Mode:** Save crawled pages, assets, and network responses for later inspection.
* **Custom Headers & Cookies:** Support for authentication or session handling.
* **Threaded Checks:** Speed up network requests using multithreading.

---

## Installation

1. Clone or download the repository.

```bash
git clone https://github.com/giriaryan694-a11y/S3Scope
cd S3Scope
```

2. Install required Python packages using the provided `requirements.txt`:

```bash
pip install -r requirements.txt
```

3. Run the tool using Python 3.10+:

```bash
python main.py -u <target_url>
```

---

## Usage

```text
usage: main.py [-h] -u URL [--header HEADER] [--cookies COOKIES] [--ua UA]
               [--crawl-depth CRAWL_DEPTH] [--threads THREADS] [--output OUTPUT]
               [--format {txt,json,html}] [--no-guess] [--only-guess] [--no-check]
               [--debug]

S3Scope - Passive discovery & logical guessing for AWS S3 buckets

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL (http/https)
  --header HEADER        Custom header (Key: Value)
  --cookies COOKIES      Cookies (k=v; k2=v2)
  --ua UA                Override User-Agent
  --crawl-depth CRAWL_DEPTH
                        Internal crawl depth (0 = only the given page)
  --threads THREADS      Concurrent threads for access checks
  --output OUTPUT        Output filename (only saved when provided)
  --format {txt,json,html}
                        Output format (default: txt)
  --no-guess             Do not generate guessed endpoints (use discovered only)
  --only-guess           Run hostname-based guessing only (skip extraction)
  --no-check             Do not perform network checks; only list URLs
  --debug                Enable debug mode (save scanned assets)
```

---

## Flags Explained

* `-u / --url`: **Required.** Target website URL to scan.
* `--header`: Add custom headers for HTTP requests.
* `--cookies`: Provide cookies for session-based access.
* `--ua`: Override the default User-Agent.
* `--crawl-depth`: Depth for internal crawling. `0` fetches only the main page.
* `--threads`: Number of concurrent network checks (default: 12).
* `--output`: Save results to a file.
* `--format`: Output file format (`txt`, `json`, `html`).
* `--no-guess`: Skip guessed endpoints, only use discovered buckets.
* `--only-guess`: Skip extraction; only generate guessed S3 endpoints from hostname.
* `--no-check`: Do not check bucket accessibility; list URLs only.
* `--debug`: Save crawled pages, assets, and responses for inspection.

### Behavior of Flags

| Mode           | Description                                                                             |
| -------------- | --------------------------------------------------------------------------------------- |
| Default        | Extracts buckets, guesses endpoints, checks accessibility.                              |
| `--no-guess`   | Only direct references from assets are considered; no guessed endpoints shown.          |
| `--only-guess` | Skips all extraction and crawls; only hostname-based S3 endpoint guesses are displayed. |
| `--no-check`   | URLs are listed but no network requests are made to test accessibility.                 |

---

## S3 Guessing Logic

S3Scope generates likely bucket endpoints based on the target domain and AWS S3 patterns:

1. **Direct REST Endpoints:**

   * Virtual-hosted style: `https://bucketname.s3.amazonaws.com`
   * Path-style: `https://s3.amazonaws.com/bucketname`

2. **Regional REST Endpoints:**

   * `https://s3-<region>.amazonaws.com/bucketname`

3. **Website Endpoints:**

   * Dash-style: `http://bucketname.s3-website-<region>.amazonaws.com`
   * Dot-style: `http://bucketname.s3-website.<region>.amazonaws.com`
   * HTTPS variants are also guessed (for connectivity).

4. **Hostname Transformations:**

   * Original hostname as bucket
   * Subdomain only (first segment)
   * Dot replaced with dash for guessing (e.g., `sub.example.com` -> `sub-example-com`)

These guesses allow detection of buckets even if not directly referenced on the website.

---

## Output & Reports

* **Console:** Nicely formatted with colors for status:

  * Green: PUBLIC / LISTABLE buckets
  * Red: RESTRICTED / ERROR
  * Yellow: NOT FOUND / NOT CHECKED

* **Saved Reports:** Optional using `--output` and `--format`

  * TXT: Human-readable report
  * JSON: Machine-readable structured report
  * HTML: Formatted browser-viewable report with clickable links

* **Debug Mode:** Saves:

  * Crawled pages (`.html`)
  * Extracted assets (`assets_list.txt`)
  * Network responses per endpoint

---

## Example Usage

```bash
# Basic scan with extraction, guessing, and network checks
python main.py -u https://example.com

# Scan only hostname-based guesses
python main.py -u https://example.com --only-guess

# Scan discovered buckets only, skip guesses
python main.py -u https://example.com --no-guess

# List URLs only, skip network checks
python main.py -u https://example.com --no-check

# Save results as JSON
python main.py -u https://example.com --output report.json --format json

# Enable debug to save crawled pages and assets
python main.py -u https://example.com --debug
```

---

## Notes

* This tool is **passive only**: it does not write to or modify any S3 buckets.
* Use responsibly; only target sites you have permission to test.
* The guessing logic is based on AWS official endpoint patterns and common recon heuristics.
* `--debug` is useful for investigating why certain buckets were discovered or missed.

---

Reference: [AWS S3 Website Endpoints](https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteEndpoints.html)
