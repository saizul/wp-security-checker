# wp-security-checker

[![CI](https://github.com/saizul/wp-security-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/saizul/wp-security-checker/actions/workflows/ci.yml) ![Python](https://img.shields.io/badge/Python-ready-blue?logo=python&logoColor=white) ![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

Passive, non-intrusive security checks for WordPress sites. Point it at a URL
and get a prioritised list of exposed information, risky defaults and missing
hardening, as a console table, JSON or a self-contained HTML report.

> **Only scan sites you own or have explicit permission to test.**
> Every check is a plain `GET` request to a public URL, the same thing a
> browser or search engine bot does. Nothing is submitted, guessed or
> exploited, and the contents of sensitive files are never read or printed
> (at most the first few hundred bytes are inspected to rule out a soft-404 page).

## Features

- Modular, plugin-style check registry: one module per check family, plus an
  entry point group for third-party checks.
- YAML config to enable or disable checks, override severities and set thresholds.
- Retry with exponential backoff (honours `Retry-After`), timeouts, a polite
  delay between requests and the `wp-security-checker` User-Agent.
- Severity levels: critical, high, medium, low, info.
- Output: rich table, `--json`, `--html report.html` (with a severity summary),
  and `--sarif results.sarif` for GitHub code scanning.
- `--baseline previous.json` diffs a run against an earlier JSON run and shows
  what is new, resolved or unchanged.
- CI friendly exit codes with `--fail-on`.

## Checks

| ID | Family | What it looks at |
| --- | --- | --- |
| `wp-version` | disclosure | generator meta tag, `readme.html`, `?ver=` on core assets |
| `plugin-versions` | disclosure | plugins and themes referenced by the home page, readable plugin `readme.txt`, versions below a configured minimum |
| `xmlrpc` | surface | `xmlrpc.php` reachable (GET only) |
| `rest-users` | users | `/wp-json/wp/v2/users` lists accounts |
| `author-enum` | users | `?author=1` redirects to `/author/<login>/` |
| `directory-listing` | exposure | "Index of" pages, default `/wp-content/uploads/` |
| `sensitive-files` | exposure | `debug.log`, `.env`, `wp-config` backup filenames |
| `security-headers` | hardening | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `https-redirect` | transport | `http://` redirects to `https://` |
| `login-url` | surface | default `wp-login.php` reachable |
| `jquery` | hardening | outdated jQuery referenced by the home page |

List them any time with `wp-security-check --list-checks`.

## Install

```bash
pip install .            # from a clone of this repository
# or, for development
pip install -e ".[dev]"
```

Requires Python 3.9+.

## Usage

```bash
wp-security-check https://example.com
wp-security-check https://example.com --json > run1.json
wp-security-check https://example.com --html report.html
wp-security-check https://example.com --sarif results.sarif
wp-security-check https://example.com --baseline run1.json --fail-on medium
wp-security-check https://example.com --only xmlrpc,security-headers
wp-security-check https://example.com --skip login-url --config wp-security-checker.yml
```

Options: `--config`, `--json`, `--html PATH`, `--sarif PATH`,
`--sarif-location FILE`, `--baseline PATH`, `--only`,
`--skip`, `--list-checks`, `--delay`, `--timeout`, `--retries`, `--fail-on`,
`--version`.

`--timeout` must be greater than 0 and `--delay` / `--retries` must not be negative; the same rules apply to the `http:` section of the config file.

Exit codes: `0` success, `1` a finding at or above `--fail-on` exists (with
`--baseline`, only **new** findings count), `2` usage, config or network error.

## Sample output

Illustrative output from a mocked site:

```text
                                    WordPress security check: https://example.com/                                    
┏━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Status ┃ Severity ┃ Check                                        ┃ Details                                         ┃
┡━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ FAIL   │ HIGH     │ Exposed debug log: /wp-content/debug.log     │ HTTP 200 and the content type looks like data,  │
│        │          │                                              │ not a web page (text/plain). Fix: Delete the    │
│        │          │                                              │ file or block access to it, and rotate any      │
│        │          │                                              │ credentials in it.                              │
│ FAIL   │ MEDIUM   │ REST API exposes user accounts               │ 1 user(s) listed publicly (e.g. admin). Fix:    │
│        │          │                                              │ Restrict /wp/v2/users to authenticated          │
│        │          │                                              │ requests.                                       │
│ FAIL   │ MEDIUM   │ xmlrpc.php is reachable                      │ GET /xmlrpc.php answered HTTP 405. Fix: Block   │
│        │          │                                              │ xmlrpc.php at the web server or with a plugin   │
│        │          │                                              │ unless you need it.                             │
│ FAIL   │ LOW      │ Content-Security-Policy header missing       │ Fix: Define a Content-Security-Policy.          │
│ FAIL   │ LOW      │ X-Frame-Options header missing               │ Fix: Send X-Frame-Options: SAMEORIGIN.          │
│ FAIL   │ LOW      │ Referrer-Policy header missing               │ Fix: Send Referrer-Policy:                      │
│        │          │                                              │ strict-origin-when-cross-origin.                │
│ FAIL   │ LOW      │ Permissions-Policy header missing            │ Fix: Send a Permissions-Policy limiting browser │
│        │          │                                              │ features.                                       │
│ FAIL   │ LOW      │ Default login URL is reachable               │ /wp-login.php serves the login form. Fix:       │
│        │          │                                              │ Consider rate limiting, 2FA and optionally      │
│        │          │                                              │ moving or restricting the login page.           │
│ FAIL   │ LOW      │ WordPress version exposed                    │ Exposed via: generator meta tag. Version        │
│        │          │                                              │ appears to be 6.4.2. Fix: Remove the generator  │
│        │          │                                              │ tag, delete readme.html and strip ?ver= query   │
│        │          │                                              │ strings from assets; keep WordPress updated.    │
│ PASS   │ -        │ Strict-Transport-Security header             │ max-age=31536000                                │
│ PASS   │ -        │ X-Content-Type-Options header                │ nosniff                                         │
│ PASS   │ -        │ No outdated jQuery detected                  │ Found jQuery 3.7.1.                             │
│ PASS   │ -        │ No directory listing found                   │                                                 │
│ PASS   │ -        │ HTTP redirects to HTTPS                      │ HTTP 301                                        │
│ PASS   │ -        │ Author enumeration not possible via ?author= │                                                 │
└────────┴──────────┴──────────────────────────────────────────────┴─────────────────────────────────────────────────┘
Failed: 9 (0 critical, 1 high, 2 medium, 6 low) | Passed: 6
```

## Plugin and theme inventory

`plugin-versions` reads the asset URLs already present in the home page
(`/wp-content/plugins/<slug>/...` and `/wp-content/themes/<slug>/...`) and builds an
inventory from them. Nothing is guessed: a plugin that loads no asset on the home page is
not listed. For each detected plugin it requests `readme.txt` once (only the first 4 KB are
inspected, and nothing but the `Stable tag` is kept).

| Finding | Severity | When |
| --- | --- | --- |
| Plugin version exposed: `<slug>` | low | the plugin's `readme.txt` is publicly readable |
| Outdated plugin / theme: `<slug> <version>` | medium | the detected version is below `min_versions` |
| Detected N plugin(s) and M theme(s) | pass | always, with the slugs and versions found |

The version comes from `readme.txt` when it is readable and from the `?ver=` query string
of the component's assets otherwise. Options:

```yaml
checks:
  plugin-versions:
    probe_readme: true      # false: build the inventory from the home page only
    max_probes: 10          # upper limit of readme.txt requests per scan
    ignore: ["hello-dolly", "theme/twentytwentyfour"]
    min_versions:           # slug or plugin/<slug>, theme/<slug>
      woocommerce: "8.5.0"
      contact-form-7: "5.8.4"
      theme/astra: "4.6.0"
```

Each finding has its own key (`plugin-versions:readme:<slug>`,
`plugin-versions:outdated:plugin/<slug>`), so `--baseline` reports a newly exposed or newly
outdated plugin on its own.

## GitHub code scanning (SARIF)

`--sarif PATH` writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) file
next to the normal output. Only failing findings are reported. Severities map to SARIF
levels (`critical`/`high` -> error, `medium` -> warning, `low`/`info` -> note) and to
GitHub's `security-severity` score, and each finding has a stable fingerprint so repeat
scans update the same alert. With `--baseline`, results carry `baselineState`
(`new` or `unchanged`).

A site scan has no source file, so every result points at one file in the repository
that uploads the report (`README.md` by default; change it with `--sarif-location`).

Example workflow that scans nightly and uploads the results:

```yaml
name: wp-security-check
on:
  schedule:
    - cron: "17 3 * * *"
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/saizul/wp-security-checker.git
      - name: Scan (only sites you own)
        run: wp-security-check https://example.com --sarif results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: wp-security-check
```

## Configuration

See [`examples/wp-security-checker.yml`](examples/wp-security-checker.yml).

```yaml
http:
  timeout: 10
  delay: 0.5
  retries: 2
  backoff: 0.5
checks:
  author-enum: false
  xmlrpc:
    severity: high
  security-headers:
    hsts_min_age: 15552000
  jquery:
    min_version: "3.5.0"
```

Unknown check ids or malformed values are rejected with a clear message.

## Baseline mode

Save a JSON run, fix things, then compare:

```bash
wp-security-check https://example.com --json > baseline.json
wp-security-check https://example.com --baseline baseline.json
```

Findings are matched by a stable key (for example `sensitive-files:.env`), so
the report lists them as `new`, `resolved` or `unchanged`.

## Writing a check

```python
from wp_security_checker.models import Finding, Severity
from wp_security_checker.registry import register

@register("robots-txt", family="disclosure", description="robots.txt lists admin paths")
def check_robots(ctx, options):
    resp = ctx.client.request(ctx.url("robots.txt"))
    ...
    return [Finding.ok("robots-txt", "Looks fine")]
```

Publish it from your own package via the `wp_security_checker.checks` entry
point (a module or a callable that receives the registry). See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

Tests use mocked HTTP responses only, so they never touch the network.

## Limitations

These are indicators, not a vulnerability scanner. A clean report does not mean
a site is secure, and some findings (for example a visible login page) are
informational. Keep WordPress core, themes and plugins updated.

## License

MIT, see [LICENSE](LICENSE). Author: Saizul Amin, https://saizul.com
