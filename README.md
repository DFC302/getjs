# getjs

A browser-backed JavaScript URL extractor for security researchers. It combines runtime network observation, DOM inspection, and bounded recursive bundle parsing to discover JavaScript used or referenced by web applications.

## Features

- **Real Browser Execution** - Uses Playwright/Chromium to execute JavaScript exactly like a real browser
- **Multi-Domain Support** - Process multiple targets from a file or stdin with concurrent threads
- **Dynamic JS Detection** - Captures scripts loaded via:
  - Static `<script src>` tags
  - Deferred `data-src`, module-preload, preload, and prefetch elements
  - Dynamic script injection
  - Classic inline loaders and ES6 module imports
  - `import()` dynamic imports
  - XHR/fetch loaded scripts
  - Same-origin and cross-origin frames
  - Lazy-loaded scripts triggered by scrolling
  - **WebSocket messages** (monitors for JS URLs in WS traffic)
  - **Service Workers** (detects SW registrations and scripts)
- **Recursive Dependency Parsing** - Follows static imports, dynamic string imports, workers, and JavaScript URL literals with depth/file/size limits
- **Optional Route Crawling** - Visits bounded, same-origin GET links while avoiding common logout and destructive routes
- **Authentication Support** - Access protected pages via:
  - Browser cookie exports, Netscape cookie jars, or raw cookie strings
  - Playwright storage-state files containing cookies and per-origin localStorage
  - Origin-scoped custom HTTP headers and localStorage values
- **Interactive Auth Capture** - Log in through a headed browser and save a mode-`0600` storage-state file with `getjs auth`
- **Auth-Aware Downloads** - Downloaded JS files carry browser session cookies/headers
- **Safe Downloads** - Enforces size limits, rejects HTML responses, follows bounded redirects, scopes credentials per redirect, and uses collision-safe filenames
- **Navigation Diagnostics** - Reports final URLs, redirect chains, failed requests, and authentication-related redirects in JSON output
- **Domain Filtering** - Whitelist/blacklist JS URLs by domain pattern
- **Flexible Output** - Per-domain files, combined file, JSON, or stdout
- **Resume Mode** - Incremental scanning skips already-discovered URLs
- **Content Deduplication** - Skip duplicate JS files by content hash during download
- **Smart URL Normalization** - Deduplicates and normalizes all discovered URLs
- **Proxy Support** - Route traffic through Burp Suite or other proxies
- **Headless Toggle** - Run with visible browser for debugging
- **Secret Scanning Pipeline** - Discover, download, and scan JavaScript with TruffleHog in one command
- **Unredacted Evidence Reports** - Preserves complete findings in mode-`0600` JSON reports for validation
- **Managed TruffleHog** - Installs and explicitly updates checksum-validated official releases

## Installation

### Prerequisites

- **Node.js 18+** - Required for Playwright compatibility
- **npm** - Comes with Node.js
- **tar** - Used only for managed TruffleHog installation (normally preinstalled on Linux/macOS and modern Windows)

Check your Node.js version:
```bash
node --version  # Should be v18.0.0 or higher
```

### Option 1: Full Installation from GitHub (Recommended)

The repository is private, so GitHub authentication must already be configured for npm/Git.

```bash
# Install getjs globally from GitHub
npm install -g github:DFC302/getjs

# Install Chromium browser (required, one-time setup)
npx playwright install chromium

# Install managed TruffleHog (required only for --scan-secrets)
getjs scanner install

# Verify both components
getjs --version
getjs scanner status --check-updates
```

TruffleHog is not downloaded silently during a normal getjs installation or collection. This keeps installation predictable for offline and restricted systems. To install it as part of the first scanning pipeline instead, omit `getjs scanner install` and use `--install-scanner` with `--scan-secrets`.

### Option 2: Clone and Install Locally

```bash
# Clone the repository
git clone https://github.com/DFC302/getjs.git
cd getjs

# Install dependencies
npm install

# Install Chromium browser (required, one-time setup)
npx playwright install chromium

# Option A: Install globally on your system
npm install -g .

# Option B: Run directly without global install
node bin/getjs.js -u https://example.com
```

### Option 3: Run with npx (No Install)

```bash
# Run directly without installing
npx github:DFC302/getjs -u https://example.com
```

### Required Browser Setup

After installing getjs, you must install the Chromium browser (~170MB):

```bash
npx playwright install chromium
```

This only needs to be done once per system.

Secret scanning additionally requires TruffleHog. Install it separately:

```bash
getjs scanner install
getjs scanner status --check-updates
```

You can skip this separate step and add `--install-scanner` to the first `--scan-secrets` pipeline instead. Scanner updates remain explicit through `getjs scanner update` or the pipeline's `--update-scanner` flag.

### Updating

```bash
# Update getjs from the private GitHub repository
npm install -g github:DFC302/getjs

# Update the managed scanner to the latest official release
getjs scanner update

# Confirm the active versions and query the official release feed
getjs --version
getjs scanner status --check-updates
```

### Troubleshooting

**Permission errors on Linux/macOS:**
```bash
sudo npm install -g github:DFC302/getjs
```

**Missing dependencies on Linux (headless servers):**
```bash
# Debian/Ubuntu
sudo apt-get install libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
  libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2

# Or use Playwright's installer
npx playwright install-deps chromium
```

**Running `--no-headless` on a VPS without X server:**

Some sites block headless browsers. Use Xvfb to create a virtual display so you can run in headed mode on a headless VPS:

```bash
# Install Xvfb
sudo apt-get install xvfb

# Run getjs with a virtual display
xvfb-run getjs -u https://example.com --no-headless

# Or start a persistent virtual display
Xvfb :99 -screen 0 1920x1080x24 &
export DISPLAY=:99
getjs -u https://example.com --no-headless
```

**Shell still finds an older installation:**

```bash
command -v getjs
getjs -V
rehash       # zsh only; needed after changing install locations, not every run
```

### Uninstall

```bash
npm uninstall -g getjs
```

## Quick Start

```bash
# Basic usage - output JS URLs to stdout
getjs -u https://example.com

# Save to file
getjs -u https://example.com -o js-urls.txt

# Scan multiple domains from a file
getjs -f targets.txt --output-dir ./results

# Pipe domains from stdin
cat targets.txt | getjs --output-dir ./results

# Download all discovered JS files
getjs -u https://example.com --fetch-all -d ./js-files

# Discover, download, and scan all JS in one pipeline
getjs -u https://example.com --scan-secrets -d ./js-files

# Install TruffleHog automatically as part of the first pipeline run
getjs -u https://example.com --scan-secrets --install-scanner -d ./js-files

# Authenticated discovery, download, and secret scan
getjs -u https://example.com/dashboard \
  --storage-state ./target.storage-state.json \
  --crawl \
  --scan-secrets \
  --secret-report ./js-files/getjs-secrets.json \
  -d ./js-files

# Run with visible browser (for debugging)
getjs -u https://example.com --no-headless
```

## CLI Reference

### Collect Command (Default)

```
getjs [collect] -u <url> [options]
getjs [collect] -f <file> [options]
cat urls.txt | getjs [options]
```

#### Input Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url <url>` | Target URL to analyze | - |
| `-f, --file <path>` | File containing URLs (one per line) | - |
| (stdin) | Pipe URLs from stdin when no -u or -f | - |

#### Output Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <file>` | Output file for JS URLs (combined) | stdout |
| `--output-dir <dir>` | Directory for per-domain output files | - |
| `--json` | Output results as structured JSON | - |
| `-s, --silent` | Suppress banner and status messages | - |
| `-v, --verbose` | Verbose output | - |

#### Browser Options

| Option | Description | Default |
|--------|-------------|---------|
| `--headless` | Run browser in headless mode | true |
| `--no-headless` | Run browser with visible UI | - |
| `-t, --timeout <seconds>` | Page load timeout | 30 |
| `-w, --wait <seconds>` | Additional wait after load | 5 |
| `--no-scroll` | Disable automatic scrolling | - |
| `--no-recursive` | Disable recursive dependency parsing | - |
| `--max-depth <n>` | Maximum recursive import depth | 3 |
| `--max-files <n>` | Maximum recursively parsed scripts | 500 |
| `--max-file-size <mb>` | Maximum parsed/downloaded script size | 10 |
| `--crawl` | Visit safe same-origin GET links | - |
| `--max-pages <n>` | Maximum additional pages for `--crawl` | 10 |
| `-A, --user-agent <string>` | Custom User-Agent | - |
| `-x, --proxy <url>` | Proxy server URL | - |

#### Authentication Options

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --cookies <file\|string>` | Cookie file (JSON) or raw cookie string | - |
| `--storage-state <file>` | Playwright storage state with cookies/localStorage | - |
| `--cookie-domain <domain>` | Domain assigned to raw cookies | Target host |
| `-H, --header <header...>` | Extra HTTP headers | - |
| `--local-storage <entry...>` | Set localStorage entries | - |
| `--auth-domain <pattern...>` | Expand header/localStorage scope beyond target origin | Target origin only |

#### Auth Capture Command

`getjs auth` opens a visible browser so you can complete a real login and save the resulting cookies and origin storage for later scans.

```text
getjs auth -u <url> -o <storage-state.json> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url <url>` | Login or application URL to open | Required |
| `-o, --output <file>` | Storage-state JSON file to create | Required |
| `-t, --timeout <seconds>` | Initial navigation timeout | 30 |
| `-A, --user-agent <string>` | Custom User-Agent | Browser default |
| `-x, --proxy <url>` | Proxy server URL | - |
| `--channel <name>` | Browser channel such as `chrome` or `msedge` | Bundled Chromium |
| `--force` | Overwrite an existing state file | - |

Captured state is written with mode `0600`. Keep the browser open after logging in, return to the terminal, and press Enter to save it.

#### Download Options

| Option | Description | Default |
|--------|-------------|---------|
| `--fetch-all` | Download all discovered JS files | - |
| `--fetch-one <url>` | Download a specific JS file | - |
| `-d, --download-dir <dir>` | Directory for downloads | ./js-downloads |
| `--download-concurrency <n>` | Concurrent downloads | 5 |
| `--dedupe-content` | Skip duplicate files by content hash | - |

#### Secret Scanning Options

`--scan-secrets` runs collection, enables `--fetch-all` when no explicit fetch option was supplied, and scans only files successfully downloaded during that invocation.

| Option | Description | Default |
|--------|-------------|---------|
| `--scan-secrets` | Download and scan discovered JavaScript with TruffleHog | - |
| `--secret-report <file>` | Unredacted JSON evidence report | `<download-dir>/getjs-secrets.json` |
| `--verify-secrets` | Allow provider verification requests | Disabled |
| `--fail-on-secret` | Exit with status `3` when candidates are found | - |
| `--trufflehog-path <file>` | Use a specific TruffleHog executable | Managed binary, then `PATH` |
| `--install-scanner` | Install managed TruffleHog before the scan | - |
| `--update-scanner` | Update managed TruffleHog before the scan | - |
| `--scanner-version <version>` | Version used by pipeline installation/update | Latest |

Reports intentionally contain full, unredacted credential material and are created with permissions `0600`. The default report name is ignored by Git. Protect custom report paths yourself, and do not attach reports to tickets or commits without reviewing their contents.

Verification is disabled by default because it can make outbound requests containing a candidate credential. Use `--verify-secrets` only when the engagement scope permits active validation.

#### Scanner Management Command

```text
getjs scanner install [--scanner-version <version>] [--force]
getjs scanner status [--check-updates]
getjs scanner update
```

Managed binaries are stored under the user's data directory (`~/.local/share/getjs` on a typical Linux installation). Installation downloads an official TruffleHog release and validates the archive against its published SHA-256 checksum before replacing the managed binary. Updates are explicit so an engagement remains reproducible; `status --check-updates` reports whether a newer official release exists.

#### Multi-Domain Options

| Option | Description | Default |
|--------|-------------|---------|
| `--threads <n>` | Concurrent threads for multi-URL | 3 |
| `--filter-domain <pattern...>` | Only include JS from matching domains | - |
| `--exclude-domain <pattern...>` | Exclude JS from matching domains | - |
| `--resume` | Skip URLs already in output file | - |

## Usage Examples

### Basic Reconnaissance

```bash
# Discover all JS files on a target
getjs -u https://target.com -o target-js.txt

# View results
cat target-js.txt
```

### Multi-Domain Scanning

```bash
# Scan multiple domains from a file
getjs -f targets.txt --output-dir ./results

# Per-target output filenames include the host, route, and a short URL hash.

# Pipe from stdin
cat targets.txt | getjs --output-dir ./results

# Combined output to single file
getjs -f targets.txt -o all-js-urls.txt

# Both per-domain and combined
getjs -f targets.txt --output-dir ./results -o combined.txt

# Control concurrency (default: 3 threads)
getjs -f targets.txt --threads 5 --output-dir ./results
```

**Target file format (`targets.txt`):**
```
# Bug bounty targets
https://target1.com
https://app.target2.com
https://staging.target3.com

# Subdomain from recon
https://api.target1.com
```

### Domain Filtering

```bash
# Only collect first-party JS
getjs -u https://target.com --filter-domain "*.target.com"

# Exclude known CDNs
getjs -u https://target.com --exclude-domain "*.googleapis.com" --exclude-domain "*.cloudflare.com"

# Combine filters
getjs -f targets.txt --filter-domain "*.target.com" --exclude-domain "*.cdn.target.com"
```

### JSON Output

```bash
# Structured output for downstream processing
getjs -u https://target.com --json

# Multi-domain JSON (grouped by target)
getjs -f targets.txt --json
```

Output format:
```json
{
  "https://target.com": {
    "count": 15,
    "urls": [
      "https://target.com/assets/app.js",
      "https://target.com/assets/vendor.js"
    ],
    "metadata": {
      "initialUrl": "https://target.com/",
      "finalUrl": "https://target.com/dashboard",
      "title": "Dashboard",
      "redirects": ["https://target.com/", "https://target.com/dashboard"],
      "failedRequests": [],
      "warnings": []
    },
    "downloads": { "completed": 0, "failed": [] },
    "error": null
  }
}
```

### Resume / Incremental Mode

```bash
# First scan
getjs -f targets.txt -o results.txt

# Later: re-scan and only append new URLs
getjs -f targets.txt -o results.txt --resume

# Works with --output-dir too
getjs -f targets.txt --output-dir ./results --resume
```

### With Burp Suite Proxy

```bash
# Route through Burp for inspection
getjs -u https://target.com -x http://127.0.0.1:8080 -o js-urls.txt
```

### Authenticated Scanning

For login-protected pages, you can inject cookies, headers, or localStorage:

```bash
# Recommended: open a browser, log in, then press Enter in the terminal
getjs auth -u https://target.com/dashboard -o /tmp/target-state.json
getjs -u https://target.com/dashboard --storage-state /tmp/target-state.json

# Using a cookie file (export from browser DevTools or EditThisCookie)
getjs -u https://target.com/dashboard -c cookies.json -v

# Using a raw Cookie header value (the optional "Cookie:" prefix is accepted)
getjs -u https://target.com/dashboard -c "session_id=abc123; token=eyJ...; cf_clearance=xyz"

# For cookies shared across sibling hosts, set the intended cookie domain
getjs -u https://app.target.com/dashboard -c "session=abc123" --cookie-domain .target.com

# Preferred for multi-host sessions: preserve cookies and localStorage by origin
getjs -u https://app.target.com/dashboard --storage-state browser-state.json

# Using HTTP headers (e.g., Authorization token)
getjs -u https://target.com/api -H "Authorization: Bearer eyJ..." -H "X-API-Key: abc123"

# Using a custom User-Agent string
getjs -u https://target.com -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Using localStorage (for JWT tokens stored client-side)
getjs -u https://target.com --local-storage "token=eyJ..." --local-storage "userId=123"

# Explicitly allow auth material on sibling domains when required
getjs -u https://app.target.com -H "Authorization: Bearer eyJ..." --auth-domain "*.target.com"

# Combined: cookies + custom headers
getjs -u https://target.com/admin -c session.json -H "X-CSRF-Token: xyz"
```

**Cookie file format (Playwright style):**
```json
[
  {
    "name": "session_id",
    "value": "abc123",
    "domain": "target.com",
    "path": "/",
    "httpOnly": true,
    "secure": true
  }
]
```

**Exporting cookies from browser:**
1. Open DevTools → Application → Cookies
2. Use browser extension like "EditThisCookie" to export as JSON
3. Or use: `document.cookie` in console and format manually

Raw cookies apply to one domain because a Cookie header does not contain browser cookie attributes. For applications that authenticate across sibling hosts, export every required cookie with its original domain or use a Playwright storage-state file. Custom headers and `--local-storage` are restricted to the exact target origin unless `--auth-domain` is supplied, preventing credentials from being copied to unrelated resources and frames.

`getjs auth` requires an interactive desktop session. Keep the browser open after logging in and press Enter in the terminal to save. Existing files are not overwritten unless `--force` is supplied, and saved state is restricted to mode `0600`. Treat storage-state files as credentials and delete or rotate them when the assessment ends.

### Download for Offline Analysis

```bash
# Discover and download all JS (auth-aware - carries browser cookies)
getjs -u https://target.com --fetch-all -d ./target-js/ -c cookies.json

# Skip duplicate files by content hash
getjs -u https://target.com --fetch-all -d ./target-js/ --dedupe-content

# Discover route-specific bundles without clicking controls
getjs -u https://target.com --crawl --max-pages 20 --fetch-all -d ./target-js/

# Analyze with other tools
grep -r "api_key" ./target-js/
grep -r "password" ./target-js/
```

Recursive analysis can find plausible JavaScript references that the browser did not request. Some may be incomplete runtime templates or stale paths and can legitimately return `404` during `--fetch-all`. These are reported as partial download failures without discarding successful downloads. Use `--no-recursive` when you only want browser-observed resources.

### Secret Scanning Pipeline

```bash
# Existing TruffleHog installation or managed binary
getjs -u https://target.com \
  --storage-state /tmp/target-state.json \
  --scan-secrets \
  --download-dir ./target-js

# First run: install the managed scanner, then collect/download/scan
getjs -u https://target.com \
  --scan-secrets \
  --install-scanner \
  --secret-report ./evidence/target-secrets.json \
  --download-dir ./target-js

# Update first, enable provider verification, and fail CI on findings
getjs -f targets.txt \
  --scan-secrets \
  --update-scanner \
  --verify-secrets \
  --fail-on-secret \
  --secret-report ./evidence/all-secrets.json
```

The report records the getjs version, TruffleHog path/version, verification setting, scanned files and hashes, summary counts, and complete TruffleHog finding objects. Public client identifiers and false positives can still be reported; findings require analyst review.

### Debugging

```bash
# Visible browser + verbose output
getjs -u https://target.com --no-headless -v

# Extended timeout for slow sites
getjs -u https://target.com -t 60 -w 10
```

### Silent Mode

```bash
# Suppress banner and status messages (clean output for piping)
getjs -u https://target.com -s

# Combine with other flags
getjs -u https://target.com -s -o results.txt
```

### Pipeline Integration

```bash
# Feed into other tools (silent mode for clean piping)
getjs -u https://target.com -s | httpx -silent

# Combine with nuclei
getjs -u https://target.com -s | nuclei -t exposures/

# Multi-domain with native file support (no shell loop needed)
getjs -f targets.txt -s | nuclei -t exposures/
```

## Programmatic Usage

```javascript
const { JSCollector, JSDownloader, scanDownloadedFiles } = require('getjs');

async function main() {
  // Initialize collector
  const collector = new JSCollector({
    headless: true,
    timeout: 30000,
    verbose: true,
  });

  try {
    // Collect JS URLs
    const urls = await collector.collect('https://example.com');
    console.log(`Found ${urls.length} JavaScript files:`);
    urls.forEach(url => console.log(url));

    // Download files (auth-aware when passing browser context)
    const downloader = new JSDownloader({
      outputDir: './js-files',
      verbose: true,
      context: collector.context, // Carries browser cookies
      headersForUrl: url => collector.headersForUrl(url),
    });

    const { results, errors } = await downloader.downloadAll(urls);
    console.log(`Downloaded ${results.length} files`);

    const secretScan = await scanDownloadedFiles(results, {
      downloadDir: './js-files',
      secretReport: './js-files/getjs-secrets.json',
      verifySecrets: false,
    });
    console.log(`Secret candidates: ${secretScan.total}`);

  } finally {
    await collector.close();
  }
}

main().catch(console.error);
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         getjs v2.2                          │
├─────────────────────────────────────────────────────────────┤
│  CLI (bin/getjs.js)                                         │
│  ├── Interactive authenticated-state capture                │
│  ├── URL input (single, file, stdin)                        │
│  ├── Multi-domain orchestrator (concurrent batches)         │
│  ├── Domain filtering (whitelist/blacklist)                 │
│  ├── Output routing (stdout, file, per-domain, JSON)        │
│  └── Resume/incremental mode                                │
├─────────────────────────────────────────────────────────────┤
│  JSCollector (src/collector.js)                              │
│  ├── Browser lifecycle (shared or standalone)                │
│  ├── Request/response/failure interception                   │
│  ├── DOM mutation observer (dynamic scripts)                 │
│  ├── Recursive module/import/worker extraction               │
│  ├── Scroll-triggered lazy loading                           │
│  ├── Optional bounded same-origin route crawling             │
│  ├── WebSocket monitoring                                    │
│  ├── Service Worker extraction                               │
│  └── URL normalization and deduplication                     │
├─────────────────────────────────────────────────────────────┤
│  JSDownloader (src/collector.js)                             │
│  ├── Auth-aware downloads (Playwright context)               │
│  ├── Raw HTTP/HTTPS fallback                                 │
│  ├── Content deduplication (SHA-256)                         │
│  ├── Bounded redirect following and response validation      │
│  └── Collision-safe URL-hashed filenames                     │
├─────────────────────────────────────────────────────────────┤
│  Secret Scanner (src/secret-scanner.js)                      │
│  ├── TruffleHog discovery and managed installation            │
│  ├── Official release checksum validation                     │
│  ├── Offline-by-default scanning                              │
│  └── Mode-0600 unredacted evidence reports                    │
└─────────────────────────────────────────────────────────────┘
```

## How It Works

1. **Browser Launch** - Starts a Chromium instance via Playwright (shared across domains in multi-mode)
2. **Interceptor Setup** - Attaches listeners for:
   - Network requests, responses, and failures
   - DOM mutations (catches dynamically injected scripts)
   - Sent and received WebSocket frames
   - BrowserContext Service Worker events
3. **Page Navigation** - Loads through `DOMContentLoaded`; later stages still run if background traffic never becomes idle
4. **DOM Extraction** - Extracts scripts, deferred sources, preloads, prefetches, and inline references from the main page and frames
5. **Scroll Triggering** - Scrolls the page to trigger lazy-loaded content
6. **Interaction Triggering** - Hovers over elements to trigger lazy loading
7. **Optional Route Crawl** - Visits bounded, safe-looking same-origin links without clicking controls
8. **Module Extraction** - Parses inline and external bundles with import-map awareness and safety limits
9. **Service Worker Extraction** - Detects inline registrations and registered workers through Playwright
10. **Normalization** - Converts URLs to absolute form and deduplicates
11. **Filtering and Downloads** - Applies domain filters before authenticated downloads
12. **Optional Secret Scan** - Runs TruffleHog against files downloaded by the current invocation
13. **Output** - Returns URLs plus redirect, failure, warning, download, and scan metadata in JSON mode

## Exit Status

| Code | Meaning |
|------|---------|
| `0` | Collection completed without target or download errors |
| `1` | The command could not run, such as invalid options, missing input, or browser startup failure |
| `2` | Collection produced usable results but one or more targets, inputs, or downloads failed |
| `3` | `--fail-on-secret` was enabled and the scan produced one or more findings |

## Limitations

- **CAPTCHAs** - Cannot bypass CAPTCHA challenges automatically
- **Heavily Obfuscated Loaders** - Custom loaders using eval() or complex string manipulation may evade detection
- **Encrypted WebSocket Payloads** - If JS URLs are encrypted in WS messages, they won't be detected
- **State Explosion** - No finite crawler can exercise every application state; `--crawl` is intentionally bounded and does not click controls
- **Computed Chunk Names** - Bundler URLs assembled entirely at runtime may require the corresponding feature to execute
- **Static Candidates** - Recursive parsing intentionally reports plausible references even when they later return `404`; use `--no-recursive` for runtime-only results
- **Secret Scanner Coverage** - TruffleHog scans downloaded files only; undiscovered chunks and runtime-only configuration remain outside the report
- **Candidate Quality** - Unverified findings, public identifiers, and false positives require manual review

## Future Improvements

- [x] ~~Cookie injection support for authenticated sessions~~ ✅ Implemented
- [x] ~~WebSocket traffic monitoring~~ ✅ Implemented
- [x] ~~Service worker script extraction~~ ✅ Implemented
- [x] ~~Concurrent multi-URL collection~~ ✅ Implemented
- [x] ~~Recursive external bundle parsing~~ ✅ Implemented
- [x] ~~Bounded same-origin route crawling~~ ✅ Implemented
- [x] ~~Interactive authenticated-state capture~~ ✅ Implemented
- [x] ~~Optional TruffleHog secret scanning pipeline~~ ✅ Implemented
- [x] ~~Managed scanner installation and updates~~ ✅ Implemented
- [ ] HAR file export
- [ ] Source map discovery and parsing
- [ ] Integration with waybackurls for historical JS discovery

## License

MIT

## Contributing

Pull requests welcome. For major changes, please open an issue first.
