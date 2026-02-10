# getjs

A production-grade JavaScript URL extractor for security researchers. Loads web applications like a real browser, executing JavaScript to discover all JS files including dynamically loaded modules.

## Features

- **Real Browser Execution** - Uses Playwright/Chromium to execute JavaScript exactly like a real browser
- **Multi-Domain Support** - Process multiple targets from a file or stdin with concurrent threads
- **Dynamic JS Detection** - Captures scripts loaded via:
  - Static `<script src>` tags
  - Dynamic script injection
  - ES6 module imports
  - `import()` dynamic imports
  - XHR/fetch loaded scripts
  - Lazy-loaded scripts triggered by scrolling
  - **WebSocket messages** (monitors for JS URLs in WS traffic)
  - **Service Workers** (detects SW registrations and scripts)
- **Authentication Support** - Access protected pages via:
  - Cookie injection (JSON file)
  - Custom HTTP headers (Authorization, API keys)
  - localStorage injection (for client-side tokens)
- **Auth-Aware Downloads** - Downloaded JS files carry browser session cookies/headers
- **Domain Filtering** - Whitelist/blacklist JS URLs by domain pattern
- **Flexible Output** - Per-domain files, combined file, JSON, or stdout
- **Resume Mode** - Incremental scanning skips already-discovered URLs
- **Content Deduplication** - Skip duplicate JS files by content hash during download
- **Smart URL Normalization** - Deduplicates and normalizes all discovered URLs
- **Proxy Support** - Route traffic through Burp Suite or other proxies
- **Headless Toggle** - Run with visible browser for debugging

## Installation

### Prerequisites

- **Node.js 18+** - Required for Playwright compatibility
- **npm** - Comes with Node.js

Check your Node.js version:
```bash
node --version  # Should be v18.0.0 or higher
```

### Option 1: Install from GitHub (Recommended)

```bash
# Install globally from GitHub
npm install -g github:DFC302/getjs

# Install Chromium browser (required, one-time setup)
npx playwright install chromium

# Verify installation
getjs --version
```

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

### Post-Installation (Required)

After installing getjs, you must install the Chromium browser (~170MB):

```bash
npx playwright install chromium
```

This only needs to be done once per system.

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
| `-A, --user-agent <string>` | Custom User-Agent | - |
| `-x, --proxy <url>` | Proxy server URL | - |

#### Authentication Options

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --cookies <file\|string>` | Cookie file (JSON) or raw cookie string | - |
| `-H, --header <header...>` | Extra HTTP headers | - |
| `--local-storage <entry...>` | Set localStorage entries | - |

#### Download Options

| Option | Description | Default |
|--------|-------------|---------|
| `--fetch-all` | Download all discovered JS files | - |
| `--fetch-one <url>` | Download a specific JS file | - |
| `-d, --download-dir <dir>` | Directory for downloads | ./js-downloads |
| `--dedupe-content` | Skip duplicate files by content hash | - |

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

# Per-domain output files are created automatically:
# ./results/target_com.txt
# ./results/app_example_com.txt
# etc.

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
    ]
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
# Using a cookie file (export from browser DevTools or EditThisCookie)
getjs -u https://target.com/dashboard -c cookies.json -v

# Using a raw cookie string (domain auto-detected from -u URL)
getjs -u https://target.com/dashboard -c "session_id=abc123; token=eyJ...; cf_clearance=xyz"

# Using HTTP headers (e.g., Authorization token)
getjs -u https://target.com/api -H "Authorization: Bearer eyJ..." -H "X-API-Key: abc123"

# Using a custom User-Agent string
getjs -u https://target.com -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Using localStorage (for JWT tokens stored client-side)
getjs -u https://target.com --local-storage "token=eyJ..." --local-storage "userId=123"

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

### Download for Offline Analysis

```bash
# Discover and download all JS (auth-aware - carries browser cookies)
getjs -u https://target.com --fetch-all -d ./target-js/ -c cookies.json

# Skip duplicate files by content hash
getjs -u https://target.com --fetch-all -d ./target-js/ --dedupe-content

# Analyze with other tools
grep -r "api_key" ./target-js/
grep -r "password" ./target-js/
```

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
const { JSCollector, JSDownloader } = require('getjs');

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
      context: collector.context, // Carries cookies/headers
    });

    const { results, errors } = await downloader.downloadAll(urls);
    console.log(`Downloaded ${results.length} files`);

  } finally {
    await collector.close();
  }
}

main().catch(console.error);
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         getjs v2.0                          │
├─────────────────────────────────────────────────────────────┤
│  CLI (bin/getjs.js)                                         │
│  ├── URL input (single, file, stdin)                        │
│  ├── Multi-domain orchestrator (concurrent batches)         │
│  ├── Domain filtering (whitelist/blacklist)                 │
│  ├── Output routing (stdout, file, per-domain, JSON)        │
│  └── Resume/incremental mode                                │
├─────────────────────────────────────────────────────────────┤
│  JSCollector (src/collector.js)                              │
│  ├── Browser lifecycle (shared or standalone)                │
│  ├── Network interception (response listener)                │
│  ├── DOM mutation observer (dynamic scripts)                 │
│  ├── Module import extraction (ES6 imports)                  │
│  ├── Scroll-triggered lazy loading                           │
│  ├── WebSocket monitoring                                    │
│  ├── Service Worker extraction                               │
│  └── URL normalization and deduplication                     │
├─────────────────────────────────────────────────────────────┤
│  JSDownloader (src/collector.js)                             │
│  ├── Auth-aware downloads (Playwright context)               │
│  ├── Raw HTTP/HTTPS fallback                                 │
│  ├── Content deduplication (SHA-256)                         │
│  ├── Redirect following                                      │
│  └── Filename sanitization                                   │
└─────────────────────────────────────────────────────────────┘
```

## How It Works

1. **Browser Launch** - Starts a Chromium instance via Playwright (shared across domains in multi-mode)
2. **Interceptor Setup** - Attaches listeners for:
   - Network responses (captures all JS by content-type/URL pattern)
   - DOM mutations (catches dynamically injected scripts)
   - Script creation (intercepts `document.createElement('script')`)
   - WebSocket frames (monitors for JS URLs in WS payloads)
3. **Page Navigation** - Loads the target URL, waits for network idle
4. **DOM Extraction** - Extracts `<script src>` and `<link rel="preload">` elements
5. **Scroll Triggering** - Scrolls the page to trigger lazy-loaded content
6. **Interaction Triggering** - Hovers over elements to trigger lazy loading
7. **Module Extraction** - Parses inline `<script type="module">` for imports
8. **Service Worker Extraction** - Detects SW registrations and scripts via CDP
9. **Normalization** - Converts all URLs to absolute, deduplicates
10. **Filtering** - Applies domain whitelist/blacklist if configured
11. **Output** - Returns sorted list of JS URLs in chosen format

## Limitations

- **CAPTCHAs** - Cannot bypass CAPTCHA challenges automatically
- **Heavily Obfuscated Loaders** - Custom loaders using eval() or complex string manipulation may evade detection
- **Encrypted WebSocket Payloads** - If JS URLs are encrypted in WS messages, they won't be detected
- **iframe Isolation** - Scripts in cross-origin iframes may not be captured

## Future Improvements

- [x] ~~Cookie injection support for authenticated sessions~~ ✅ Implemented
- [x] ~~WebSocket traffic monitoring~~ ✅ Implemented
- [x] ~~Service worker script extraction~~ ✅ Implemented
- [x] ~~Concurrent multi-URL collection~~ ✅ Implemented
- [ ] HAR file export
- [ ] Source map discovery and parsing
- [ ] Cross-origin iframe script extraction
- [ ] Integration with waybackurls for historical JS discovery

## License

MIT

## Contributing

Pull requests welcome. For major changes, please open an issue first.
