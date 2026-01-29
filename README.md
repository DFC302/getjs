# getjs

A production-grade JavaScript URL extractor for security researchers. Loads web applications like a real browser, executing JavaScript to discover all JS files including dynamically loaded modules.

## Features

- **Real Browser Execution** - Uses Playwright/Chromium to execute JavaScript exactly like a real browser
- **Dynamic JS Detection** - Captures scripts loaded via:
  - Static `<script src>` tags
  - Dynamic script injection
  - ES6 module imports
  - `import()` dynamic imports
  - XHR/fetch loaded scripts
  - Lazy-loaded scripts triggered by scrolling
- **Smart URL Normalization** - Deduplicates and normalizes all discovered URLs
- **Download Mode** - Fetch all discovered JS files or a specific one
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

# Verify installation
getjs --version
```

### Option 2: Clone and Install Locally

```bash
# Clone the repository
git clone https://github.com/DFC302/getjs.git
cd getjs

# Install dependencies (this also installs Chromium)
npm install

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

### Post-Installation

The first run will automatically download Chromium (~170MB) via Playwright. If you need to manually trigger this:

```bash
npx playwright install chromium
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

# With verbose output
getjs -u https://example.com -v -o js-urls.txt

# Download all discovered JS files
getjs -u https://example.com --fetch-all -d ./js-files

# Run with visible browser (for debugging)
getjs -u https://example.com --no-headless
```

## CLI Reference

### Collect Command (Default)

```
getjs collect -u <url> [options]
getjs -u <url> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url <url>` | Target URL to analyze | Required |
| `-o, --output <file>` | Output file for JS URLs | stdout |
| `--headless` | Run browser in headless mode | true |
| `--no-headless` | Run browser with visible UI | - |
| `-t, --timeout <seconds>` | Page load timeout | 30 |
| `-w, --wait <seconds>` | Additional wait after load | 5 |
| `--no-scroll` | Disable automatic scrolling | - |
| `-A, --user-agent <string>` | Custom User-Agent | - |
| `-x, --proxy <url>` | Proxy server URL | - |
| `--fetch-all` | Download all discovered JS files | - |
| `--fetch-one <url>` | Download a specific JS file | - |
| `-d, --download-dir <dir>` | Directory for downloads | ./js-downloads |
| `-v, --verbose` | Verbose output | - |

### Download Command

```
getjs download -u <js-url> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url <url>` | JavaScript URL to download | Required |
| `-d, --download-dir <dir>` | Directory for downloaded file | ./js-downloads |
| `-v, --verbose` | Verbose output | - |

## Usage Examples

### Basic Reconnaissance

```bash
# Discover all JS files on a target
getjs -u https://target.com -o target-js.txt

# View results
cat target-js.txt
```

### With Burp Suite Proxy

```bash
# Route through Burp for inspection
getjs -u https://target.com -x http://127.0.0.1:8080 -o js-urls.txt
```

### Download for Offline Analysis

```bash
# Discover and download all JS
getjs -u https://target.com --fetch-all -d ./target-js/

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

### Pipeline Integration

```bash
# Feed into other tools
getjs -u https://target.com | httpx -silent

# Combine with nuclei
getjs -u https://target.com | nuclei -t exposures/

# Mass scanning with output per target
cat targets.txt | while read url; do
  domain=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)
  getjs -u "$url" -o "${domain}-js.txt"
done
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

    // Download files
    const downloader = new JSDownloader({
      outputDir: './js-files',
      verbose: true,
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
│                         getjs                                │
├─────────────────────────────────────────────────────────────┤
│  CLI (bin/getjs.js)                                         │
│  └── Command parsing, output formatting                      │
├─────────────────────────────────────────────────────────────┤
│  JSCollector (src/collector.js)                             │
│  ├── Browser lifecycle management (Playwright)              │
│  ├── Network interception (response listener)               │
│  ├── DOM mutation observer (dynamic scripts)                │
│  ├── Module import extraction (ES6 imports)                 │
│  ├── Scroll-triggered lazy loading                          │
│  └── URL normalization and deduplication                    │
├─────────────────────────────────────────────────────────────┤
│  JSDownloader (src/collector.js)                            │
│  ├── HTTP/HTTPS file fetching                               │
│  ├── Redirect following                                     │
│  └── Filename sanitization                                  │
└─────────────────────────────────────────────────────────────┘
```

## How It Works

1. **Browser Launch** - Starts a Chromium instance via Playwright
2. **Interceptor Setup** - Attaches listeners for:
   - Network responses (captures all JS by content-type/URL pattern)
   - DOM mutations (catches dynamically injected scripts)
   - Script creation (intercepts `document.createElement('script')`)
3. **Page Navigation** - Loads the target URL, waits for network idle
4. **DOM Extraction** - Extracts `<script src>` and `<link rel="preload">` elements
5. **Scroll Triggering** - Scrolls the page to trigger lazy-loaded content
6. **Interaction Triggering** - Hovers over elements to trigger lazy loading
7. **Module Extraction** - Parses inline `<script type="module">` for imports
8. **Normalization** - Converts all URLs to absolute, deduplicates
9. **Output** - Returns sorted list of JS URLs

## Limitations

- **Authentication** - Does not handle login-protected pages (use cookies/proxy)
- **CAPTCHAs** - Cannot bypass CAPTCHA challenges
- **Heavily Obfuscated Loaders** - Some custom loaders may evade detection
- **WebSocket-loaded JS** - JS loaded via WebSocket is not captured
- **Service Workers** - Scripts installed by service workers may not be captured

## Future Improvements

- [ ] Cookie injection support for authenticated sessions
- [ ] HAR file export
- [ ] Source map discovery and parsing
- [ ] Concurrent URL collection
- [ ] WebSocket traffic monitoring
- [ ] Service worker script extraction
- [ ] Integration with waybackurls for historical JS discovery

## License

MIT

## Contributing

Pull requests welcome. For major changes, please open an issue first.
