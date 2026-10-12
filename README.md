# getjs

A browser-backed JavaScript URL extractor for security researchers. It combines runtime network observation, DOM inspection, and bounded recursive bundle parsing to discover JavaScript used or referenced by web applications.

## README Reference

| Section | Contents |
|---------|----------|
| [Features](#features) | Supported discovery, authentication, download, scanning, and analysis capabilities |
| [Installation](#installation) | Prerequisites, setup methods, updates, troubleshooting, and uninstalling |
| [Choose a Workflow](#choose-a-workflow) | Commands for the most common getjs tasks |
| [Quick Start](#quick-start) | Short command examples for first-time use |
| [CLI Reference](#cli-reference) | Complete commands, options, defaults, and configuration |
| [Usage Examples](#usage-examples) | Reconnaissance, multi-domain, filtering, proxy, and pipeline examples |
| [Authenticated Scanning](#authenticated-scanning) | Cookies, storage state, custom headers, and interactive login workflows |
| [Secret Scanning Pipeline](#secret-scanning-pipeline) | TruffleHog collection, scanning, verification, and reporting |
| [AI-Assisted Analysis](#ai-assisted-javascript-analysis) | Codex and Claude endpoint or full security analysis |
| [Programmatic Usage](#programmatic-usage) | Using getjs as a Node.js library |
| [Architecture](#architecture) | Main components and data flow |
| [How It Works](#how-it-works) | End-to-end collection and analysis sequence |
| [Exit Status](#exit-status) | Process exit codes and meanings |
| [Limitations](#limitations) | Known coverage and validation boundaries |
| [Future Improvements](#future-improvements) | Implemented and planned work |
| [License](#license) | Project license |
| [Contributing](#contributing) | Contribution guidance |

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
- **Explicit Entry Points** - Visits one or more known application routes such as `/app` even when public navigation does not link to them
- **Passive API Inventory** - Records all same-origin XHR, fetch, SSE, and WebSocket connections observed by the browser regardless of response content type
- **HAR and Burp Import** - Merges scoped HAR entries, Burp XML history, or raw HTTP requests into the API inventory
- **Split Coverage** - Reports page visits, JavaScript/assets, and observed/imported APIs separately
- **Session Context** - Attaches user-supplied identity, role, and session labels to each observed endpoint
- **Authorization Leads** - Flags `/admin/`, `/recruiter/`, `/staff/`, `/internal/`, and related paths for manual authorization review
- **Safe Authorization Diff** - An explicit subcommand can compare previously observed same-origin GET/HEAD requests across unauthenticated and candidate sessions without storing response bodies
- **Authentication Support** - Access protected pages via:
  - Browser cookie exports, Netscape cookie jars, or raw cookie strings
  - Playwright storage-state files containing cookies and per-origin localStorage
  - Origin-scoped custom HTTP headers and localStorage values
- **Integrated Interactive Authentication** - Log in through a headed browser, preserve the live session, discard pre-login collection noise, and scan the authenticated application page
- **Authenticated Manual Exploration** - After login, click through application features while getjs retains the resulting scripts and API traffic; cross-host navigation no longer aborts collection
- **Reusable Auth Capture** - Save a mode-`0600` storage-state file with either `getjs auth` or the integrated collection workflow
- **Auth-Aware Downloads** - Downloaded JS files carry browser session cookies/headers
- **Safe Downloads** - Enforces size limits, rejects HTML responses, follows bounded redirects, scopes credentials per redirect, and uses collision-safe filenames
- **Navigation Diagnostics** - Reports final URLs, redirect chains, failed requests, and authentication-related redirects in JSON output
- **Partial Failure Recovery** - Fatal collection errors preserve discovered URLs, coverage metadata, and any available API inventory before exit
- **Domain Filtering** - Whitelist/blacklist JS URLs by domain pattern
- **Flexible Output** - Per-domain files, combined file, JSON, or stdout
- **Resume Mode** - Incremental scanning skips already-discovered URLs
- **Content Deduplication** - Skip duplicate JS files by content hash during download
- **Smart URL Normalization** - Deduplicates and normalizes all discovered URLs
- **Proxy Support** - Route traffic through Burp Suite or other proxies
- **Headless Toggle** - Run with visible browser for debugging
- **Secret Scanning Pipeline** - Discover, download, and scan JavaScript with TruffleHog in one command
- **Unredacted Evidence Reports** - Preserves complete findings in mode-`0600` JSON reports for validation
- **Managed TruffleHog** - Automatically installs the latest checksum-validated official release with getjs
- **Two AI Tasks** - Choose a compact endpoint inventory or the complete client-side security review
- **AI Endpoint Reconstruction** - Correlates URLs, methods, parameters, bodies, headers, authentication clues, GraphQL, and realtime channels without producing the full security report
- **Full AI Security Analysis** - Produces strict JSON plus readable Markdown covering endpoints, secrets, DOM sinks, `postMessage`, auth flows, client-side vulnerabilities, and prioritized follow-up checks
- **Custom Analysis Prompts** - Uses the shipped task-specific prompt by default, with per-run or config-file prompt and model overrides
- **Offline OpenAPI Export** - Converts an existing AI report into evidence-linked OpenAPI 3.1 JSON without another model call
- **Self-Contained Swagger UI** - Builds a portable, interactive HTML API explorer with embedded assets and no CDN or online validator

## Installation

### Prerequisites

- **Node.js 18+** - Required for Playwright compatibility
- **npm** - Comes with Node.js
- **tar** - Used to install managed TruffleHog (normally preinstalled on Linux/macOS and modern Windows)
- **Codex CLI or Claude Code CLI** - Optional; required only for `--ai`. Install and authenticate the provider separately before use.

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

# Verify both components
getjs --version
getjs scanner status

# Optional: verify an installed AI provider and inspect active settings
getjs ai status --provider codex
```

The npm installation automatically downloads the latest official TruffleHog release, validates its published SHA-256 checksum, and installs it in getjs's user data directory. Set `GETJS_SKIP_TRUFFLEHOG_INSTALL=1` before the npm command only when an offline or restricted installation must skip this step; you can install it later with `getjs scanner install`.

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

TruffleHog is installed automatically by getjs's npm installation. Verify the managed scanner with:

```bash
getjs scanner status
```

If installation scripts were disabled with npm's `--ignore-scripts` option, or `GETJS_SKIP_TRUFFLEHOG_INSTALL=1` was set, run `getjs scanner install` before using `--scan-secrets`. You can also add `--install-scanner` to the first scanning pipeline.

### Updating

```bash
# Update getjs from the private GitHub repository
npm install -g github:DFC302/getjs

# Updating getjs also checks and installs the latest managed scanner.
# This command can update only the scanner between getjs releases:
getjs scanner update

# Confirm the active versions and query the official release feed
getjs --version
getjs scanner status --check-updates
```

### Troubleshooting

**Permission errors during a global install on Linux/macOS:**

Use a user-owned npm prefix so getjs and its managed TruffleHog binary are installed for the same account:

```bash
mkdir -p "$HOME/.local"
npm config set prefix "$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
npm install -g github:DFC302/getjs
```

Add the `PATH` export to your shell profile to keep it across sessions. Avoid running the install with `sudo`, because the lifecycle hook would install the managed scanner for the root account rather than your normal user.

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

## Choose a Workflow

Most uses fit one of these commands:

| Goal | Command |
|------|---------|
| Find JavaScript URLs | `getjs -u https://example.com -o js-urls.txt` |
| Download the JavaScript | `getjs -u https://example.com --fetch-all -d ./js` |
| Build an AI endpoint inventory | `getjs -u https://example.com --ai --ai-task endpoints -d ./js` |
| Include a hidden application route | `getjs -u https://example.com --entrypoint /app --api-inventory` |
| Import proxy/browser history | `getjs -u https://example.com --har traffic.har --burp burp-history.xml --api-inventory` |
| Run the complete AI security review | `getjs -u https://example.com --ai --ai-task full -d ./js` |
| Compare safe requests across sessions | `getjs auth-diff -u https://example.com -i ./js/getjs-api-inventory.json --candidate-storage-state candidate.json` |

`--ai-task endpoints` is the focused everyday mode. It returns endpoints,
methods, parameters, request bodies, headers, authentication clues, GraphQL,
realtime channels, and exact evidence. It does not generate general security
findings, secret candidates, technology inventory, or a hunt plan.

`--ai-task full` is the original comprehensive analysis and remains the default
for backward compatibility. Use it when you want DOM sinks, `postMessage`,
client-side security findings, secrets, and prioritized follow-up work in
addition to endpoints.

Both tasks still review every selected byte. Inline scripts, JSON script blocks,
relevant server-rendered configuration, and the passive API inventory are added
as private analysis artifacts when present. Endpoint mode normally produces a
shorter response and avoids unrelated reasoning, but it currently uses the same
file/chunk pass boundaries as full mode, so the runtime improvement depends on
the provider and target. It is focused mode, not a reduced-coverage shortcut.

Provider and task are separate choices:

```bash
# Codex, endpoints only
getjs -u https://example.com --ai codex --ai-task endpoints

# Claude, full security review
getjs -u https://example.com --ai claude --ai-task full
```

Both AI tasks download first-party JavaScript automatically. Add `--crawl` for
route-specific scripts and `--storage-state` for authenticated pages. AI can
only analyze code that getjs collects; an endpoint absent from the collected
JavaScript cannot be reconstructed from static analysis.

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

# Recommended for endpoint hunting: compact AI endpoint inventory
getjs -u https://example.com --ai --ai-task endpoints -d ./js-files

# Complete client-side security analysis (also the default when --ai-task is omitted)
getjs -u https://example.com --ai --ai-task full -d ./js-files

# Select Claude for an endpoint-only run and save reports at an explicit path
getjs -u https://example.com --ai claude \
  --ai-task endpoints \
  --ai-report ./evidence/example-endpoints.json \
  -d ./js-files

# Generate OpenAPI during the same AI run (no additional model call)
getjs -u https://example.com --ai \
  --ai-task endpoints \
  --ai-report ./evidence/example-endpoints.json \
  --openapi ./evidence/example.openapi.json \
  --openapi-html ./evidence/example-swagger.html \
  -d ./js-files

# Or regenerate it later, entirely offline
getjs openapi \
  --input ./evidence/example-endpoints.json \
  --html ./evidence/example-swagger.html

# TruffleHog was installed with getjs; collect, download, and scan
getjs -u https://example.com --scan-secrets -d ./js-files

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
| `--no-source-maps` | Disable valid same-origin source-map discovery | Source-map discovery enabled |
| `--max-depth <n>` | Maximum recursive import depth | 3 |
| `--max-files <n>` | Maximum recursively parsed scripts | 500 |
| `--max-file-size <mb>` | Maximum parsed/downloaded script size | 10 |
| `--crawl` | Visit safe discovered same-origin GET links | - |
| `--max-pages <n>` | Maximum additional pages for `--crawl` | 10 |
| `-A, --user-agent <string>` | Custom User-Agent | - |
| `-x, --proxy <url>` | Proxy server URL | - |

#### Authentication Options

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --cookies <file\|string>` | Cookie file (JSON) or raw cookie string | - |
| `--storage-state <file>` | Playwright storage state with cookies/localStorage | - |
| `--interactive-auth` | Open a visible browser, pause for login, then collect using that live session | - |
| `--login-url <url>` | Login URL to open; relative URLs resolve against the target | Target URL |
| `--save-storage-state <file>` | Save the confirmed session for later runs (mode `0600`) | - |
| `--force-auth-state` | Overwrite an existing saved state file | - |
| `--auth-check-url <url>` | Same-origin URL requested after login to validate the session | - |
| `--auth-check-status <code>` | Required status from the authentication check | Any 2xx/3xx |
| `--auth-check-match <text>` | Required literal response marker from the authentication check | - |
| `--auth-check-not-match <text>` | Literal unauthenticated marker that causes validation to fail | - |
| `--cookie-domain <domain>` | Domain assigned to raw cookies | Target host |
| `-H, --header <header...>` | Extra HTTP headers | - |
| `--local-storage <entry...>` | Set localStorage entries | - |
| `--auth-domain <pattern...>` | Expand header/localStorage scope beyond target origin | Target origin only |
| `--session-identity <value>` | Label the identity associated with observed API requests | - |
| `--session-role <value>` | Label the role associated with observed API requests | - |
| `--session-label <value>` | Label the session, for example `candidate` | Inferred authenticated/unauthenticated label |

Identity and role values are analyst-supplied context. getjs records them but
does not independently prove which account or role the server assigned.

For a login that may involve passwords, MFA, SSO, consent, or CAPTCHA, use the
integrated workflow:

```bash
getjs -u https://apply.example.com/ \
  --interactive-auth \
  --login-url /login \
  --save-storage-state ./candidate.storage-state.json \
  --session-label candidate \
  --session-role candidate \
  --crawl \
  --api-inventory ./candidate-api.json \
  --fetch-all \
  --download-dir ./candidate-js
```

getjs opens the login URL in a visible browser and uses two prompts. First,
complete the entire login and press Enter. getjs then removes login-phase
scripts and traffic, reloads the authenticated application page, and starts a
clean capture phase. Click through the application and open the features you
want observed, then press Enter a second time to finish manual exploration and
continue the automated crawl and download steps.

The same browser context and tab are retained, including in-memory
`sessionStorage`. If a click takes that tab to another host, getjs records the
traffic, returns the tab to the authenticated target page, and continues rather
than aborting. Domain filters still decide which observed JavaScript is included
in output and downloads, while the original target origin defines API inventory
scope. An optional authentication check can prevent a mistaken confirmation
from starting collection.

`--interactive-auth` accepts exactly one target and requires a terminal. A
saved Playwright storage-state file contains cookies and localStorage but not
sessionStorage; the current integrated run still retains sessionStorage because
it does not replace the live context. Treat saved state as a credential.

If a fatal collector error occurs, getjs writes every URL collected up to that
point to the requested `--output`/`--output-dir`. Without either option it uses
`<download-dir>/getjs-partial-urls.txt`. A private adjacent `.partial.json`
records the error and coverage metadata, and any requested API inventory is
also written. JavaScript files downloaded before a later-stage failure remain
in the download directory.

#### Entry Points, API Inventory, and Imports

Use `--entrypoint` for authenticated or unlinked application roots that the
normal page and bounded crawler may never reach:

```bash
getjs -u https://apply.example.com \
  --storage-state candidate.json \
  --session-role candidate \
  --entrypoint /app /account \
  --api-inventory \
  --ai --ai-task endpoints \
  -d ./example-results
```

Each entry point must resolve to a safe URL on the target origin. It is visited
even without `--crawl`; `--crawl` additionally follows bounded same-origin links.

| Option | Description | Default |
|--------|-------------|---------|
| `--entrypoint <path...>` | One or more explicit same-origin pages to visit | - |
| `--api-inventory [file]` | Write the passive/imported API inventory | `<download-dir>/getjs-api-inventory.json` |
| `--api-report-dir <dir>` | Per-target API report directory in multi-target mode | `<download-dir>/getjs-api-inventory/` |
| `--har <file...>` | Import HAR files and keep only requests matching the target origin | - |
| `--burp <file...>` | Import Burp XML history or raw HTTP request files | - |

API inventory files are mode `0600`. Header and request-body values are not
stored; header names and parameter names are retained. URLs are retained as
observed, so query-string values can still be sensitive. Imported traffic is
scope-filtered to the target's exact origin.

Coverage is intentionally split:

- `pages` records planned, visited, and failed pages plus explicit entry points.
- `assets` records observed JavaScript, source maps, inline artifacts, download
  success/failure, and AI-selected artifacts.
- `api` records browser observations, imported observations, unique endpoint
  shapes, and WebSocket connections.

These are evidence counts, not a claim of complete application coverage.

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

#### Authorization Differential Command

`getjs auth-diff` is deliberately separate from passive collection. It replays
requests only when explicitly invoked, accepts only previously observed
same-origin `GET`/`HEAD` requests, excludes destructive/logout-like paths,
disables redirects, caps the request count, and stores hashes rather than
response bodies. By default it tests only role-significant paths; add
`--all-safe-get` to compare every eligible observed request.

```bash
getjs auth-diff \
  -u https://apply.example.com \
  -i ./results/getjs-api-inventory.json \
  --candidate-storage-state candidate.json \
  --candidate-label candidate \
  -o ./results/getjs-auth-diff.json
```

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url <url>` | Target origin used to enforce replay scope | Required |
| `-i, --input <file>` | Existing getjs API inventory | Required |
| `-o, --output <file>` | Private comparison report | `./getjs-auth-diff.json` |
| `--candidate-storage-state <file>` | Candidate Playwright session | One candidate auth option required |
| `--candidate-cookies <file\|string>` | Candidate cookies | - |
| `--candidate-header <header...>` | Candidate authorization header(s) | - |
| `--all-safe-get` | Include non-role-significant safe GET/HEAD requests | Disabled |
| `--max-endpoints <n>` | Maximum requests per session | 25 |
| `--max-response-kb <n>` | Maximum response bytes hashed in memory | 1024 KB |
| `--delay <ms>` | Delay between endpoint comparison pairs | 250 ms |

A difference is a lead, not proof of broken access control. In particular,
`candidate_access_to_role_significant_path` means the candidate received a 2xx
where the baseline did not; the response data and intended authorization still
require manual verification.

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

#### AI Analysis Options

`--ai` runs after collection and download. It enables `--fetch-all` when no fetch option was supplied, then gives the selected provider an isolated copy of the successfully downloaded files plus collected inline/configuration and API-inventory artifacts for that target. By default, AI mode infers the target's registrable domain and saves/analyzes only JavaScript from that apex and its subdomains; browser-observed Google, analytics, consent, video, and other third-party scripts are excluded. Use `--filter-domain` to supply the engagement scope explicitly or `--ai-include-third-party` to opt back into vendor analysis.

Choose the output with `--ai-task`:

- `endpoints` creates a compact endpoint report containing HTTP/API endpoints,
  methods, parameters, request bodies, headers, authentication clues, GraphQL,
  realtime channels, evidence, and coverage.
- `full` creates the comprehensive security report. It includes the endpoint
  inventory plus secrets, client-side findings, technologies, data entities,
  routes/features, and a prioritized hunt plan. This is the default.

Each task has its own shipped prompt and strict JSON Schema. `--prompt` replaces
the instructions for the selected task but retains that task's schema.
Observed/imported API endpoints are also merged into the validated AI inventory
deterministically, so a model omission cannot remove browser/proxy evidence.

| Option | Description | Default |
|--------|-------------|---------|
| `-a, --ai [provider]` | Analyze with `codex` or `claude` | Provider from config; `codex` initially |
| `--ai-task <task>` | Select `endpoints` or `full` output | `full` |
| `--ai-model <model>` | Override the configured provider model | Provider default |
| `--prompt <file>` | Replace the built-in analysis instructions for this run | Built-in prompt |
| `--ai-config <file>` | Read AI settings from another JSON file | Platform config path |
| `--ai-report <file>` | JSON report path for one target; concise Markdown is written beside it | Task-specific name in the download directory |
| `--ai-report-dir <dir>` | Per-target JSON and Markdown report directory | `<download-dir>/getjs-ai-analysis/` in multi-target mode |
| `--ai-timeout <seconds>` | Provider timeout for each full-review pass | 900 |
| `--ai-concurrency <n>` | Concurrent provider runs for multiple targets | 1 |
| `--ai-max-files <n>` | Maximum files sent per target | 250 |
| `--ai-max-total-size <mb>` | Maximum total input size per target | 100 MB |
| `--ai-max-inline-size <kb>` | Maximum source bytes in each provider pass | 512 KB |
| `--ai-include-third-party` | Download and analyze scripts outside the target apex scope | Disabled |
| `--openapi <file>` | Generate OpenAPI 3.1 JSON from this run's report without another model call; single-target mode only | Disabled |
| `--openapi-title <title>` | Override the generated OpenAPI title | Target hostname |
| `--openapi-html <file>` | Generate a self-contained Swagger UI page from this run's OpenAPI document | Disabled |
| `--swagger-try-it-out` | Permit live requests from generated Swagger UI; requires `--openapi-html` | Disabled |

Endpoint reports default to `<download-dir>/getjs-ai-endpoints.json`; full reports
default to `<download-dir>/getjs-ai-analysis.json`. Both receive a matching
Markdown file. OpenAPI generation accepts either JSON format.

Full reports include a reusable evidence ledger, endpoint and parameter inventory, GraphQL operations, WebSocket/SSE channels, routes and feature flags, sensitive data entities, secret candidates, technologies and third-party integrations, security findings, and a prioritized hunt plan. The full security review asks for DOM XSS sources and sinks, unsafe `postMessage`, client-side request forgery/open redirect behavior, prototype pollution, auth/OAuth/session weaknesses, storage and token exposure, service-worker and worker risks, risky file handling, business-logic clues, and missing browser defenses. These are static-analysis leads, not confirmed vulnerabilities.

Every byte of every selected file is supplied to the provider. Inputs larger than one safe provider request are divided into byte-range passes and merged into one report; getjs fails the AI stage if any pass fails. Valid same-origin source maps are downloaded by default, allowing embedded original sources to be reviewed alongside production bundles. Chunked review guarantees byte coverage, although a data flow crossing a chunk boundary can still require manual follow-up.

When selection limits skip nothing, reports say: “All collected JavaScript was
reviewed within the configured domain and analysis scope.” This refers only to
JavaScript that getjs collected and selected. It never means that the entire
application, every route, or every server endpoint was reviewed.

Both report types are created with mode `0600` because evidence can contain
sensitive source excerpts or literal request material. The provider may process
the downloaded code remotely under its own product settings. Use `--ai` only
when that is permitted by scope and policy.

#### AI Configuration Command

```text
getjs ai init [-o <config.json>] [--force]
getjs ai status [--provider codex|claude] [--task full|endpoints] [--ai-config <file>]
```

`getjs ai init` creates a private configuration file at `~/.config/getjs/config.json` on a typical Linux installation. The built-in defaults work without creating a file when the selected executable is already on `PATH`.

```json
{
  "ai": {
    "provider": "codex",
    "task": "full",
    "prompt": "builtin",
    "timeoutSeconds": 900,
    "maxFiles": 250,
    "maxTotalBytes": 104857600,
    "maxInlineBytes": 524288,
    "concurrency": 1
  },
  "providers": {
    "codex": { "executable": "codex", "model": null, "home": null },
    "claude": { "executable": "claude", "model": null }
  }
}
```

Relative prompt paths in the config are resolved from the config file's directory. `"builtin"` selects the prompt and schema shipped for the active task. Set `"task": "endpoints"` to make compact endpoint analysis your personal default. Command-line values override config values. `getjs ai status --task endpoints` resolves the executable and displays its version, model, endpoint prompt, schema, and active config before you run a target.

The mandatory execution wrapper remains in effect with a custom prompt: downloaded files are untrusted data, analysis is static and read-only, network activity is disabled where the provider supports it, and the response must match the bundled schema. A custom prompt changes the analysis goals, not these safety boundaries. getjs embeds each source range directly in provider input so analysis does not depend on model-initiated filesystem commands. For Codex, getjs creates a private temporary writable `CODEX_HOME` under the user's cache directory, copies an existing file-based `auth.json` into it with mode `0600`, and removes the temporary home after the run. This lets Codex write required process and socket state while the staged JavaScript files remain read-only. Set `providers.codex.home` when the authenticated source profile is somewhere other than `CODEX_HOME` or `~/.codex`. Final reports are written by getjs to the requested report path.

#### OpenAPI Generation Command

```text
getjs openapi --input <getjs-ai-report.json> [--output <openapi.json>] [--html <swagger.html>] [--title <title>] [--swagger-try-it-out]
```

This command is deterministic and offline: it reads either a compact endpoint report or a full AI report and does not start Codex, Claude, Chromium, or a network request. When `--output` is omitted, it writes `<input-name>.openapi.json` beside the report. The same conversion can run immediately after analysis with `--openapi <file>`; that convenience flag reuses the completed report and does not incur a second AI call.

Resolvable in-scope URLs with standard HTTP methods become OpenAPI 3.1 paths and operations. The converter maps path, query, header, cookie, JSON-body, form, and multipart parameters, while retaining auth clues, confidence, endpoint IDs, evidence IDs, notes, inferred request shapes, and response clues in `x-getjs-*` extensions. Same-apex API subdomains use operation-level `servers`. Dynamic URLs, unsupported or missing methods, and off-scope endpoints are preserved under `x-getjs-unresolved-endpoints` rather than guessed or discarded.

Add `--html <file>` to create a Petstore-style Swagger UI alongside the JSON. The generated page embeds the OpenAPI document, Swagger UI JavaScript, and CSS in one portable HTML file. It makes no CDN request, disables Swagger's online validator, blocks query-string configuration overrides, and uses a restrictive Content Security Policy. Routes are grouped into inferred tags to make large applications easier to browse.

The page is read-only by default. `--swagger-try-it-out` enables Swagger UI's live request controls and relaxes the page's network policy for HTTP(S) API requests. Use that option only with explicit authorization; browser CORS policy can still prevent requests. Credentials are not persisted by the page.

The document and viewer are inferred hunting aids, not authoritative server contracts. Both are written with mode `0600` because they may contain sensitive source-derived details.

#### Scanner Management Command

```text
getjs scanner install [--scanner-version <version>] [--force]
getjs scanner status [--check-updates]
getjs scanner update
```

Managed binaries are stored under the user's data directory (`~/.local/share/getjs` on a typical Linux installation). The npm installation downloads the latest official TruffleHog release and validates the archive against its published SHA-256 checksum before replacing the managed binary. Each later getjs installation checks for a newer release; between getjs installations, updates remain explicit through `scanner update` or a pipeline's `--update-scanner` flag. `status --check-updates` reports whether a newer official release exists.

#### Multi-Domain Options

| Option | Description | Default |
|--------|-------------|---------|
| `--threads <n>` | Concurrent threads for multi-URL | 3 |
| `--filter-domain <pattern...>` | Only include JS from matching apex/domain scopes | AI mode infers target apex |
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
# Only collect first-party JS; bare apex and wildcard both include subdomains
getjs -u https://target.com --filter-domain target.com

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
    "aiAnalysis": {
      "task": "full",
      "provider": "codex",
      "model": null,
      "reportPath": "/work/js-downloads/getjs-ai-analysis.json",
      "markdownPath": "/work/js-downloads/getjs-ai-analysis.md",
      "filesProvided": 12,
      "filesAnalyzed": 12,
      "endpoints": 31,
      "secrets": 2,
      "findings": 4,
      "huntPlanItems": 8,
      "complete": true,
      "providerCalls": 4,
      "openapi": {
        "outputPath": "/work/evidence/target.openapi.json",
        "paths": 24,
        "operations": 31,
        "unresolved": 5,
        "swaggerUI": {
          "outputPath": "/work/evidence/target-swagger.html",
          "tryItOut": false,
          "bytes": 1900000
        }
      }
    },
    "error": null
  }
}
```

`aiAnalysis` is present only with `--ai`. Endpoint mode sets `"task":
"endpoints"` and omits the `secrets`, `findings`, and `huntPlanItems` counters.
In multi-target mode, a failed provider run is recorded as `aiError` for that
target while other targets continue.

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
# The managed TruffleHog binary was installed automatically with getjs
getjs -u https://target.com \
  --storage-state /tmp/target-state.json \
  --scan-secrets \
  --download-dir ./target-js

# Recovery path when npm lifecycle scripts were deliberately skipped
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

### AI-Assisted JavaScript Analysis

Authenticate the provider CLI first, then verify that getjs can find it:

```bash
getjs ai status --provider codex
getjs ai status --provider claude
```

Run AI analysis:

```bash
# Focused endpoint inventory (recommended when endpoints are all you need)
getjs -u https://target.com --ai --ai-task endpoints -d ./target-js

# Complete security review; --ai-task full is optional because it is the default
getjs -u https://target.com --ai --ai-task full -d ./target-js

# Explicit provider, task, and model
getjs -u https://target.com --ai codex --ai-task endpoints --ai-model <model> -d ./target-js

# Claude endpoint analysis with an explicit private report location
getjs -u https://target.com --ai claude \
  --ai-task endpoints \
  --ai-report ./evidence/target-endpoints.json \
  -d ./target-js

# Multi-target analysis, with provider calls deliberately bounded
getjs -f targets.txt --ai codex \
  --ai-task endpoints \
  --ai-concurrency 2 \
  --ai-report-dir ./evidence/ai \
  -d ./target-js
```

Use a custom prompt while retaining the selected task's strict output shape:

```bash
getjs -u https://target.com --ai \
  --ai-task endpoints \
  --prompt ./prompts/my-analysis.md \
  --ai-report ./evidence/custom-endpoints.json \
  -d ./target-js
```

The custom prompt should describe what to extract and how to prioritize it; getjs supplies the target metadata, file manifest, mandatory safety instructions, and output schema. The JSON report is the canonical machine-readable artifact. The adjacent Markdown report is a concise analyst view generated deterministically from that JSON.

Create or recreate an OpenAPI document later without using an AI provider:

```bash
getjs openapi \
  --input ./evidence/target-analysis.json \
  --output ./evidence/target.openapi.json \
  --html ./evidence/target-swagger.html

# Explicitly enable live request controls for an authorized engagement
getjs openapi \
  --input ./evidence/target-analysis.json \
  --html ./evidence/target-swagger-live.html \
  --swagger-try-it-out
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
const {
  JSCollector,
  JSDownloader,
  analyzeDownloadedFiles,
  generateOpenAPIFile,
  resolveAISettings,
  scanDownloadedFiles,
} = require('getjs');

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

    const aiAnalysis = await analyzeDownloadedFiles(results, {
      settings: resolveAISettings({ ai: 'codex', aiTask: 'endpoints' }),
      target: 'https://example.com',
      workspace: './js-files',
      reportPath: './js-files/getjs-ai-endpoints.json',
    });
    console.log(`AI endpoints: ${aiAnalysis.endpoints}`);

    const openapi = generateOpenAPIFile(
      aiAnalysis.reportPath,
      './js-files/getjs.openapi.json',
      { htmlPath: './js-files/getjs-swagger.html' },
    );
    console.log(`OpenAPI operations: ${openapi.operations}`);

  } finally {
    await collector.close();
  }
}

main().catch(console.error);
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        getjs v2.9.1                         │
├─────────────────────────────────────────────────────────────┤
│  CLI (bin/getjs.js)                                         │
│  ├── Interactive authenticated-state capture                │
│  ├── URL input (single, file, stdin)                        │
│  ├── Multi-domain orchestrator (concurrent batches)         │
│  ├── Domain filtering (whitelist/blacklist)                 │
│  ├── Output routing (stdout, file, per-domain, JSON)        │
│  ├── Offline OpenAPI generation from canonical AI JSON     │
│  ├── Self-contained Swagger UI rendering                   │
│  └── Resume/incremental mode                                │
├─────────────────────────────────────────────────────────────┤
│  JSCollector (src/collector.js)                              │
│  ├── Browser lifecycle (shared or standalone)                │
│  ├── Request/response/failure interception                   │
│  ├── DOM mutation observer (dynamic scripts)                 │
│  ├── Recursive module/import/worker extraction               │
│  ├── Scroll-triggered lazy loading                           │
│  ├── Optional bounded same-origin route crawling             │
│  ├── Explicit entry-point visits and page coverage            │
│  ├── Same-origin XHR/fetch/SSE/WebSocket API inventory        │
│  ├── Inline script and server-configuration collection        │
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
├─────────────────────────────────────────────────────────────┤
│  AI Analyzer (src/ai-analyzer.js)                            │
│  ├── Codex and Claude CLI adapters                           │
│  ├── Per-target isolated, read-only analysis workspace       │
│  ├── Strict JSON Schema and evidence-reference validation    │
│  ├── Built-in or user-supplied analysis prompt               │
│  └── Mode-0600 canonical JSON and derived Markdown reports   │
├─────────────────────────────────────────────────────────────┤
│  Traffic/Auth Analysis                                       │
│  ├── HAR, Burp XML, and raw-request import                   │
│  ├── Role-significant path classification                    │
│  └── Explicit bounded GET/HEAD session differential testing  │
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
7. **Entry Points and Optional Crawl** - Visits explicit application roots and optionally follows bounded, safe-looking same-origin links without clicking controls
8. **API Observation** - Records same-origin XHR/fetch/SSE/WebSocket traffic and attaches the declared session context
9. **Inline Configuration Collection** - Preserves inline scripts, JSON script blocks, and relevant rendered metadata/data attributes for AI review
10. **Module Extraction** - Parses inline and external bundles with import-map awareness and safety limits
11. **Service Worker Extraction** - Detects inline registrations and registered workers through Playwright
12. **Optional Traffic Import** - Adds target-origin HAR or Burp observations to the API inventory
13. **Normalization** - Converts URLs to absolute form and deduplicates
14. **Filtering and Downloads** - Applies domain filters before authenticated downloads
15. **Optional Secret Scan** - Runs TruffleHog against files selected by the current invocation
16. **Optional AI Analysis** - Copies selected downloads and collection artifacts into a temporary workspace, invokes Codex or Claude with bounded permissions, validates the result, and creates JSON and Markdown reports
17. **Output** - Returns URLs plus separate page/asset/API coverage and report metadata in JSON mode

## Exit Status

| Code | Meaning |
|------|---------|
| `0` | Collection and requested analysis completed without errors |
| `1` | The command could not run, such as invalid options, missing input, or browser startup failure |
| `2` | The multi-target run produced usable results but one or more targets, inputs, downloads, or AI analyses failed |
| `3` | `--fail-on-secret` was enabled and the scan produced one or more findings |

## Limitations

- **CAPTCHAs** - Cannot bypass CAPTCHA challenges automatically
- **Heavily Obfuscated Loaders** - Custom loaders using eval() or complex string manipulation may evade detection
- **Encrypted WebSocket Payloads** - If JS URLs are encrypted in WS messages, they won't be detected
- **State Explosion** - No finite crawler can exercise every application state; `--crawl` is intentionally bounded and does not click controls
- **Observed API Coverage** - The API inventory includes only traffic exercised by visited pages or supplied through imports; it cannot enumerate unseen server routes
- **Role Labels Are Declarative** - Session identity and role labels come from the operator and are not verified against server-side account data
- **Differential Checks Are Leads** - Status/body-hash differences do not establish intended authorization or vulnerability impact
- **Computed Chunk Names** - Bundler URLs assembled entirely at runtime may require the corresponding feature to execute
- **Static Candidates** - Recursive parsing intentionally reports plausible references even when they later return `404`; use `--no-recursive` for runtime-only results
- **Secret Scanner Coverage** - TruffleHog scans downloaded files only; undiscovered chunks and runtime-only configuration remain outside the report
- **Candidate Quality** - Unverified findings, public identifiers, and false positives require manual review
- **AI Is Advisory** - Static model output can miss behavior or overstate a lead; validate every finding against the cited source and an authorized target
- **Provider Data Handling** - `--ai` can send downloaded source, embedded tokens, and source excerpts to the configured provider; review engagement and provider policies first
- **Minified and Obfuscated Code** - Models have finite context and may produce incomplete coverage when bundles are extremely large, generated, or intentionally obscured
- **No Active AI Validation** - The AI stage does not execute target code or make target requests; its suggested checks are a manual hunt plan

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
- [x] ~~Optional Codex/Claude analysis with structured hunt reports~~ ✅ Implemented
- [x] ~~Automatic same-origin source map discovery~~ ✅ Implemented
- [x] ~~Offline OpenAPI 3.1 generation from AI reports~~ ✅ Implemented
- [x] ~~Self-contained Swagger UI HTML generation~~ ✅ Implemented
- [x] ~~Same-origin browser API inventory with HAR/Burp import~~ ✅ Implemented
- [x] ~~Explicit application entry points and split page/asset/API coverage~~ ✅ Implemented
- [x] ~~Inline script and server-rendered configuration analysis~~ ✅ Implemented
- [x] ~~Session context, role-path flags, and safe authorization differential checks~~ ✅ Implemented
- [ ] HAR file export
- [ ] Integration with waybackurls for historical JS discovery

## License

MIT

## Contributing

Pull requests welcome. For major changes, please open an issue first.
