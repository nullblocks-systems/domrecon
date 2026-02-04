# DomRecon

A containerized Go application for domain reconnaissance and security analysis.

## Features

- **Subdomain Discovery** - Discovers subdomains using multiple sources (crt.sh, HackerTarget, ThreatCrowd, URLScan, AlienVault OTX)
- **HTTP Probing** - Validates live HTTP/HTTPS servers
- **Port Scanning** - Pure Go TCP connect scanner for common ports
- **Directory Enumeration** - Brute-force directory discovery with embedded wordlist
- **Vulnerability Scanning** - Security header analysis and common misconfigurations
- **Content Analysis** - Detects secrets, vulnerable libraries, and security issues

## Installation

### Docker (Recommended)

```bash
# Build the image
docker build -t domrecon .

# Run as a service
docker-compose up -d

# Or run a single scan
docker run --rm domrecon scan example.com
```

### From Source

```bash
go build -o domrecon ./cmd/domrecon
./domrecon scan example.com
```

## Usage

### CLI Mode

```bash
# Basic scan
domrecon scan example.com

# Scan with options
domrecon scan example.com --skip-ports --output text

# Output to file
domrecon scan example.com --output-file results.json
```

### Service Mode

```bash
# Start the server
domrecon serve --addr :8080

# Or with Docker
docker-compose up -d
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/scan` | POST | Synchronous scan |
| `/api/v1/scan/async` | POST | Asynchronous scan |

#### Scan Request

```json
{
  "domain": "example.com",
  "skip_nuclei": false,
  "skip_ports": false,
  "skip_dirs": false,
  "ports": ["80", "443", "8080"]
}
```

#### Example

```bash
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

## Configuration

Configuration can be provided via:
1. **Config file** - `/etc/domrecon/config.yaml`, `~/.domrecon/config.yaml`, or `./config.yaml`
2. **Environment variables** - Prefixed with `DOMRECON_` (e.g., `DOMRECON_CONCURRENCY=20`)
3. **CLI flags** - `--concurrency 20`

### Config File Example

```yaml
output: json
verbose: true
concurrency: 20

skip-nuclei: false
skip-ports: false
skip-dirs: false

ports:
  - "80"
  - "443"
  - "8080"
  - "8443"

addr: ":8080"
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DOMRECON_OUTPUT` | Output format (json/text) | json |
| `DOMRECON_VERBOSE` | Enable verbose logging | false |
| `DOMRECON_CONCURRENCY` | Number of concurrent workers | 10 |
| `DOMRECON_SKIP_NUCLEI` | Skip vulnerability scanning | false |
| `DOMRECON_SKIP_PORTS` | Skip port scanning | false |
| `DOMRECON_SKIP_DIRS` | Skip directory enumeration | false |
| `DOMRECON_ADDR` | Server listen address | :8080 |

## Output

### JSON Output Structure

```json
{
  "domain": "example.com",
  "start_time": "2024-01-01T00:00:00Z",
  "end_time": "2024-01-01T00:05:00Z",
  "subdomains": [
    {"name": "www.example.com", "source": "crt.sh"}
  ],
  "live_hosts": [
    {"url": "https://www.example.com", "status_code": 200, "title": "Example"}
  ],
  "open_ports": [
    {"host": "example.com", "port": 443, "service": "https", "state": "open"}
  ],
  "directories": [
    {"url": "https://example.com/admin", "status_code": 200, "size": 1234}
  ],
  "vulnerabilities": [
    {"template": "missing-hsts", "name": "Missing HSTS Header", "severity": "low", "host": "https://example.com"}
  ],
  "analysis": {
    "secrets": [],
    "vulnerable_libraries": [],
    "header_issues": [],
    "links": [],
    "new_subdomains": []
  }
}
```

## Architecture

```
domrecon/
├── cmd/domrecon/          # Main entry point
├── internal/
│   ├── config/            # Configuration handling
│   ├── types/             # Data types and output
│   ├── discovery/         # Subdomain and HTTP probing
│   ├── scanner/           # Port, directory, and vuln scanning
│   ├── analysis/          # Content analysis
│   ├── pipeline/          # Orchestration
│   └── server/            # HTTP API server
├── Dockerfile
├── docker-compose.yml
└── config.yaml
```

## License

MIT License
