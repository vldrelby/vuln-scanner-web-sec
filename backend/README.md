# Web Vulnerability Scanner

A comprehensive security scanning tool for web applications built with Python 3.11, FastAPI, and async execution.

## Features

- **Nmap Integration**: Network port scanning and service detection
- **Nuclei Integration**: Vulnerability scanning with custom templates
- **Custom Scanner**: Application-specific security checks:
  - HTTP security headers analysis
  - Open directory detection
  - Reflected XSS testing
  - Insecure cookie analysis
  - CORS misconfiguration detection
- **REST API**: Full REST API for scan management
- **SQLite Database**: Persistent storage of scan results
- **Docker Support**: Easy deployment with Docker
- **Async Execution**: Non-blocking scan execution
- **Normalized Results**: Standardized vulnerability format

## Architecture

The application follows clean architecture principles:

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration management
│   ├── database.py          # Database models and connection
│   ├── models.py            # Pydantic models
│   └── scanners/
│       ├── __init__.py
│       ├── base.py          # Base scanner interface
│       ├── nmap_scanner.py  # Nmap scanner
│       ├── nuclei_scanner.py # Nuclei scanner
│       └── custom_scanner.py # Custom security checks
├── config.yaml              # Configuration file
├── requirements.txt         # Python dependencies
├── Dockerfile              # Docker image
└── docker-compose.yml      # Docker Compose setup
```

## Installation

### Local Installation

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Install external tools:**
   - **Nmap**: `sudo apt-get install nmap` (Linux) or download from [nmap.org](https://nmap.org/)
   - **Nuclei**: Download from [projectdiscovery.io](https://github.com/projectdiscovery/nuclei)

3. **Configure:**
   - Copy `config.yaml` and adjust settings as needed
   - Optionally create `.env` file for environment variables

4. **Run:**
```bash
python -m uvicorn app.main:app --reload
```

### Docker Installation

1. **Build and run:**
```bash
docker-compose up -d
```

2. **View logs:**
```bash
docker-compose logs -f
```

## Configuration

Edit `config.yaml` to customize scanner behavior:

- **Scanner settings**: Timeouts, concurrency, user agent
- **Nmap settings**: Ports, scan types, arguments
- **Nuclei settings**: Templates path, severity filters, rate limits
- **Custom scanner**: Directories to check, XSS payloads, security headers

## API Endpoints

### Health Check
```
GET /health
```

### Create Scan
```
POST /api/scans
Body: {
  "target_url": "http://testphp.vulnweb.com",
  "scan_type": "full",  # nmap, nuclei, custom, or full
  "options": {}  # Optional scan-specific options
}
```

### List Scans
```
GET /api/scans?skip=0&limit=100
```

### Get Scan
```
GET /api/scans/{scan_id}
```

### Get Scan Vulnerabilities
```
GET /api/scans/{scan_id}/vulnerabilities?severity=high
```

### Delete Scan
```
DELETE /api/scans/{scan_id}
```

## Example Usage

### Using curl

```bash
# Create a scan
curl -X POST "http://localhost:8000/api/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://testphp.vulnweb.com",
    "scan_type": "full"
  }'

# Get scan results
curl "http://localhost:8000/api/scans/1"

# Get only high severity vulnerabilities
curl "http://localhost:8000/api/scans/1/vulnerabilities?severity=high"
```

### Using Python

```python
import httpx

# Create scan
response = httpx.post(
    "http://localhost:8000/api/scans",
    json={
        "target_url": "http://testphp.vulnweb.com",
        "scan_type": "custom"
    }
)
scan = response.json()

# Wait for scan to complete, then get results
results = httpx.get(f"http://localhost:8000/api/scans/{scan['id']}").json()
print(f"Found {len(results['vulnerabilities'])} vulnerabilities")
```

## Test Targets

The scanner can be tested against:

- **testphp.vulnweb.com**: Acunetix Web Vulnerability Test Site
- **testfire.net**: Altoro Mutual Test Site
- **DVWA**: Damn Vulnerable Web Application (requires local setup)

## Security Logic

### HTTP Headers Analysis
- Checks for missing security headers (X-Frame-Options, CSP, HSTS, etc.)
- Validates header values for insecure configurations
- Prevents clickjacking, MIME sniffing, and XSS attacks

### Open Directory Detection
- Tests common sensitive directories
- Detects directory listing pages
- Identifies information disclosure risks

### Reflected XSS Testing
- Injects XSS payloads into URL parameters
- Checks for unsanitized reflection in responses
- Tests multiple payload types to bypass filters

### Cookie Security
- Validates HttpOnly flag (prevents XSS cookie theft)
- Checks Secure flag (HTTPS-only transmission)
- Verifies SameSite attribute (CSRF protection)

### CORS Configuration
- Detects overly permissive CORS policies
- Identifies wildcard origins with credentials
- Prevents CSRF and unauthorized access

## Logging

Logs are written to:
- Console (stdout)
- File: `scanner.log` (configurable)

Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

## Database

SQLite database stores:
- Scan records with status and metadata
- Vulnerability findings with severity and evidence
- Timestamps for audit trail

Database file: `scanner.db` (configurable)

## Error Handling

- All scanners handle errors gracefully
- Failed scans are marked with error messages
- Partial results are saved even if some scanners fail
- Comprehensive logging for debugging

## License

This project is provided as-is for educational and testing purposes.

## Disclaimer

Only use this scanner on systems you own or have explicit permission to test. Unauthorized scanning may be illegal.

