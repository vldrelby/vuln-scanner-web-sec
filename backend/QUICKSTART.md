# Quick Start Guide

## Prerequisites

1. **Python 3.11+** installed
2. **Nmap** installed (optional, for network scanning)
3. **Nuclei** installed (optional, for vulnerability scanning)

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. (Optional) Install Nmap:
   - Windows: Download from https://nmap.org/download.html
   - Linux: `sudo apt-get install nmap`
   - macOS: `brew install nmap`

3. (Optional) Install Nuclei:
   - Download from https://github.com/projectdiscovery/nuclei/releases
   - Add to PATH

## Running the Server

### Option 1: Using Python directly
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Option 2: Using the run script
```bash
python run.py
```

### Option 3: Using Docker
```bash
docker-compose up -d
```

## Testing the API

### Health Check
```bash
curl http://localhost:8000/health
```

### Create a Scan
```bash
curl -X POST "http://localhost:8000/api/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://testphp.vulnweb.com",
    "scan_type": "custom"
  }'
```

### Get Scan Results
```bash
curl http://localhost:8000/api/scans/1
```

### Run Test Script
```bash
python test_scanner.py
```

## API Documentation

Once the server is running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Test Targets

Safe test targets for scanning:
- http://testphp.vulnweb.com (Acunetix test site)
- http://testfire.net (Altoro Mutual test site)

**WARNING**: Only scan targets you own or have explicit permission to test!

