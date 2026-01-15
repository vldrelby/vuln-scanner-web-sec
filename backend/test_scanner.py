"""
Simple test script to verify the scanner API is working.
"""

import asyncio
import httpx
import time


async def test_scanner():
    """Test the scanner API."""
    base_url = "http://localhost:8000"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Test health check
        print("Testing health endpoint...")
        response = await client.get(f"{base_url}/health")
        print(f"Health check: {response.status_code} - {response.json()}")
        
        # Create a scan
        print("\nCreating scan for testphp.vulnweb.com...")
        scan_request = {
            "target_url": "http://testphp.vulnweb.com",
            "scan_type": "custom",  # Start with custom scanner (fastest)
            "options": {}
        }
        
        response = await client.post(f"{base_url}/api/scans", json=scan_request)
        if response.status_code == 201:
            scan = response.json()
            scan_id = scan["id"]
            print(f"Scan created: ID {scan_id}")
            print(f"Status: {scan['status']}")
            
            # Poll for completion
            print("\nWaiting for scan to complete...")
            max_wait = 120  # 2 minutes
            waited = 0
            while waited < max_wait:
                await asyncio.sleep(5)
                response = await client.get(f"{base_url}/api/scans/{scan_id}")
                if response.status_code == 200:
                    scan = response.json()
                    status = scan["status"]
                    print(f"Scan status: {status}")
                    
                    if status == "completed":
                        print(f"\nScan completed! Found {len(scan['vulnerabilities'])} vulnerabilities")
                        
                        # Show vulnerabilities
                        for vuln in scan["vulnerabilities"][:5]:  # Show first 5
                            print(f"\n  - {vuln['title']} ({vuln['severity']})")
                            if vuln.get('affected_url'):
                                print(f"    URL: {vuln['affected_url']}")
                        
                        if len(scan["vulnerabilities"]) > 5:
                            print(f"\n  ... and {len(scan['vulnerabilities']) - 5} more")
                        break
                    elif status == "failed":
                        print(f"Scan failed: {scan.get('error_message', 'Unknown error')}")
                        break
                
                waited += 5
            
            if waited >= max_wait:
                print("Scan timeout - check status manually")
        else:
            print(f"Failed to create scan: {response.status_code} - {response.text}")


if __name__ == "__main__":
    print("Web Vulnerability Scanner - Test Script")
    print("=" * 50)
    asyncio.run(test_scanner())

