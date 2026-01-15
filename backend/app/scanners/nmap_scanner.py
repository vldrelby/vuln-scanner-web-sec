"""
Nmap scanner implementation.
Performs network port scanning and service detection.
"""

import asyncio
import subprocess
import json
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from loguru import logger

from app.scanners.base import BaseScanner, ScanResult
from app.database import Severity
from app.config import settings


class NmapScanner(BaseScanner):
    """Nmap-based network scanner."""
    
    def __init__(self, config=None):
        """Initialize Nmap scanner."""
        super().__init__(config or settings.nmap)
        self.scanner_type = "nmap"
    
    async def scan(self, target_url: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Perform Nmap scan on target.
        
        Security Logic:
        - Extracts hostname/IP from URL
        - Runs Nmap with service detection and vulnerability scripts
        - Parses output to identify open ports, services, and vulnerabilities
        - Normalizes findings into standardized vulnerability format
        
        Args:
            target_url: Target URL to scan
            options: Optional scan options (ports, scan_type, etc.)
        
        Returns:
            ScanResult with discovered vulnerabilities
        """
        try:
            # Parse target URL to extract hostname/IP
            parsed = urlparse(target_url)
            target_host = parsed.hostname or target_url
            
            if not target_host:
                return ScanResult(
                    vulnerabilities=[],
                    error="Invalid target URL: could not extract hostname"
                )
            
            # Get scan options
            ports = options.get("ports", self.config.ports) if options else self.config.ports
            scan_type = options.get("scan_type", self.config.scan_type) if options else self.config.scan_type
            arguments = options.get("arguments", self.config.arguments) if options else self.config.arguments
            
            # Build Nmap command
            # Security: Using -sV for service version detection, -sC for default scripts
            # --script vuln runs vulnerability detection scripts
            # Map scan_type to proper nmap flags
            scan_flags = {
                "syn": "-sS",  # SYN scan (requires root)
                "connect": "-sT",  # TCP connect scan (no root needed)
                "udp": "-sU",  # UDP scan
                "ack": "-sA",  # ACK scan
            }
            scan_flag = scan_flags.get(scan_type.lower(), "-sT")  # Default to connect scan
            
            # Build command arguments
            cmd = ["nmap", scan_flag, "-p", ports]
            
            # Add additional arguments if provided
            if arguments and arguments.strip():
                # Split arguments and filter out empty strings
                arg_list = [arg for arg in arguments.split() if arg.strip()]
                cmd.extend(arg_list)
            else:
                # Default: fast scan with version detection
                cmd.extend(["-T4", "-sV", "-sC", "--max-retries", "1", "--host-timeout", "60s"])
            
            # Use XML output instead of JSON for better compatibility
            # JSON output to stdout doesn't work reliably, so we'll parse XML
            import tempfile
            import os
            temp_file = tempfile.NamedTemporaryFile(mode='w+', suffix='.xml', delete=False)
            temp_file.close()
            
            # Add XML output and target
            cmd.extend(["-oX", temp_file.name, target_host])
            
            logger.info(f"Running Nmap scan on {target_host} with ports {ports} (command: {' '.join(cmd)})")
            
            # Run Nmap in subprocess (async) with timeout
            try:
                process = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    ),
                    timeout=240  # 4 minute timeout to allow scripts to complete
                )
            except asyncio.TimeoutError:
                logger.error(f"Nmap scan timed out after 4 minutes for {target_host}")
                # Try to read partial results if file exists
                if os.path.exists(temp_file.name):
                    try:
                        with open(temp_file.name, 'r') as f:
                            partial_output = f.read()
                        if partial_output and len(partial_output) > 100:
                            logger.warning("Reading partial nmap results from timed out scan")
                            vulnerabilities = self._parse_nmap_xml_output(partial_output, target_url)
                            os.unlink(temp_file.name)
                            return ScanResult(
                                vulnerabilities=vulnerabilities,
                                error="Nmap scan timed out, but partial results were parsed."
                            )
                    except Exception as e:
                        logger.error(f"Error reading partial results: {e}")
                    os.unlink(temp_file.name)
                return ScanResult(
                    vulnerabilities=[],
                    error="Nmap scan timed out after 4 minutes. Try scanning fewer ports or use faster scan options."
                )
            
            stdout, stderr = await process.communicate()
            
            # Decode stderr for error messages
            error_output = stderr.decode('utf-8', errors='ignore') if stderr else ""
            
            # Log stderr for debugging (nmap often writes to stderr even on success)
            if error_output and "Failed to resolve" not in error_output and "Unable to split" not in error_output:
                logger.debug(f"Nmap stderr: {error_output[:200]}")
            
            # Read XML output from file
            try:
                with open(temp_file.name, 'r') as f:
                    output = f.read()
                os.unlink(temp_file.name)
            except Exception as e:
                logger.error(f"Error reading nmap output file: {e}")
                if os.path.exists(temp_file.name):
                    os.unlink(temp_file.name)
                return ScanResult(
                    vulnerabilities=[],
                    error=f"Failed to read nmap output: {str(e)}"
                )
            
            # Check if output is empty or invalid
            if not output.strip():
                if process.returncode != 0:
                    error_msg = error_output if error_output else "Nmap scan failed with no output"
                    logger.error(f"Nmap scan failed: {error_msg}")
                    return ScanResult(
                        vulnerabilities=[],
                        error=f"Nmap scan failed: {error_msg}"
                    )
                else:
                    logger.warning(f"Nmap scan returned empty output for {target_host}")
                    return ScanResult(
                        vulnerabilities=[],
                        metadata={"host": target_host, "ports_scanned": ports, "scan_type": scan_type},
                        error="Nmap scan completed but returned no results"
                    )
            
            # Parse XML output
            logger.debug(f"XML output length: {len(output)} characters")
            logger.debug(f"XML output preview: {output[:500]}")
            vulnerabilities = self._parse_nmap_xml_output(output, target_url)
            
            metadata = {
                "host": target_host,
                "ports_scanned": ports,
                "scan_type": scan_type
            }
            
            logger.info(f"Nmap scan completed: found {len(vulnerabilities)} vulnerabilities")
            if len(vulnerabilities) == 0:
                logger.warning(f"No vulnerabilities found for {target_host}. XML output may be empty or invalid.")
            
            return ScanResult(
                vulnerabilities=vulnerabilities,
                metadata=metadata
            )
            
        except FileNotFoundError:
            error_msg = "Nmap not found. Please install Nmap and ensure it's in PATH."
            logger.error(error_msg)
            return ScanResult(
                vulnerabilities=[],
                error=error_msg
            )
        except Exception as e:
            logger.exception(f"Error during Nmap scan: {e}")
            return ScanResult(
                vulnerabilities=[],
                error=f"Scan error: {str(e)}"
            )
    
    def _parse_nmap_xml_output(self, output: str, target_url: str) -> List:
        """
        Parse Nmap XML output and extract vulnerabilities.
        
        Security Logic:
        - Identifies open ports with vulnerable services
        - Extracts CVE information from vulnerability scripts
        - Categorizes findings by severity based on CVE scores
        - Maps service versions to known vulnerabilities
        - Reports open ports and services as informational findings
        
        Args:
            output: Nmap XML output
            target_url: Original target URL
        
        Returns:
            List of VulnerabilityResponse objects
        """
        vulnerabilities = []
        open_ports_found = []
        
        try:
            # Parse XML
            if not output or not output.strip():
                logger.error("Nmap XML output is empty!")
                return vulnerabilities
            
            logger.debug(f"Parsing nmap XML output, length: {len(output)}")
            root = ET.fromstring(output)
            
            # Find all hosts
            hosts = root.findall('.//host')
            logger.info(f"Found {len(hosts)} hosts in XML")
            
            if len(hosts) == 0:
                logger.warning("No hosts found in XML output!")
                return vulnerabilities
            
            for host in hosts:
                # Find all ports
                ports_elem = host.find('ports')
                if ports_elem is None:
                    logger.warning("No ports element found in host! This may indicate nmap scan failed or timed out.")
                    # Try to find ports directly
                    ports = host.findall('.//port')
                    if len(ports) > 0:
                        logger.info(f"Found {len(ports)} ports directly in host (ports element missing)")
                    else:
                        logger.error("No ports found at all in host XML!")
                        continue
                else:
                    ports = ports_elem.findall('port')
                    logger.info(f"Found {len(ports)} ports in host")
                
                if len(ports) == 0:
                    logger.warning("No ports found in XML! This may indicate nmap scan failed or timed out.")
                    # Still try to process - maybe ports are in different location
                    continue
                
                for port_elem in ports:
                    port_id = port_elem.get('portid', 'unknown')
                    # Get port state
                    state_elem = port_elem.find('state')
                    if state_elem is None:
                        logger.debug(f"Port {port_id} has no state element, skipping")
                        continue
                    
                    port_state = state_elem.get('state')
                    logger.debug(f"Port {port_id} state: {port_state}")
                    if port_state != 'open':
                        logger.debug(f"Port {port_id} is {port_state}, skipping")
                        continue
                    
                    logger.info(f"Processing open port {port_id}")
                    
                    port = port_elem.get('portid')
                    protocol = port_elem.get('protocol', 'tcp')
                    
                    # Get service information
                    service_elem = port_elem.find('service')
                    service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                    service_version = service_elem.get('version', '') if service_elem is not None else ''
                    service_product = service_elem.get('product', '') if service_elem is not None else ''
                    
                    # Combine version info
                    if service_product and service_version:
                        full_version = f"{service_product} {service_version}"
                    elif service_version:
                        full_version = service_version
                    elif service_product:
                        full_version = service_product
                    else:
                        full_version = ""
                    
                    open_ports_found.append({
                        "port": port,
                        "service": service_name,
                        "version": full_version,
                        "product": service_product
                    })
                    
                    # Check for scripts (vulnerability detection and information gathering)
                    # Nmap can have multiple script elements
                    scripts_elems = port_elem.findall('script')
                    logger.debug(f"Found {len(scripts_elems)} scripts for port {port}")
                    vulnerability_found = False
                    script_info = {}
                    
                    for scripts_elem in scripts_elems:
                        script_id = scripts_elem.get('id', '')
                        script_output = scripts_elem.get('output', '')
                        
                        # Get output text - can be in output attribute or text content
                        if not script_output:
                            script_output = scripts_elem.text if scripts_elem.text else ''
                        
                        if not script_output:
                            continue
                        
                        # Store script information for later use
                        script_info[script_id] = script_output
                        
                        # Parse vulners script output (has structured table format)
                        if script_id == 'vulners':
                            logger.info(f"Processing vulners script for port {port}")
                            # Extract CVE from table structure
                            tables = scripts_elem.findall('.//table')
                            logger.info(f"Found {len(tables)} vulnerability tables in vulners output")
                            cves_found = []
                            
                            if len(tables) == 0:
                                logger.warning(f"No vulnerability tables found in vulners output for port {port}")
                                # Try to extract CVE from text output as fallback
                                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                                text_cves = re.findall(cve_pattern, script_output, re.IGNORECASE)
                                if text_cves:
                                    logger.info(f"Found {len(text_cves)} CVEs in vulners text output")
                                    for cve in list(dict.fromkeys(text_cves))[:5]:
                                        cves_found.append({
                                            'cve': cve,
                                            'id': cve,
                                            'cvss': 7.0,  # Default to high severity
                                            'is_exploit': False
                                        })
                            for table in tables:
                                id_elem = table.find('.//elem[@key="id"]')
                                cvss_elem = table.find('.//elem[@key="cvss"]')
                                is_exploit_elem = table.find('.//elem[@key="is_exploit"]')
                                
                                if id_elem is not None and id_elem.text:
                                    vuln_id = id_elem.text
                                    cvss_score = float(cvss_elem.text) if cvss_elem is not None and cvss_elem.text else 0.0
                                    is_exploit = is_exploit_elem.text == 'true' if is_exploit_elem is not None else False
                                    
                                    # Extract CVE from ID (format: NGINX:CVE-2022-41741 or CVE-2022-41741)
                                    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', vuln_id, re.IGNORECASE)
                                    if cve_match:
                                        cve = cve_match.group(0)
                                        cves_found.append({
                                            'cve': cve,
                                            'id': vuln_id,
                                            'cvss': cvss_score,
                                            'is_exploit': is_exploit
                                        })
                            
                            logger.debug(f"Found {len(cves_found)} CVEs from vulners script")
                            # Create vulnerability for each high-severity CVE
                            for cve_info in cves_found[:5]:  # Limit to top 5
                                if cve_info['cvss'] >= 7.0:  # High/Critical severity
                                    logger.info(f"Creating vulnerability for CVE {cve_info['cve']} (CVSS: {cve_info['cvss']})")
                                    severity = Severity.CRITICAL if cve_info['cvss'] >= 9.0 else Severity.HIGH
                                    
                                    vuln = self.create_vulnerability(
                                        title=f"CVE Found: {cve_info['cve']} in {service_name} {full_version}",
                                        description=(
                                            f"Critical vulnerability {cve_info['cve']} (CVSS: {cve_info['cvss']}) "
                                            f"identified in {service_name} version {full_version} on port {port}. "
                                            f"{'Exploit available!' if cve_info['is_exploit'] else ''} "
                                            f"Vulnerability ID: {cve_info['id']}"
                                        ),
                                        severity=severity,
                                        affected_url=f"{target_url}:{port}",
                                        cve=cve_info['cve'],
                                        recommendation=(
                                            f"Immediately update {service_name} to a patched version. "
                                            f"Apply security patches for {cve_info['cve']}. "
                                            f"Review vendor advisories and security bulletins."
                                        ),
                                        evidence={
                                            "port": port,
                                            "service": service_name,
                                            "version": full_version,
                                            "cve": cve_info['cve'],
                                            "cvss": cve_info['cvss'],
                                            "is_exploit": cve_info['is_exploit'],
                                            "vulnerability_id": cve_info['id']
                                        }
                                    )
                                    vulnerabilities.append(vuln)
                                    vulnerability_found = True
                        
                        # Check for VULNERABLE keyword
                        if "vulnerable" in script_output.lower() or "vulnerability" in script_output.lower():
                            # Extract CVE information
                            cve_pattern = r'CVE-\d{4}-\d{4,7}'
                            cves = re.findall(cve_pattern, script_output, re.IGNORECASE)
                            
                            severity = self._determine_severity_from_script(script_output, script_id)
                            
                            vuln_desc = script_output[:500] if len(script_output) > 500 else script_output
                            
                            vuln = self.create_vulnerability(
                                title=f"Vulnerability Detected: {service_name} on port {port}",
                                description=(
                                    f"Security vulnerability detected in {service_name} service "
                                    f"running on port {port}/{protocol}. "
                                    f"Script: {script_id}. "
                                    f"Details: {vuln_desc}"
                                ),
                                severity=severity,
                                affected_url=f"{target_url}:{port}",
                                cve=cves[0] if cves else None,
                                recommendation=(
                                    f"Immediately address this vulnerability in {service_name} on port {port}. "
                                    f"{f'Update to latest version (current: {full_version}). ' if full_version else ''}"
                                    f"Review and apply security patches for identified CVEs. "
                                    f"Review script output for specific remediation steps. "
                                    f"Consider disabling the service if not required."
                                ),
                                evidence={
                                    "port": port,
                                    "protocol": protocol,
                                    "service": service_name,
                                    "version": full_version,
                                    "script_id": script_id,
                                    "script_output": script_output,
                                    "cves": cves
                                }
                            )
                            vulnerabilities.append(vuln)
                            vulnerability_found = True
                        
                        # Check for CVE patterns from other scripts (skip vulners as it's handled above)
                        elif script_id and script_id != 'vulners':
                            cve_pattern = r'CVE-\d{4}-\d{4,7}'
                            cves = re.findall(cve_pattern, script_output, re.IGNORECASE)
                            if cves:
                                # Remove duplicates
                                cves = list(dict.fromkeys(cves))
                                severity = Severity.HIGH if len(cves) > 0 else Severity.MEDIUM
                                
                                vuln = self.create_vulnerability(
                                    title=f"CVE Found: {service_name} on port {port}",
                                    description=(
                                        f"CVE(s) identified for {service_name} service "
                                        f"on port {port}: {', '.join(cves[:3])}. "
                                        f"Script: {script_id}."
                                    ),
                                    severity=severity,
                                    affected_url=f"{target_url}:{port}",
                                    cve=cves[0],
                                    recommendation=(
                                        f"Review and patch identified CVEs: {', '.join(cves[:3])}. "
                                        f"Update {service_name} to a patched version."
                                    ),
                                    evidence={
                                        "port": port,
                                        "service": service_name,
                                        "version": full_version,
                                        "script_id": script_id,
                                        "cves": cves
                                    }
                                )
                                vulnerabilities.append(vuln)
                                vulnerability_found = True
                        
                        # Extract HTTP security headers information
                        if script_id == "http-security-headers":
                            missing_headers = []
                            if "X-Frame-Options" not in script_output:
                                missing_headers.append("X-Frame-Options")
                            if "X-Content-Type-Options" not in script_output:
                                missing_headers.append("X-Content-Type-Options")
                            if "Strict-Transport-Security" not in script_output and port == "443":
                                missing_headers.append("Strict-Transport-Security")
                            
                            if missing_headers:
                                vuln = self.create_vulnerability(
                                    title=f"Missing Security Headers: {service_name} on port {port}",
                                    description=(
                                        f"Security headers are missing on {service_name} service "
                                        f"running on port {port}. Missing headers: {', '.join(missing_headers)}. "
                                        f"This can expose the application to clickjacking, MIME type sniffing, "
                                        f"and other attacks."
                                    ),
                                    severity=Severity.MEDIUM,
                                    affected_url=f"{target_url}:{port}",
                                    recommendation=(
                                        f"Configure the web server to include security headers: {', '.join(missing_headers)}. "
                                        f"Review OWASP guidelines for security header implementation."
                                    ),
                                    evidence={
                                        "port": port,
                                        "service": service_name,
                                        "missing_headers": missing_headers,
                                        "script_output": script_output
                                    }
                                )
                                vulnerabilities.append(vuln)
                        
                        # Extract HTTP methods information
                        if script_id == "http-methods":
                            dangerous_methods = []
                            if "PUT" in script_output:
                                dangerous_methods.append("PUT")
                            if "DELETE" in script_output:
                                dangerous_methods.append("DELETE")
                            if "PATCH" in script_output:
                                dangerous_methods.append("PATCH")
                            if "TRACE" in script_output:
                                dangerous_methods.append("TRACE")
                            
                            if dangerous_methods:
                                vuln = self.create_vulnerability(
                                    title=f"Dangerous HTTP Methods Enabled: {service_name} on port {port}",
                                    description=(
                                        f"Dangerous HTTP methods are enabled on {service_name} service "
                                        f"running on port {port}. Enabled methods: {', '.join(dangerous_methods)}. "
                                        f"These methods can allow unauthorized modification or deletion of resources."
                                    ),
                                    severity=Severity.MEDIUM,
                                    affected_url=f"{target_url}:{port}",
                                    recommendation=(
                                        f"Disable unnecessary HTTP methods: {', '.join(dangerous_methods)}. "
                                        f"Only allow GET, POST, and OPTIONS if not needed for API functionality."
                                    ),
                                    evidence={
                                        "port": port,
                                        "service": service_name,
                                        "dangerous_methods": dangerous_methods,
                                        "script_output": script_output
                                    }
                                )
                                vulnerabilities.append(vuln)
                        
                        # Extract HTTP server header information
                        if script_id == "http-server-header" and script_output:
                            # Check for outdated versions
                            if "nginx" in script_output.lower() and "1.19" in script_output:
                                vuln = self.create_vulnerability(
                                    title=f"Outdated Server Version: {service_name} on port {port}",
                                    description=(
                                        f"Server is running an outdated version: {script_output.strip()}. "
                                        f"Older versions may contain known security vulnerabilities. "
                                        f"Current version should be reviewed against latest stable release."
                                    ),
                                    severity=Severity.MEDIUM,
                                    affected_url=f"{target_url}:{port}",
                                    recommendation=(
                                        f"Update server to the latest stable version. "
                                        f"Review changelog for security fixes and apply patches."
                                    ),
                                    evidence={
                                        "port": port,
                                        "service": service_name,
                                        "server_header": script_output.strip(),
                                        "script_id": script_id
                                    }
                                )
                                vulnerabilities.append(vuln)
                    
                    # Check for outdated/insecure service versions
                    if full_version and self._is_insecure_service(service_name, full_version):
                        vuln = self.create_vulnerability(
                            title=f"Potentially Insecure Service Version: {service_name} {full_version}",
                            description=(
                                f"Service {service_name} version {full_version} on port {port} "
                                f"may contain known vulnerabilities. "
                                f"Older versions often have unpatched security issues."
                            ),
                            severity=Severity.MEDIUM,
                            affected_url=f"{target_url}:{port}",
                            recommendation=(
                                f"Update {service_name} to the latest stable version. "
                                f"Review changelog for security fixes."
                            ),
                            evidence={
                                "port": port,
                                "service": service_name,
                                "version": full_version
                            }
                        )
                        vulnerabilities.append(vuln)
                    
                    # Always report open ports with detailed information
                    if service_name != "unknown":
                        # Create detailed port information
                        port_info_parts = [f"Port {port}/{protocol}"]
                        if service_name:
                            port_info_parts.append(f"Service: {service_name}")
                        if full_version:
                            port_info_parts.append(f"Version: {full_version}")
                        
                        # Get additional service info from XML
                        service_extrainfo = ""
                        if service_elem is not None:
                            extrainfo = service_elem.get('extrainfo', '')
                            if extrainfo:
                                service_extrainfo = f" ({extrainfo})"
                        
                        # Get service method if available
                        service_method = service_elem.get('method', '') if service_elem is not None else ''
                        if service_method:
                            port_info_parts.append(f"Method: {service_method}")
                        
                        # Extract additional information from scripts
                        http_title = script_info.get('http-title', '')
                        http_headers = script_info.get('http-headers', '')
                        http_enum = script_info.get('http-enum', '')
                        
                        # Build comprehensive description
                        description_parts = [
                            f"Open port detected: {', '.join(port_info_parts)}{service_extrainfo}."
                        ]
                        
                        if http_title:
                            title_text = http_title.strip().split('\n')[0][:100]
                            if title_text:
                                description_parts.append(f"Page title: {title_text}")
                        
                        if http_enum:
                            enum_items = []
                            for line in http_enum.split('\n')[:10]:
                                line = line.strip()
                                if line and not line.startswith('|') and 'http' in line.lower():
                                    # Extract URL from line
                                    url_match = re.search(r'http://[^\s]+', line)
                                    if url_match:
                                        enum_items.append(url_match.group(0)[:80])
                            if enum_items:
                                description_parts.append(f"Discovered {len(enum_items)} paths/endpoints")
                        
                        description_parts.append(
                            "This port is accessible and should be reviewed for security configuration."
                        )
                        
                        if not vulnerability_found:
                            description_parts.append(
                                "No critical vulnerabilities detected by nmap scripts, "
                                "but the service should still be reviewed and kept up to date."
                            )
                        
                        description = " ".join(description_parts)
                        
                        # Always create info finding for open ports (even if vulnerabilities found)
                        logger.debug(f"Creating port finding for {port}/{service_name}")
                        vuln = self.create_vulnerability(
                            title=f"Open Port: {port}/{service_name}{f' ({full_version})' if full_version else ''}",
                            description=description,
                            severity=Severity.INFO if vulnerability_found else Severity.LOW,
                            affected_url=f"{target_url}:{port}",
                            recommendation=(
                                f"Review security configuration for {service_name} on port {port}. "
                                f"{f'Update to latest version (current: {full_version}). ' if full_version else ''}"
                                f"Ensure service is properly configured and patched. "
                                f"Restrict access if not needed. "
                                f"Review firewall rules and network segmentation."
                            ),
                            evidence={
                                "port": port,
                                "protocol": protocol,
                                "service": service_name,
                                "version": full_version,
                                "extrainfo": service_extrainfo,
                                "method": service_method,
                                "state": "open",
                                "http_title": http_title[:200] if http_title else None,
                                "scripts_run": list(script_info.keys()),
                                "vulnerabilities_found": vulnerability_found
                            }
                        )
                        vulnerabilities.append(vuln)
        
        except ET.ParseError as e:
            logger.error(f"Error parsing Nmap XML output: {e}")
            logger.debug(f"Nmap XML output (first 500 chars): {output[:500]}")
        except Exception as e:
            logger.error(f"Error parsing Nmap output: {e}")
            logger.debug(f"Nmap output (first 500 chars): {output[:500]}")
        
        # Log summary
        if open_ports_found:
            port_list = [f"{p['port']}/{p['service']}" for p in open_ports_found[:5]]
            logger.info(f"Found {len(open_ports_found)} open ports: {', '.join(port_list)}")
        
        logger.info(f"Total vulnerabilities created: {len(vulnerabilities)}")
        return vulnerabilities
    
    def _determine_severity_from_script(self, script_output: str, script_id: str) -> Severity:
        """
        Determine vulnerability severity from Nmap script output.
        
        Security Logic:
        - Analyzes script output for severity indicators
        - Maps critical keywords to severity levels
        - Defaults to medium if uncertain
        
        Args:
            script_output: Script output text
            script_id: Script identifier
        
        Returns:
            Severity level
        """
        output_lower = script_output.lower()
        
        # Critical indicators
        if any(keyword in output_lower for keyword in [
            "critical", "remote code execution", "rce", "arbitrary code",
            "authentication bypass", "privilege escalation"
        ]):
            return Severity.CRITICAL
        
        # High indicators
        if any(keyword in output_lower for keyword in [
            "high", "sql injection", "command injection", "path traversal",
            "file inclusion", "xxe", "ssrf"
        ]):
            return Severity.HIGH
        
        # Medium indicators
        if any(keyword in output_lower for keyword in [
            "medium", "xss", "csrf", "information disclosure",
            "weak encryption", "default credentials"
        ]):
            return Severity.MEDIUM
        
        return Severity.LOW
    
    def _is_insecure_service(self, service_name: str, version: str) -> bool:
        """
        Check if service version is known to be insecure.
        
        Security Logic:
        - Identifies services with known vulnerable versions
        - Checks for outdated protocols or weak configurations
        
        Args:
            service_name: Service name
            version: Service version string
        
        Returns:
            True if service is potentially insecure
        """
        # Simple heuristic: very old version numbers or specific insecure versions
        insecure_patterns = [
            ("apache", ["1.3", "2.0", "2.2"]),
            ("nginx", ["0.", "1.0", "1.2"]),
            ("openssh", ["4.", "5.", "6."]),
            ("mysql", ["4.", "5.0", "5.1"]),
        ]
        
        service_lower = service_name.lower()
        version_lower = version.lower()
        
        for service, insecure_versions in insecure_patterns:
            if service in service_lower:
                for insecure_ver in insecure_versions:
                    if insecure_ver in version_lower:
                        return True
        
        return False

