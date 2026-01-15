"""
Nuclei scanner implementation.
Runs Nuclei vulnerability scanner with custom templates.
"""

import asyncio
import subprocess
import json
import tempfile
import os
from typing import List, Dict, Any, Optional, Callable, Awaitable
from pathlib import Path

from loguru import logger

from app.scanners.base import BaseScanner, ScanResult
from app.database import Severity
from app.config import settings


class NucleiScanner(BaseScanner):
    """Nuclei-based vulnerability scanner."""
    
    def __init__(self, config=None):
        """Initialize Nuclei scanner."""
        super().__init__(config or settings.nuclei)
        self.scanner_type = "nuclei"
    
    async def scan(
        self, 
        target_url: str, 
        options: Optional[Dict[str, Any]] = None,
        on_vulnerability_found: Optional[Callable[[Any], Awaitable[None]]] = None
    ) -> ScanResult:
        """
        Perform Nuclei scan on target.
        
        Security Logic:
        - Uses Nuclei's extensive template library to detect vulnerabilities
        - Supports custom templates for organization-specific checks
        - Runs multiple vulnerability checks in parallel
        - Parses JSON output to extract findings with CVE information
        
        Args:
            target_url: Target URL to scan
            options: Optional scan options (templates, severity, etc.)
        
        Returns:
            ScanResult with discovered vulnerabilities
        """
        try:
            # Get scan options
            severity = options.get("severity", self.config.severity) if options else self.config.severity
            rate_limit = options.get("rate_limit", self.config.rate_limit) if options else self.config.rate_limit
            templates_path = options.get("templates_path", self.config.templates_path) if options else self.config.templates_path
            
            # Build Nuclei command
            # Security: Using -j for JSON output, -severity to filter results
            # -rate-limit to avoid overwhelming target, -silent for clean output
            # -timeout to prevent hanging scans
            # -max-host-error to stop after too many errors
            # -bulk-size to limit concurrent requests
            # -etags to use only specific vulnerability categories for faster scans
            cmd = [
                self.config.binary_path,
                "-u", target_url,
                "-j",  # JSON output (v3.1.0 uses -j instead of -json)
                "-severity", ",".join(severity),
                "-rate-limit", str(rate_limit),
                "-silent",
                "-timeout", "15",  # 15 second timeout per request
                "-max-host-error", "10",  # Stop after 10 errors
                "-bulk-size", "50",  # Increase concurrent requests for faster scanning
                "-retries", "1",  # Only retry once
                "-no-interactsh",  # Disable interactsh for faster scans
                "-etags", "xss,sqli,rce,lfi,ssrf",  # Focus on common web vulnerabilities
            ]
            
            # Add custom templates if path exists
            if templates_path and os.path.exists(templates_path):
                cmd.extend(["-t", templates_path])
            
            logger.info(f"Running Nuclei scan on {target_url}")
            
            vulnerabilities = []
            error_output = ""
            
            # Run Nuclei in subprocess (async) with streaming output
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # Read output line by line in real-time
                async def read_stdout():
                    nonlocal vulnerabilities, error_output
                    buffer = ""
                    while True:
                        chunk = await process.stdout.read(1024)
                        if not chunk:
                            break
                        buffer += chunk.decode('utf-8', errors='ignore')
                        
                        # Process complete lines
                        while '\n' in buffer:
                            line, buffer = buffer.split('\n', 1)
                            line = line.strip()
                            if not line:
                                continue
                            
                            try:
                                # Parse JSON line
                                data = json.loads(line)
                                
                                # Parse vulnerability immediately
                                vuln = self._parse_single_vulnerability(data, target_url)
                                if vuln:
                                    vulnerabilities.append(vuln)
                                    logger.info(f"Nuclei found vulnerability: {vuln.title}")
                                    
                                    # Call callback if provided (for real-time saving)
                                    if on_vulnerability_found:
                                        try:
                                            await on_vulnerability_found(vuln)
                                        except Exception as callback_error:
                                            logger.error(f"Error in vulnerability callback: {callback_error}")
                            
                            except json.JSONDecodeError:
                                # Not a JSON line, skip
                                continue
                    
                    # Process remaining buffer
                    if buffer.strip():
                        try:
                            data = json.loads(buffer.strip())
                            vuln = self._parse_single_vulnerability(data, target_url)
                            if vuln:
                                vulnerabilities.append(vuln)
                                if on_vulnerability_found:
                                    try:
                                        await on_vulnerability_found(vuln)
                                    except Exception as callback_error:
                                        logger.error(f"Error in vulnerability callback: {callback_error}")
                        except json.JSONDecodeError:
                            pass
                
                async def read_stderr():
                    nonlocal error_output
                    while True:
                        chunk = await process.stderr.read(1024)
                        if not chunk:
                            break
                        error_output += chunk.decode('utf-8', errors='ignore')
                
                # Read stdout and stderr concurrently
                try:
                    await asyncio.wait_for(
                        asyncio.gather(read_stdout(), read_stderr()),
                        timeout=300  # 5 minute timeout for entire scan
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"Nuclei scan timed out after 5 minutes for {target_url}. Killing process...")
                    try:
                        process.kill()
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except:
                        pass
                    logger.info(f"Nuclei scan completed with timeout: found {len(vulnerabilities)} vulnerabilities before timeout")
                    # Return partial results even on timeout
                    return ScanResult(
                        vulnerabilities=vulnerabilities,
                        metadata={
                            "target": target_url,
                            "severity_filter": severity,
                            "templates_used": templates_path if templates_path and os.path.exists(templates_path) else "default",
                            "timeout": True
                        }
                    )
                
                # Wait for process to complete
                await process.wait()
                
            except Exception as e:
                logger.exception(f"Error running Nuclei process: {e}")
                return ScanResult(
                    vulnerabilities=vulnerabilities,
                    error=f"Error running Nuclei: {str(e)}"
                )
            
            # Check for errors in stderr
            if process.returncode != 0 and error_output and "error" in error_output.lower():
                logger.warning(f"Nuclei scan returned non-zero exit code: {error_output[:200]}")
                # Don't fail completely if we found some vulnerabilities
            
            # Log stderr for debugging
            if error_output and "error" not in error_output.lower():
                logger.debug(f"Nuclei stderr: {error_output[:200]}")
            
            # Return results (even if empty)
            if not vulnerabilities:
                logger.info(f"Nuclei scan completed with no findings for {target_url}")
                logger.debug(f"Command used: {' '.join(cmd)}")
                logger.debug(f"Return code: {process.returncode}")
            
            metadata = {
                "target": target_url,
                "severity_filter": severity,
                "templates_used": templates_path if templates_path and os.path.exists(templates_path) else "default"
            }
            
            logger.info(f"Nuclei scan completed: found {len(vulnerabilities)} vulnerabilities")
            
            return ScanResult(
                vulnerabilities=vulnerabilities,
                metadata=metadata
            )
            
        except FileNotFoundError:
            error_msg = f"Nuclei not found at {self.config.binary_path}. Please install Nuclei."
            logger.error(error_msg)
            return ScanResult(
                vulnerabilities=[],
                error=error_msg
            )
        except Exception as e:
            logger.exception(f"Error during Nuclei scan: {e}")
            return ScanResult(
                vulnerabilities=[],
                error=f"Scan error: {str(e)}"
            )
    
    def _parse_single_vulnerability(self, data: dict, target_url: str):
        """
        Parse a single Nuclei JSON line and create a vulnerability object.
        
        Args:
            data: Parsed JSON data from Nuclei output
            target_url: Original target URL
        
        Returns:
            VulnerabilityResponse object or None
        """
        try:
            # Extract vulnerability information
            template_id = data.get("template-id", "unknown")
            template_name = data.get("info", {}).get("name", template_id)
            severity_str = data.get("info", {}).get("severity", "info").lower()
            description = data.get("info", {}).get("description", "No description available")
            reference = data.get("info", {}).get("reference", [])
            tags = data.get("info", {}).get("tags", [])
            
            # Extract matched URL
            matched_url = data.get("matched-at", target_url)
            
            # Extract CVE from tags or reference
            cve = None
            for tag in tags:
                if tag.startswith("cve-"):
                    cve = tag.upper()
                    break
            
            # Check references for CVE
            if not cve:
                for ref in reference:
                    if "cve" in ref.lower():
                        # Extract CVE from URL or text
                        import re
                        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', ref, re.IGNORECASE)
                        if cve_match:
                            cve = cve_match.group().upper()
                            break
            
            # Normalize severity
            severity = self.normalize_severity(severity_str)
            
            # Build recommendation
            recommendation = (
                f"Review and remediate the vulnerability identified by template '{template_name}'. "
                f"Check references for detailed information and patches."
            )
            if reference:
                recommendation += f" References: {', '.join(reference[:3])}"
            
            # Extract evidence
            evidence = {
                "template_id": template_id,
                "template_name": template_name,
                "matched_at": matched_url,
                "tags": tags,
                "reference": reference,
                "extracted_results": data.get("extracted-results", []),
                "matcher_name": data.get("matcher-name"),
                "curl_command": data.get("curl-command")
            }
            
            vuln = self.create_vulnerability(
                title=template_name,
                description=description or f"Vulnerability detected by Nuclei template: {template_id}",
                severity=severity,
                affected_url=matched_url,
                cve=cve,
                recommendation=recommendation,
                evidence=evidence
            )
            
            return vuln
        
        except Exception as e:
            logger.error(f"Error parsing single Nuclei vulnerability: {e}")
            return None
    
    def _parse_nuclei_output(self, output: str, target_url: str) -> List:
        """
        Parse Nuclei JSON output and extract vulnerabilities.
        
        Security Logic:
        - Extracts template information and matched patterns
        - Maps Nuclei severity to standardized severity levels
        - Extracts CVE information from template metadata
        - Preserves evidence for manual verification
        
        Args:
            output: Nuclei JSON output (one JSON per line)
            target_url: Original target URL
        
        Returns:
            List of VulnerabilityResponse objects
        """
        vulnerabilities = []
        
        try:
            for line in output.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                # Extract vulnerability information
                template_id = data.get("template-id", "unknown")
                template_name = data.get("info", {}).get("name", template_id)
                severity_str = data.get("info", {}).get("severity", "info").lower()
                description = data.get("info", {}).get("description", "No description available")
                reference = data.get("info", {}).get("reference", [])
                tags = data.get("info", {}).get("tags", [])
                
                # Extract matched URL
                matched_url = data.get("matched-at", target_url)
                
                # Extract CVE from tags or reference
                cve = None
                for tag in tags:
                    if tag.startswith("cve-"):
                        cve = tag.upper()
                        break
                
                # Check references for CVE
                if not cve:
                    for ref in reference:
                        if "cve" in ref.lower():
                            # Extract CVE from URL or text
                            import re
                            cve_match = re.search(r'CVE-\d{4}-\d{4,7}', ref, re.IGNORECASE)
                            if cve_match:
                                cve = cve_match.group().upper()
                                break
                
                # Normalize severity
                severity = self.normalize_severity(severity_str)
                
                # Build recommendation
                recommendation = (
                    f"Review and remediate the vulnerability identified by template '{template_name}'. "
                    f"Check references for detailed information and patches."
                )
                if reference:
                    recommendation += f" References: {', '.join(reference[:3])}"
                
                # Extract evidence
                evidence = {
                    "template_id": template_id,
                    "template_name": template_name,
                    "matched_at": matched_url,
                    "tags": tags,
                    "reference": reference,
                    "extracted_results": data.get("extracted-results", []),
                    "matcher_name": data.get("matcher-name"),
                    "curl_command": data.get("curl-command")
                }
                
                vuln = self.create_vulnerability(
                    title=template_name,
                    description=description or f"Vulnerability detected by Nuclei template: {template_id}",
                    severity=severity,
                    affected_url=matched_url,
                    cve=cve,
                    recommendation=recommendation,
                    evidence=evidence
                )
                
                vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.error(f"Error parsing Nuclei output: {e}")
        
        return vulnerabilities

