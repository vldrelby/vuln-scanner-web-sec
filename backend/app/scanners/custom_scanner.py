"""
Custom vulnerability scanner implementation.
Performs application-specific security checks:
- HTTP headers analysis
- Open directory detection
- Reflected XSS checks
- Insecure cookies analysis
- CORS misconfiguration detection
"""

import asyncio
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import httpx
from loguru import logger

from app.scanners.base import BaseScanner, ScanResult
from app.database import Severity
from app.config import settings


class CustomScanner(BaseScanner):
    """Custom application security scanner."""
    
    def __init__(self, config=None):
        """Initialize custom scanner."""
        super().__init__(config or settings.custom_scanner)
        self.scanner_type = "custom"
        self.timeout = settings.scanner.request_timeout
    
    async def scan(self, target_url: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """
        Perform custom security scan on target.
        
        Security Logic:
        - Analyzes HTTP security headers for missing protections
        - Checks for open directory listings (information disclosure)
        - Tests for reflected XSS vulnerabilities
        - Examines cookie security attributes
        - Detects CORS misconfigurations that could enable CSRF
        
        Args:
            target_url: Target URL to scan
            options: Optional scan options
        
        Returns:
            ScanResult with discovered vulnerabilities
        """
        vulnerabilities = []
        metadata = {}
        
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False  # Allow self-signed certificates for testing
            ) as client:
                # 1. HTTP Headers Analysis
                logger.info(f"Analyzing HTTP headers for {target_url}")
                header_vulns = await self._check_security_headers(client, target_url)
                vulnerabilities.extend(header_vulns)
                
                # 2. Open Directory Detection
                logger.info(f"Checking for open directories on {target_url}")
                directory_vulns = await self._check_open_directories(client, target_url)
                vulnerabilities.extend(directory_vulns)
                
                # 3. Reflected XSS Check
                logger.info(f"Testing for reflected XSS on {target_url}")
                xss_vulns = await self._check_reflected_xss(client, target_url)
                vulnerabilities.extend(xss_vulns)
                
                # 4. Cookie Security Analysis
                logger.info(f"Analyzing cookie security for {target_url}")
                cookie_vulns = await self._check_cookie_security(client, target_url)
                vulnerabilities.extend(cookie_vulns)
                
                # 5. CORS Misconfiguration
                logger.info(f"Checking CORS configuration for {target_url}")
                cors_vulns = await self._check_cors_configuration(client, target_url)
                vulnerabilities.extend(cors_vulns)
                
                # 6. Sensitive Files Detection
                logger.info(f"Checking for sensitive files on {target_url}")
                file_vulns = await self._check_sensitive_files(client, target_url)
                vulnerabilities.extend(file_vulns)
                
                # 7. SQL Injection Testing
                logger.info(f"Testing for SQL injection on {target_url}")
                sqli_vulns = await self._check_sql_injection(client, target_url)
                vulnerabilities.extend(sqli_vulns)
                
                # 8. Information Disclosure
                logger.info(f"Checking for information disclosure on {target_url}")
                info_vulns = await self._check_information_disclosure(client, target_url)
                vulnerabilities.extend(info_vulns)
                
                # 9. HTTP Methods Check
                logger.info(f"Checking HTTP methods on {target_url}")
                method_vulns = await self._check_http_methods(client, target_url)
                vulnerabilities.extend(method_vulns)
                
                metadata = {
                    "target": target_url,
                    "checks_performed": [
                        "security_headers",
                        "open_directories",
                        "reflected_xss",
                        "cookie_security",
                        "cors_configuration",
                        "sensitive_files",
                        "sql_injection",
                        "information_disclosure",
                        "http_methods"
                    ]
                }
                
                logger.info(f"Custom scan completed: found {len(vulnerabilities)} vulnerabilities")
                
                return ScanResult(
                    vulnerabilities=vulnerabilities,
                    metadata=metadata
                )
        
        except Exception as e:
            logger.exception(f"Error during custom scan: {e}")
            return ScanResult(
                vulnerabilities=[],
                error=f"Scan error: {str(e)}"
            )
    
    async def _check_security_headers(
        self, client: httpx.AsyncClient, target_url: str
    ) -> List:
        """
        Check for missing or insecure security headers.
        
        Security Logic:
        - X-Frame-Options: Prevents clickjacking attacks
        - X-Content-Type-Options: Prevents MIME type sniffing
        - X-XSS-Protection: Legacy XSS protection (deprecated but still checked)
        - Strict-Transport-Security (HSTS): Forces HTTPS connections
        - Content-Security-Policy: Prevents XSS and injection attacks
        - Referrer-Policy: Controls referrer information leakage
        - Permissions-Policy: Restricts browser features
        
        Args:
            client: HTTP client
            target_url: Target URL
        
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            response = await client.get(target_url)
            headers = response.headers
            
            # Check each required security header
            for header_name in self.config.security_headers:
                header_value = headers.get(header_name)
                
                if not header_value:
                    # Missing header
                    severity = Severity.LOW
                    if header_name in ["Strict-Transport-Security", "Content-Security-Policy"]:
                        severity = Severity.MEDIUM
                    
                    recommendation = self._get_header_recommendation(header_name)
                    
                    vuln = self.create_vulnerability(
                        title=f"Missing Security Header: {header_name}",
                        description=(
                            f"The {header_name} security header is missing from server responses. "
                            f"This may expose the application to various attacks."
                        ),
                        severity=severity,
                        affected_url=target_url,
                        recommendation=recommendation,
                        evidence={
                            "header_name": header_name,
                            "present": False
                        }
                    )
                    vulnerabilities.append(vuln)
                else:
                    # Check for insecure header values
                    insecure = self._is_insecure_header_value(header_name, header_value)
                    if insecure:
                        vuln = self.create_vulnerability(
                            title=f"Insecure Security Header: {header_name}",
                            description=(
                                f"The {header_name} header is present but configured insecurely: {header_value}. "
                                f"This may not provide adequate protection."
                            ),
                            severity=Severity.MEDIUM,
                            affected_url=target_url,
                            recommendation=self._get_header_recommendation(header_name),
                            evidence={
                                "header_name": header_name,
                                "header_value": header_value,
                                "issue": insecure
                            }
                        )
                        vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.error(f"Error checking security headers: {e}")
        
        return vulnerabilities
    
    def _get_header_recommendation(self, header_name: str) -> str:
        """Get recommendation for security header."""
        recommendations = {
            "X-Frame-Options": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
            "X-Content-Type-Options": "Add 'X-Content-Type-Options: nosniff' to prevent MIME sniffing.",
            "X-XSS-Protection": "Add 'X-XSS-Protection: 1; mode=block' (legacy, consider CSP instead).",
            "Strict-Transport-Security": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS.",
            "Content-Security-Policy": "Add a restrictive Content-Security-Policy header to prevent XSS and injection attacks.",
            "Referrer-Policy": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to control referrer information.",
            "Permissions-Policy": "Add Permissions-Policy header to restrict browser features and APIs."
        }
        return recommendations.get(header_name, f"Add {header_name} header with secure configuration.")
    
    def _is_insecure_header_value(self, header_name: str, value: str) -> Optional[str]:
        """
        Check if header value is insecure.
        
        Security Logic:
        - X-Frame-Options: Should be DENY or SAMEORIGIN, not ALLOW-FROM
        - X-Content-Type-Options: Should be nosniff
        - HSTS: Should have max-age and preferably includeSubDomains
        - CSP: Should not be too permissive (e.g., 'unsafe-inline', '*')
        
        Args:
            header_name: Header name
            value: Header value
        
        Returns:
            Issue description if insecure, None otherwise
        """
        value_lower = value.lower()
        
        if header_name == "X-Frame-Options":
            if "allow-from" in value_lower:
                return "ALLOW-FROM is deprecated and insecure"
        
        if header_name == "X-Content-Type-Options":
            if "nosniff" not in value_lower:
                return "Should be 'nosniff'"
        
        if header_name == "Strict-Transport-Security":
            if "max-age" not in value_lower:
                return "Missing max-age directive"
            if "max-age=0" in value_lower:
                return "max-age=0 disables HSTS"
        
        if header_name == "Content-Security-Policy":
            if "*" in value or "unsafe-inline" in value_lower or "unsafe-eval" in value_lower:
                return "CSP contains unsafe directives"
        
        return None
    
    async def _check_open_directories(
        self, client: httpx.AsyncClient, target_url: str
    ) -> List:
        """
        Check for open directory listings.
        
        Security Logic:
        - Attempts to access common sensitive directories
        - Detects directory listing pages (indicated by directory index pages)
        - Identifies information disclosure risks
        
        Args:
            client: HTTP client
            target_url: Target URL
        
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Check common directories
            for directory in self.config.common_directories:
                test_url = urljoin(target_url.rstrip('/') + '/', directory.lstrip('/'))
                
                try:
                    response = await client.get(test_url, timeout=5)
                    
                    # Check if directory listing is enabled
                    # Indicators: directory index pages, file listings, etc.
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        # Common indicators of directory listing
                        indicators = [
                            "index of",
                            "directory listing",
                            "parent directory",
                            "<title>index of",
                            "name</th><th>size</th><th>date"
                        ]
                        
                        if any(indicator in content for indicator in indicators):
                            vuln = self.create_vulnerability(
                                title=f"Open Directory Listing: {directory}",
                                description=(
                                    f"Directory listing is enabled for {directory}. "
                                    f"This exposes file structure and may reveal sensitive files."
                                ),
                                severity=Severity.MEDIUM,
                                affected_url=test_url,
                                recommendation=(
                                    f"Disable directory listing for {directory}. "
                                    f"Configure web server to return 403 Forbidden for directory access."
                                ),
                                evidence={
                                    "directory": directory,
                                    "status_code": response.status_code,
                                    "content_length": len(response.text)
                                }
                            )
                            vulnerabilities.append(vuln)
                
                except httpx.TimeoutException:
                    continue
                except Exception:
                    continue
        
        except Exception as e:
            logger.error(f"Error checking open directories: {e}")
        
        return vulnerabilities
    
    async def _check_reflected_xss(
        self, client: httpx.AsyncClient, target_url: str
    ) -> List:
        """
        Check for reflected XSS vulnerabilities.
        
        Security Logic:
        - Injects XSS payloads into URL parameters
        - Checks if payload is reflected in response without sanitization
        - Tests multiple injection points (query params, path, etc.)
        - Uses various XSS payloads to bypass basic filters
        
        Args:
            client: HTTP client
            target_url: Target URL
        
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Extract existing query parameters
            existing_params = parse_qs(parsed.query)
            
            # Test each XSS payload
            for payload in self.config.xss_payloads:
                # Test in query parameters
                test_params = existing_params.copy()
                test_params["test"] = [payload]
                
                # Build test URL
                from urllib.parse import urlencode
                test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
                
                try:
                    response = await client.get(test_url, timeout=5)
                    
                    # Check if payload is reflected in response
                    if payload in response.text:
                        # Check if it's in a dangerous context (not escaped)
                        # Look for script tags or event handlers
                        if self._is_dangerous_reflection(payload, response.text):
                            vuln = self.create_vulnerability(
                                title="Reflected Cross-Site Scripting (XSS)",
                                description=(
                                    f"Reflected XSS vulnerability detected. "
                                    f"User input is reflected in the response without proper sanitization. "
                                    f"Payload: {payload[:50]}..."
                                ),
                                severity=Severity.HIGH,
                                affected_url=test_url,
                                recommendation=(
                                    "Sanitize all user inputs before rendering. "
                                    "Use output encoding/escaping. "
                                    "Implement Content-Security-Policy header. "
                                    "Validate and filter user input on both client and server side."
                                ),
                                evidence={
                                    "payload": payload,
                                    "reflected": True,
                                    "status_code": response.status_code
                                }
                            )
                            vulnerabilities.append(vuln)
                            break  # Found XSS, no need to test more payloads
                
                except httpx.TimeoutException:
                    continue
                except Exception:
                    continue
        
        except Exception as e:
            logger.error(f"Error checking reflected XSS: {e}")
        
        return vulnerabilities
    
    def _is_dangerous_reflection(self, payload: str, response_text: str) -> bool:
        """
        Check if payload reflection is dangerous (not properly escaped).
        
        Security Logic:
        - Checks if payload appears in script tags
        - Looks for event handlers (onerror, onload, etc.)
        - Verifies payload is not HTML-encoded
        
        Args:
            payload: XSS payload
            response_text: Response HTML
        
        Returns:
            True if reflection is dangerous
        """
        # Find payload position in response
        payload_pos = response_text.find(payload)
        if payload_pos == -1:
            return False
        
        # Extract context around payload
        context_start = max(0, payload_pos - 50)
        context_end = min(len(response_text), payload_pos + len(payload) + 50)
        context = response_text[context_start:context_end].lower()
        
        # Check for dangerous contexts
        dangerous_patterns = [
            "<script",
            "onerror=",
            "onload=",
            "onclick=",
            "javascript:",
            "<iframe",
            "<img",
            "<svg",
            "eval(",
            "innerhtml"
        ]
        
        return any(pattern in context for pattern in dangerous_patterns)
    
    async def _check_cookie_security(
        self, client: httpx.AsyncClient, target_url: str
    ) -> List:
        """
        Check cookie security attributes.
        
        Security Logic:
        - Checks for HttpOnly flag (prevents JavaScript access)
        - Checks for Secure flag (ensures HTTPS-only transmission)
        - Checks for SameSite attribute (CSRF protection)
        - Identifies session fixation risks
        
        Args:
            client: HTTP client
            target_url: Target URL
        
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            response = await client.get(target_url)
            cookies = response.cookies
            
            for cookie in cookies:
                cookie_name = cookie.name
                cookie_attrs = {
                    "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                    "secure": cookie.secure,
                    "samesite": getattr(cookie, "samesite", None)
                }
                
                issues = []
                
                # Check HttpOnly
                if not cookie_attrs["httponly"]:
                    issues.append("Missing HttpOnly flag (vulnerable to XSS)")
                
                # Check Secure flag (only if HTTPS)
                if urlparse(target_url).scheme == "https" and not cookie_attrs["secure"]:
                    issues.append("Missing Secure flag (transmitted over HTTP)")
                
                # Check SameSite
                if not cookie_attrs["samesite"] or cookie_attrs["samesite"].lower() not in ["strict", "lax"]:
                    issues.append("Missing or weak SameSite attribute (vulnerable to CSRF)")
                
                if issues:
                    severity = Severity.MEDIUM
                    if "HttpOnly" in str(issues):
                        severity = Severity.HIGH  # XSS risk is high
                    
                    vuln = self.create_vulnerability(
                        title=f"Insecure Cookie: {cookie_name}",
                        description=(
                            f"Cookie '{cookie_name}' is missing security attributes: {', '.join(issues)}. "
                            f"This may expose the application to XSS, CSRF, or session hijacking attacks."
                        ),
                        severity=severity,
                        affected_url=target_url,
                        recommendation=(
                            f"Set secure attributes on cookie '{cookie_name}': "
                            f"HttpOnly=True, Secure=True, SameSite=Strict (or Lax)."
                        ),
                        evidence={
                            "cookie_name": cookie_name,
                            "attributes": cookie_attrs,
                            "issues": issues
                        }
                    )
                    vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.error(f"Error checking cookie security: {e}")
        
        return vulnerabilities
    
    async def _check_cors_configuration(
        self, client: httpx.AsyncClient, target_url: str
    ) -> List:
        """
        Check CORS (Cross-Origin Resource Sharing) configuration.
        
        Security Logic:
        - Sends preflight OPTIONS request to check CORS headers
        - Detects overly permissive Access-Control-Allow-Origin
        - Checks for missing or weak Access-Control-Allow-Credentials
        - Identifies CORS misconfigurations that enable CSRF
        
        Args:
            client: HTTP client
            target_url: Target URL
        
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            # Send OPTIONS request to check CORS
            response = await client.options(target_url)
            headers = response.headers
            
            acao = headers.get("Access-Control-Allow-Origin")
            acac = headers.get("Access-Control-Allow-Credentials", "").lower()
            
            if acao:
                issues = []
                
                # Check for wildcard with credentials
                if acao == "*" and acac == "true":
                    issues.append("Wildcard origin with credentials (critical security risk)")
                    severity = Severity.CRITICAL
                elif acao == "*":
                    issues.append("Wildcard origin allows any domain (potential CSRF risk)")
                    severity = Severity.HIGH
                elif "null" in acao.lower():
                    issues.append("Origin set to 'null' (vulnerable to attacks)")
                    severity = Severity.HIGH
                else:
                    # Check if origin validation is weak
                    severity = Severity.MEDIUM
                    issues.append("CORS configuration may be too permissive")
                
                vuln = self.create_vulnerability(
                    title="CORS Misconfiguration",
                    description=(
                        f"CORS is configured but may be insecure. "
                        f"Access-Control-Allow-Origin: {acao}. "
                        f"Access-Control-Allow-Credentials: {acac}. "
                        f"Issues: {', '.join(issues)}"
                    ),
                    severity=severity,
                    affected_url=target_url,
                    recommendation=(
                        "Configure CORS to only allow trusted origins. "
                        "Avoid wildcard (*) when credentials are involved. "
                        "Set Access-Control-Allow-Origin to specific domains, not '*'. "
                        "Review and restrict Access-Control-Allow-Methods and Access-Control-Allow-Headers."
                    ),
                    evidence={
                        "access_control_allow_origin": acao,
                        "access_control_allow_credentials": acac,
                        "access_control_allow_methods": headers.get("Access-Control-Allow-Methods"),
                        "access_control_allow_headers": headers.get("Access-Control-Allow-Headers"),
                        "issues": issues
                    }
                )
                vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.error(f"Error checking CORS configuration: {e}")
        
        return vulnerabilities
    
    async def _check_sensitive_files(
        self, client: httpx.AsyncClient, target_url: str
    ) -> List:
        """
        Check for exposed sensitive files.
        
        Security Logic:
        - Attempts to access common sensitive files (.env, .git, backups, etc.)
        - Detects information disclosure through file exposure
        - Identifies configuration and credential leaks
        
        Args:
            client: HTTP client
            target_url: Target URL
        
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # Get sensitive files from config or use defaults
            sensitive_files = getattr(self.config, 'sensitive_files', [
                "/.env", "/.git/config", "/backup.sql", "/config.php"
            ])
            
            for file_path in sensitive_files:
                test_url = urljoin(base_url, file_path)
                
                try:
                    response = await client.get(test_url, timeout=5)
                    
                    # Check if file is accessible and contains sensitive content
                    if response.status_code == 200:
                        content = response.text.lower()
                        content_length = len(response.text)
                        
                        # Check for sensitive indicators
                        sensitive_indicators = [
                            "password", "secret", "api_key", "database",
                            "db_password", "mysql", "postgres", "mongodb",
                            "aws_access", "private_key", "token"
                        ]
                        
                        has_sensitive_content = any(
                            indicator in content for indicator in sensitive_indicators
                        ) or content_length < 10000  # Small files are more likely to be configs
                        
                        if has_sensitive_content:
                            severity = Severity.HIGH if has_sensitive_content else Severity.MEDIUM
                            
                            vuln = self.create_vulnerability(
                                title=f"Exposed Sensitive File: {file_path}",
                                description=(
                                    f"Sensitive file {file_path} is publicly accessible. "
                                    f"This may expose configuration, credentials, or other sensitive information."
                                ),
                                severity=severity,
                                affected_url=test_url,
                                recommendation=(
                                    f"Restrict access to {file_path}. "
                                    f"Move sensitive files outside web root. "
                                    f"Configure web server to deny access to sensitive file patterns. "
                                    f"Use .htaccess or server configuration to block access."
                                ),
                                evidence={
                                    "file_path": file_path,
                                    "status_code": response.status_code,
                                    "content_length": content_length,
                                    "has_sensitive_content": has_sensitive_content
                                }
                            )
                            vulnerabilities.append(vuln)
                
                except httpx.TimeoutException:
                    continue
                except Exception:
                    continue
        
        except Exception as e:
            logger.error(f"Error checking sensitive files: {e}")
        
        return vulnerabilities
    
    async def _check_sql_injection(
        self, client: httpx.AsyncClient, target_url: str
    ) -> List:
        """
        Test for SQL injection vulnerabilities.
        
        Security Logic:
        - Injects SQL payloads into URL parameters
        - Checks for SQL error messages in responses
        - Tests for boolean-based SQL injection (content changes)
        - Identifies database error patterns
        - Tests multiple parameter names and payload types
        
        Args:
            client: HTTP client
            target_url: Target URL
        
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            existing_params = parse_qs(parsed.query)
            
            # Get baseline response for comparison
            try:
                baseline_response = await client.get(target_url, timeout=10)
                baseline_text = baseline_response.text.lower()
                baseline_length = len(baseline_response.text)
            except:
                baseline_text = ""
                baseline_length = 0
            
            # Get SQLi payloads from config or use defaults
            sqli_payloads = getattr(self.config, 'sqli_payloads', [
                "' OR '1'='1", "' OR '1'='1' --", "' UNION SELECT NULL--",
                "1' AND '1'='1", "admin'--", "' OR 1=1#"
            ])
            
            # Extended SQL error patterns
            sql_errors = [
                "sql syntax",
                "mysql_fetch",
                "mysql_num_rows",
                "mysql_query",
                "mysql_result",
                "mysql_fetch_array",
                "mysql_fetch_assoc",
                "mysql_fetch_row",
                "postgresql",
                "pg_query",
                "pg_exec",
                "ora-",
                "oracle",
                "sqlite",
                "sqlite3",
                "sql server",
                "mssql",
                "odbc",
                "database error",
                "syntax error",
                "unclosed quotation",
                "quoted string not properly terminated",
                "warning: mysql",
                "warning: pg_",
                "warning: sqlite",
                "fatal error",
                "mysqli_",
                "pdoexception",
                "sqlstate",
                "invalid query",
                "sql command not properly ended"
            ]
            
            # Parameter names to test (common injection points)
            param_names = list(existing_params.keys()) if existing_params else ["id", "search", "q", "query", "user", "name"]
            
            # Limit to first 3 parameters to avoid too many requests
            for param_name in param_names[:3]:
                for payload in sqli_payloads[:5]:  # Test up to 5 payloads per parameter
                    test_params = existing_params.copy()
                    test_params[param_name] = [payload]
                    
                    from urllib.parse import urlencode
                    test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
                    
                    try:
                        response = await client.get(test_url, timeout=10)
                        response_text = response.text.lower()
                        response_length = len(response.text)
                        
                        # Check 1: SQL error messages (most reliable indicator)
                        for error_pattern in sql_errors:
                            if error_pattern in response_text:
                                vuln = self.create_vulnerability(
                                    title="SQL Injection Vulnerability Detected",
                                    description=(
                                        f"SQL injection vulnerability confirmed. "
                                        f"SQL error message detected in response: '{error_pattern}'. "
                                        f"Parameter: {param_name}, Payload: {payload[:50]}..."
                                    ),
                                    severity=Severity.CRITICAL,
                                    affected_url=test_url,
                                    recommendation=(
                                        "CRITICAL: This is a confirmed SQL injection vulnerability. "
                                        "Immediately fix by using parameterized queries or prepared statements. "
                                        "Validate and sanitize all user inputs. "
                                        "Implement input validation and output encoding. "
                                        "Use ORM frameworks that prevent SQL injection. "
                                        "Never concatenate user input into SQL queries. "
                                        "Review all database queries in the application."
                                    ),
                                    evidence={
                                        "parameter": param_name,
                                        "payload": payload,
                                        "error_pattern": error_pattern,
                                        "status_code": response.status_code,
                                        "detection_method": "error_message"
                                    }
                                )
                                vulnerabilities.append(vuln)
                                break  # Found SQLi, move to next parameter
                        
                        # Check 2: Boolean-based SQL injection (content change detection)
                        # If payload causes significant content change, might indicate SQLi
                        if baseline_length > 0:
                            length_diff = abs(response_length - baseline_length)
                            # Significant content change (more than 20% difference)
                            if length_diff > baseline_length * 0.2:
                                # Check if payload is reflected (indicates potential injection)
                                if any(char in response_text for char in ["'", '"', "--", "#", "/*"]):
                                    # Additional check: look for SQL-like patterns in response
                                    sql_indicators = ["select", "from", "where", "union", "order by", "group by"]
                                    if any(indicator in response_text for indicator in sql_indicators):
                                        vuln = self.create_vulnerability(
                                            title="Potential SQL Injection (Boolean-based)",
                                            description=(
                                                f"Potential SQL injection vulnerability detected via boolean-based testing. "
                                                f"Parameter '{param_name}' appears to affect SQL query execution. "
                                                f"Payload: {payload[:50]}... Response length changed significantly."
                                            ),
                                            severity=Severity.HIGH,
                                            affected_url=test_url,
                                            recommendation=(
                                                "This may indicate a SQL injection vulnerability. "
                                                "Verify manually with additional testing. "
                                                "Use parameterized queries or prepared statements. "
                                                "Validate and sanitize all user inputs. "
                                                "Implement proper input validation."
                                            ),
                                            evidence={
                                                "parameter": param_name,
                                                "payload": payload,
                                                "baseline_length": baseline_length,
                                                "response_length": response_length,
                                                "length_difference": length_diff,
                                                "status_code": response.status_code,
                                                "detection_method": "boolean_based"
                                            }
                                        )
                                        vulnerabilities.append(vuln)
                    
                    except httpx.TimeoutException:
                        continue
                    except Exception:
                        continue
                    
                    # If we found a critical SQLi, don't test more payloads for this parameter
                    if any(v.severity == Severity.CRITICAL for v in vulnerabilities if hasattr(v, 'severity')):
                        break
        
        except Exception as e:
            logger.error(f"Error checking SQL injection: {e}")
        
        return vulnerabilities
    
    async def _check_information_disclosure(
        self, client: httpx.AsyncClient, target_url: str
    ) -> List:
        """
        Check for information disclosure vulnerabilities.
        
        Security Logic:
        - Checks response headers for version information
        - Looks for technology stack disclosure
        - Identifies server version leaks
        - Detects framework and library versions
        
        Args:
            client: HTTP client
            target_url: Target URL
        
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            response = await client.get(target_url)
            headers = response.headers
            body = response.text.lower()
            
            issues = []
            
            # Check headers for version disclosure
            version_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Powered-CMS"]
            for header in version_headers:
                value = headers.get(header)
                if value:
                    # Check if version number is present
                    if re.search(r'\d+\.\d+', value):
                        issues.append(f"{header}: {value}")
            
            # Check body for technology disclosure
            tech_patterns = {
                "wordpress": r"wp-content|wp-includes|wordpress",
                "drupal": r"drupal|sites/all",
                "joomla": r"joomla|components/com_",
                "php": r"php/\d+\.\d+",
                "apache": r"apache/\d+\.\d+",
                "nginx": r"nginx/\d+\.\d+",
                "asp.net": r"asp\.net|\.aspx",
                "laravel": r"laravel_session|laravel"
            }
            
            for tech, pattern in tech_patterns.items():
                if re.search(pattern, body, re.IGNORECASE):
                    issues.append(f"Technology detected: {tech}")
            
            if issues:
                vuln = self.create_vulnerability(
                    title="Information Disclosure",
                    description=(
                        f"Application discloses technical information: {', '.join(issues[:3])}. "
                        f"This information can help attackers identify vulnerabilities and plan attacks."
                    ),
                    severity=Severity.LOW,
                    affected_url=target_url,
                    recommendation=(
                        "Remove or obfuscate version information from headers. "
                        "Disable server signature. "
                        "Remove technology stack indicators from HTML source. "
                        "Use generic error messages that don't reveal system details."
                    ),
                    evidence={
                        "disclosed_info": issues,
                        "headers_checked": version_headers
                    }
                )
                vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.error(f"Error checking information disclosure: {e}")
        
        return vulnerabilities
    
    async def _check_http_methods(
        self, client: httpx.AsyncClient, target_url: str
    ) -> List:
        """
        Check for dangerous HTTP methods.
        
        Security Logic:
        - Tests for TRACE, DELETE, PUT, OPTIONS methods
        - Identifies methods that may enable attacks
        - Checks for method override vulnerabilities
        
        Args:
            client: HTTP client
            target_url: Target URL
        
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        try:
            dangerous_methods = ["TRACE", "DELETE", "PUT", "PATCH"]
            
            for method in dangerous_methods:
                try:
                    response = await client.request(method, target_url, timeout=5)
                    
                    # If method is allowed (not 405 Method Not Allowed)
                    if response.status_code != 405:
                        severity = Severity.MEDIUM
                        if method == "TRACE":
                            severity = Severity.HIGH  # TRACE can enable XST attacks
                        
                        vuln = self.create_vulnerability(
                            title=f"Dangerous HTTP Method Enabled: {method}",
                            description=(
                                f"HTTP {method} method is enabled on the server. "
                                f"This may allow unauthorized modifications or information disclosure."
                            ),
                            severity=severity,
                            affected_url=target_url,
                            recommendation=(
                                f"Disable {method} method if not required. "
                                f"Configure web server to only allow necessary HTTP methods (GET, POST). "
                                f"Use proper authentication and authorization for all methods."
                            ),
                            evidence={
                                "method": method,
                                "status_code": response.status_code,
                                "allowed": True
                            }
                        )
                        vulnerabilities.append(vuln)
                
                except httpx.TimeoutException:
                    continue
                except Exception:
                    continue
        
        except Exception as e:
            logger.error(f"Error checking HTTP methods: {e}")
        
        return vulnerabilities

