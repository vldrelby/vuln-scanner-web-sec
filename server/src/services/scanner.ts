import { exec } from 'child_process';
import { promisify } from 'util';
import axios from 'axios';
import { Storage } from '../storage';

const execAsync = promisify(exec);

export interface Vulnerability {
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  scanner_type: string;
  affected_url: string;
  cve?: string;
  recommendation: string;
  evidence?: any;
}

export class ScannerService {
  private storage: Storage;

  constructor(storage?: Storage) {
    this.storage = storage || new Storage();
  }

  async scanNmap(targetUrl: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    try {
      // Extract hostname from URL
      const url = new URL(targetUrl);
      const hostname = url.hostname;

      // Run nmap scan
      const { stdout } = await execAsync(`nmap -sV -sC ${hostname} 2>/dev/null || echo "nmap not available"`);
      
      if (stdout.includes('nmap not available')) {
        return vulnerabilities;
      }

      // Parse nmap output for open ports and services
      const openPorts = stdout.match(/(\d+)\/tcp\s+open/g) || [];
      
      if (openPorts.length > 0) {
        vulnerabilities.push({
          title: 'Open Ports Detected',
          description: `Nmap scan detected ${openPorts.length} open port(s) on ${hostname}`,
          severity: 'info',
          scanner_type: 'nmap',
          affected_url: targetUrl,
          recommendation: 'Review open ports and ensure only necessary services are exposed.',
          evidence: { stdout, openPorts: openPorts.length }
        });
      }
    } catch (error: any) {
      console.error('Nmap scan error:', error.message);
    }

    return vulnerabilities;
  }

  async scanNuclei(targetUrl: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    try {
      // Run nuclei scan
      const { stdout } = await execAsync(`nuclei -u ${targetUrl} -silent -json 2>/dev/null || echo "nuclei not available"`);
      
      if (stdout.includes('nuclei not available') || !stdout.trim()) {
        return vulnerabilities;
      }

      // Parse nuclei JSON output
      const lines = stdout.trim().split('\n');
      for (const line of lines) {
        try {
          const result = JSON.parse(line);
          vulnerabilities.push({
            title: result.info?.name || 'Vulnerability Detected',
            description: result.info?.description || 'Nuclei detected a potential vulnerability',
            severity: (result.info?.severity || 'info').toLowerCase() as any,
            scanner_type: 'nuclei',
            affected_url: result.matched || targetUrl,
            cve: result.info?.classification?.cve_id?.[0],
            recommendation: 'Review the detected vulnerability and apply appropriate patches.',
            evidence: result
          });
        } catch (e) {
          // Skip invalid JSON lines
        }
      }
    } catch (error: any) {
      console.error('Nuclei scan error:', error.message);
    }

    return vulnerabilities;
  }

  async scanCustom(targetUrl: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    try {
      const response = await axios.get(targetUrl, {
        timeout: 10000,
        validateStatus: () => true,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });

      const headers = response.headers;
      const url = new URL(targetUrl);

      // Check security headers
      const securityHeaders = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'Referrer-Policy',
        'Permissions-Policy'
      ];

      const missingHeaders: string[] = [];
      for (const header of securityHeaders) {
        if (!headers[header.toLowerCase()]) {
          missingHeaders.push(header);
        }
      }

      if (missingHeaders.length > 0) {
        vulnerabilities.push({
          title: 'Missing Security Headers',
          description: `The server is missing ${missingHeaders.length} security header(s): ${missingHeaders.join(', ')}`,
          severity: 'low',
          scanner_type: 'custom',
          affected_url: targetUrl,
          recommendation: 'Add security headers to prevent clickjacking, MIME sniffing, and XSS attacks.',
          evidence: { missingHeaders }
        });
      }

      // Check for directory listing
      const commonDirs = ['/admin', '/backup', '/config', '/.git', '/.env'];
      for (const dir of commonDirs) {
        try {
          const dirUrl = new URL(dir, targetUrl).href;
          const dirResponse = await axios.get(dirUrl, {
            timeout: 5000,
            validateStatus: () => true
          });
          
          if (dirResponse.status === 200 && dirResponse.data.includes('Index of')) {
            vulnerabilities.push({
              title: 'Directory Listing Enabled',
              description: `Directory listing is enabled at ${dirUrl}`,
              severity: 'medium',
              scanner_type: 'custom',
              affected_url: dirUrl,
              recommendation: 'Disable directory listing to prevent information disclosure.',
              evidence: { status: dirResponse.status }
            });
          }
        } catch (e) {
          // Skip failed directory checks
        }
      }

      // Check cookies
      if (headers['set-cookie']) {
        const cookies = Array.isArray(headers['set-cookie']) 
          ? headers['set-cookie'] 
          : [headers['set-cookie']];
        
        for (const cookie of cookies) {
          const isSecure = cookie.includes('Secure');
          const isHttpOnly = cookie.includes('HttpOnly');
          const hasSameSite = cookie.includes('SameSite');

          if (!isSecure || !isHttpOnly || !hasSameSite) {
            vulnerabilities.push({
              title: 'Insecure Cookie Configuration',
              description: `Cookie is missing security flags: ${!isSecure ? 'Secure ' : ''}${!isHttpOnly ? 'HttpOnly ' : ''}${!hasSameSite ? 'SameSite' : ''}`,
              severity: 'medium',
              scanner_type: 'custom',
              affected_url: targetUrl,
              recommendation: 'Set Secure, HttpOnly, and SameSite flags on all cookies.',
              evidence: { cookie }
            });
            break;
          }
        }
      }

      // Check CORS
      if (headers['access-control-allow-origin'] === '*') {
        vulnerabilities.push({
          title: 'Permissive CORS Policy',
          description: 'The server allows requests from any origin (*)',
          severity: 'medium',
          scanner_type: 'custom',
          affected_url: targetUrl,
          recommendation: 'Restrict CORS to specific trusted origins.',
          evidence: { corsHeader: headers['access-control-allow-origin'] }
        });
      }

    } catch (error: any) {
      console.error('Custom scan error:', error.message);
    }

    return vulnerabilities;
  }

  async runScan(targetUrl: string, scanType: string): Promise<number> {
    // Create scan record
    const scan = this.storage.createScan({
      target_url: targetUrl,
      scan_type: scanType,
      status: 'running',
      started_at: new Date().toISOString()
    });

    const scanId = scan.id;

    // Run scans in background
    setImmediate(async () => {
      try {
        let vulnerabilities: Vulnerability[] = [];

        if (scanType === 'nmap' || scanType === 'full') {
          const nmapVulns = await this.scanNmap(targetUrl);
          vulnerabilities.push(...nmapVulns);
        }

        if (scanType === 'nuclei' || scanType === 'full') {
          const nucleiVulns = await this.scanNuclei(targetUrl);
          vulnerabilities.push(...nucleiVulns);
        }

        if (scanType === 'custom' || scanType === 'full') {
          const customVulns = await this.scanCustom(targetUrl);
          vulnerabilities.push(...customVulns);
        }

        // Save vulnerabilities
        for (const vuln of vulnerabilities) {
          this.storage.createVulnerability({
            scan_id: scanId,
            title: vuln.title,
            description: vuln.description,
            severity: vuln.severity,
            scanner_type: vuln.scanner_type,
            affected_url: vuln.affected_url,
            cve: vuln.cve,
            recommendation: vuln.recommendation,
            evidence: vuln.evidence
          });
        }

        // Update scan status
        this.storage.updateScan(scanId, {
          status: 'completed',
          completed_at: new Date().toISOString()
        });

        console.log(`✅ Scan ${scanId} completed: ${vulnerabilities.length} vulnerabilities found`);
      } catch (error: any) {
        console.error(`❌ Scan ${scanId} failed:`, error.message);
        this.storage.updateScan(scanId, {
          status: 'failed',
          error_message: error.message,
          completed_at: new Date().toISOString()
        });
      }
    });

    return scanId;
  }
}

