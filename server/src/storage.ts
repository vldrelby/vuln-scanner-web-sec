import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';

const DB_PATH = join(process.cwd(), 'scanner-data.json');

interface Scan {
  id: number;
  target_url: string;
  scan_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  scan_metadata?: any;
}

interface Vulnerability {
  id: number;
  scan_id: number;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  scanner_type: string;
  affected_url: string;
  cve?: string;
  recommendation: string;
  evidence?: any;
  discovered_at: string;
}

interface Database {
  scans: Scan[];
  vulnerabilities: Vulnerability[];
  nextScanId: number;
  nextVulnId: number;
}

export class Storage {
  private data: Database;

  constructor() {
    if (existsSync(DB_PATH)) {
      const content = readFileSync(DB_PATH, 'utf-8');
      this.data = JSON.parse(content);
    } else {
      this.data = {
        scans: [],
        vulnerabilities: [],
        nextScanId: 1,
        nextVulnId: 1
      };
      this.save();
    }
  }

  private save() {
    writeFileSync(DB_PATH, JSON.stringify(this.data, null, 2), 'utf-8');
  }

  createScan(scan: Omit<Scan, 'id' | 'created_at'>): Scan {
    const newScan: Scan = {
      ...scan,
      id: this.data.nextScanId++,
      created_at: new Date().toISOString()
    };
    this.data.scans.push(newScan);
    this.save();
    return newScan;
  }

  getScan(id: number): Scan | undefined {
    return this.data.scans.find(s => s.id === id);
  }

  updateScan(id: number, updates: Partial<Scan>): Scan | undefined {
    const scan = this.data.scans.find(s => s.id === id);
    if (scan) {
      Object.assign(scan, updates);
      this.save();
      return scan;
    }
    return undefined;
  }

  getAllScans(): Scan[] {
    return [...this.data.scans].reverse();
  }

  deleteScan(id: number): boolean {
    const index = this.data.scans.findIndex(s => s.id === id);
    if (index !== -1) {
      this.data.scans.splice(index, 1);
      this.data.vulnerabilities = this.data.vulnerabilities.filter(v => v.scan_id !== id);
      this.save();
      return true;
    }
    return false;
  }

  createVulnerability(vuln: Omit<Vulnerability, 'id' | 'discovered_at'>): Vulnerability {
    const newVuln: Vulnerability = {
      ...vuln,
      id: this.data.nextVulnId++,
      discovered_at: new Date().toISOString()
    };
    this.data.vulnerabilities.push(newVuln);
    this.save();
    return newVuln;
  }

  getVulnerabilitiesByScanId(scanId: number, severity?: string): Vulnerability[] {
    let vulns = this.data.vulnerabilities.filter(v => v.scan_id === scanId);
    if (severity) {
      vulns = vulns.filter(v => v.severity === severity.toLowerCase());
    }
    return vulns;
  }
}

