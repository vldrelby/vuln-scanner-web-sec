import { Router, Request, Response } from 'express';
import { ScannerService } from '../services/scanner';
import { Storage } from '../storage';

const router = Router();
const storage = new Storage();
const scannerService = new ScannerService(storage);

// Create scan
router.post('/', async (req: Request, res: Response) => {
  try {
    const { target_url, scan_type = 'custom' } = req.body;

    if (!target_url) {
      return res.status(400).json({ error: 'target_url is required' });
    }

    const validTypes = ['nmap', 'nuclei', 'custom', 'full'];
    if (!validTypes.includes(scan_type)) {
      return res.status(400).json({ 
        error: `Invalid scan_type. Must be one of: ${validTypes.join(', ')}` 
      });
    }

    try {
      console.log('Creating scan for:', target_url, scan_type);
      const scanId = await scannerService.runScan(target_url, scan_type);
      console.log('Scan created with ID:', scanId);

      const scan = storage.getScan(scanId);
      console.log('Retrieved scan:', scan ? 'found' : 'not found');
      if (!scan) {
        console.error('Scan not found after creation, scanId:', scanId);
        return res.status(500).json({ error: 'Failed to create scan' });
      }

    res.status(201).json({
      id: scan.id,
      target_url: scan.target_url,
      scan_type: scan.scan_type,
      status: scan.status,
      created_at: scan.created_at,
      started_at: scan.started_at,
      completed_at: scan.completed_at,
      error_message: scan.error_message,
      scan_metadata: scan.scan_metadata,
      vulnerabilities: []
    });
    } catch (error: any) {
      console.error('Create scan error:', error);
      res.status(500).json({ error: error.message || 'Failed to create scan' });
    }
  } catch (error: any) {
    console.error('Create scan error:', error);
    res.status(500).json({ error: error.message || 'Failed to create scan' });
  }
});

// Get all scans
router.get('/', (req: Request, res: Response) => {
  try {
    const scans = storage.getAllScans().slice(0, 100);
    
    const scansWithVulns = scans.map((scan) => {
      const vulns = storage.getVulnerabilitiesByScanId(scan.id);
      return {
        ...scan,
        vulnerabilities: vulns.map((v) => ({
          id: v.id,
          title: v.title,
          description: v.description,
          severity: v.severity,
          scanner_type: v.scanner_type,
          affected_url: v.affected_url,
          cve: v.cve,
          recommendation: v.recommendation,
          evidence: v.evidence,
          discovered_at: v.discovered_at
        }))
      };
    });

    res.json({
      scans: scansWithVulns,
      total: scans.length
    });
  } catch (error: any) {
    console.error('Get scans error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get scan by ID
router.get('/:id', (req: Request, res: Response) => {
  try {
    const scanId = parseInt(req.params.id);
    const scan = storage.getScan(scanId);

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const vulns = storage.getVulnerabilitiesByScanId(scanId);

    res.json({
      id: scan.id,
      target_url: scan.target_url,
      scan_type: scan.scan_type,
      status: scan.status,
      created_at: scan.created_at,
      started_at: scan.started_at,
      completed_at: scan.completed_at,
      error_message: scan.error_message,
      scan_metadata: scan.scan_metadata,
      vulnerabilities: vulns.map((v) => ({
        id: v.id,
        title: v.title,
        description: v.description,
        severity: v.severity,
        scanner_type: v.scanner_type,
        affected_url: v.affected_url,
        cve: v.cve,
        recommendation: v.recommendation,
        evidence: v.evidence,
        discovered_at: v.discovered_at
      }))
    });
  } catch (error: any) {
    console.error('Get scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get scan vulnerabilities
router.get('/:id/vulnerabilities', (req: Request, res: Response) => {
  try {
    const scanId = parseInt(req.params.id);
    const severity = req.query.severity as string;

    const vulns = storage.getVulnerabilitiesByScanId(scanId, severity);

    res.json(vulns.map((v) => ({
      id: v.id,
      title: v.title,
      description: v.description,
      severity: v.severity,
      scanner_type: v.scanner_type,
      affected_url: v.affected_url,
      cve: v.cve,
      recommendation: v.recommendation,
      evidence: v.evidence,
      discovered_at: v.discovered_at
    })));
  } catch (error: any) {
    console.error('Get vulnerabilities error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Delete scan
router.delete('/:id', (req: Request, res: Response) => {
  try {
    const scanId = parseInt(req.params.id);
    
    const deleted = storage.deleteScan(scanId);
    if (!deleted) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    res.status(204).send();
  } catch (error: any) {
    console.error('Delete scan error:', error);
    res.status(500).json({ error: error.message });
  }
});

export { router as scanRouter };

