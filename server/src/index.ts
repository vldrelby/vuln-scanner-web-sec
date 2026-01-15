import express, { Request, Response } from 'express';
import cors from 'cors';
import { Database } from './database';
import { ScannerService } from './services/scanner';
import { scanRouter } from './routes/scans';

const app = express();
const PORT = process.env.PORT || 8000;

// Middleware
app.use(cors());
app.use(express.json());

// Initialize database
const db = new Database();
db.init();

// Initialize scanner service
const scannerService = new ScannerService();

// Health check
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    version: '2.0.0',
    database: 'connected'
  });
});

app.get('/', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    version: '2.0.0',
    database: 'connected'
  });
});

// API routes
app.use('/api/scans', scanRouter);

// Error handling
app.use((err: Error, req: Request, res: Response, next: Function) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error', message: err.message });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
});

