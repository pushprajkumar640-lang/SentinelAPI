import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;

const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:3000,http://localhost:3002,http://localhost:3003')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: '10mb' }));

async function start() {
  const { createApiRouter } = await import('./src/server/apiRouter');
  app.use('/api', createApiRouter());

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  app.use((error: any, _req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (error instanceof SyntaxError && (error as any).status === 400) {
      return res.status(400).json({ success: false, error: 'Invalid JSON request body.' });
    }
    return next(error);
  });

  app.use(express.static(path.join(__dirname, 'dist')));
  app.get('*', (_req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SentinelAPI API running on port ${PORT}`);
  });
}

start().catch((error) => {
  console.error('SentinelAPI API failed to start:', error instanceof Error ? error.message : 'unknown error');
  process.exitCode = 1;
});
