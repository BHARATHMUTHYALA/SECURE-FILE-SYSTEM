import express from 'express';
import cors from 'cors';
import path from 'path';
import { config } from './config';
import routes from './routes';
import { errorHandler, securityHeaders, requestLogger, corsOptions } from './middleware';

const app = express();

// Security and logging middleware
app.use(securityHeaders);
app.use(requestLogger);
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(process.cwd(), 'public')));

// API routes
app.use('/api', routes);

// API info
app.get('/api', (_, res) => {
  res.json({
    name: 'Secure File System',
    version: '2.0.0',
    features: [
      'AES-256-GCM encryption',
      'Role-based access control',
      'File sharing & share links',
      'File versioning',
      'Folders & organization',
      'File comments',
      'Favorites & tags',
      'Trash & recovery',
      'Storage quotas',
      'Session management',
      'Activity notifications',
      'Rate limiting',
      'Audit logging',
      'Bulk operations',
    ],
  });
});

// Serve frontend
app.get('/', (_, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'index.html'), err => {
    if (err) res.redirect('/api');
  });
});

// Health check
app.get('/health', (_, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// Error handler (must be last)
app.use(errorHandler);

app.listen(config.port, () => {
  console.log(`\n🔐 Secure File System v2.0`);
  console.log(`   http://localhost:${config.port}`);
  console.log(`   Uploads: ${config.uploadDir}`);
  console.log(`   Max file size: ${Math.round(config.maxFileSize / 1024 / 1024)}MB`);
  console.log(`   Default quota: ${Math.round(config.defaultStorageQuota / 1024 / 1024)}MB per user\n`);
});
