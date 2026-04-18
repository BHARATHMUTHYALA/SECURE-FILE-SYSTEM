import dotenv from 'dotenv';
import path from 'path';

dotenv.config();

export const config = {
  port: parseInt(process.env.PORT || '3000'),
  jwtSecret: process.env.JWT_SECRET || 'change-this-secret-in-production',
  encryptionKey: process.env.ENCRYPTION_KEY || 'default-32-char-encryption-key!!',
  uploadDir: path.resolve(process.env.UPLOAD_DIR || './uploads'),
  versionsDir: path.resolve(process.env.VERSIONS_DIR || './uploads/versions'),
  trashDir: path.resolve(process.env.TRASH_DIR || './uploads/trash'),
  maxFileSize: 50 * 1024 * 1024, // 50MB
  defaultStorageQuota: 500 * 1024 * 1024, // 500MB per user
  
  // Security settings
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100,
    maxLoginAttempts: 5,
    lockoutDuration: 5 * 60 * 1000, // 5 minutes (for demonstration)
  },
  
  // Session settings
  sessionDuration: '720h', // 30 days (extended for long-term access)
  maxSessionsPerUser: 10,  // Increased to support multiple devices over 30 days
  
  // File settings
  maxVersions: 10,
  trashRetentionDays: 30,
  shareLinksMaxDays: 30,

  // Zero-trust settings
  zeroTrust: {
    proofTtlMs: 10 * 60 * 1000, // 10 minutes
    maxClockSkewMs: 2 * 60 * 1000, // 2 minutes
  },
  
  // Allowed file types with size limits
  allowedFileTypes: {
    'image/jpeg': 20 * 1024 * 1024,
    'image/png': 20 * 1024 * 1024,
    'image/gif': 10 * 1024 * 1024,
    'image/webp': 20 * 1024 * 1024,
    'application/pdf': 50 * 1024 * 1024,
    'text/plain': 5 * 1024 * 1024,
    'text/csv': 10 * 1024 * 1024,
    'application/json': 5 * 1024 * 1024,
    'application/zip': 50 * 1024 * 1024,
    'application/x-zip-compressed': 50 * 1024 * 1024,
    'application/msword': 25 * 1024 * 1024,
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 25 * 1024 * 1024,
    'application/vnd.ms-excel': 25 * 1024 * 1024,
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 25 * 1024 * 1024,
  },
};
