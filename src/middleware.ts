import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { v4 as uuid } from 'uuid';
import { config } from './config';
import { Role } from './types';
import { db } from './db';

// Ensure directories exist
[config.uploadDir, config.versionsDir, config.trashDir].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Response helpers
export const ok = (res: Response, data: unknown, msg = 'Success', status = 200) =>
  res.status(status).json({ success: true, message: msg, data });

export const fail = (res: Response, msg: string, status = 400) =>
  res.status(status).json({ success: false, message: msg });

// Get client IP
export const getClientIp = (req: Request): string => {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
};

// Rate limiting middleware
export const rateLimit = (maxRequests?: number, windowMs?: number) => {
  const limit = maxRequests || config.rateLimit.maxRequests;
  const window = windowMs || config.rateLimit.windowMs;
  
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = `${getClientIp(req)}:${req.path}`;
    
    if (!db.checkRateLimit(key, limit, window)) {
      res.setHeader('Retry-After', Math.ceil(window / 1000));
      res.setHeader('X-RateLimit-Limit', limit);
      res.setHeader('X-RateLimit-Remaining', 0);
      fail(res, 'Too many requests. Please try again later.', 429);
      return;
    }
    
    res.setHeader('X-RateLimit-Limit', limit);
    res.setHeader('X-RateLimit-Remaining', db.getRateLimitRemaining(key, limit));
    next();
  };
};

// Auth middleware with session tracking
export const auth = (req: Request, res: Response, next: NextFunction): void => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) { fail(res, 'No token provided', 401); return; }

  try {
    const decoded = jwt.verify(token, config.jwtSecret) as { userId: string; role: Role; sessionId?: string };
    const user = db.findUserById(decoded.userId);
    if (!user) { fail(res, 'User not found', 401); return; }
    
    // Check if account is locked
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      fail(res, 'Account is temporarily locked. Try again later.', 423);
      return;
    }
    
    // Verify session if sessionId is in token
    if (decoded.sessionId) {
      const session = db.findSessionById(decoded.sessionId);
      if (!session || session.expiresAt < new Date()) {
        fail(res, 'Session expired. Please login again.', 401);
        return;
      }
      // Update last active
      db.updateSession(decoded.sessionId, { lastActiveAt: new Date() });
      req.sessionId = decoded.sessionId;
    }
    
    req.user = { id: decoded.userId, role: user.role }; // Always use current role from DB
    req.clientIp = getClientIp(req);
    next();
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      fail(res, 'Token expired', 401);
    } else {
      fail(res, 'Invalid token', 401);
    }
  }
};

// Optional auth - doesn't fail if no token
export const optionalAuth = (req: Request, res: Response, next: NextFunction): void => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) { 
    next(); 
    return; 
  }

  try {
    const decoded = jwt.verify(token, config.jwtSecret) as { userId: string; role: Role };
    const user = db.findUserById(decoded.userId);
    if (user) {
      req.user = { id: decoded.userId, role: user.role };
    }
  } catch {
    // Ignore invalid token for optional auth
  }
  req.clientIp = getClientIp(req);
  next();
};

// Role check
export const requireRole = (...roles: Role[]) => (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user || !roles.includes(req.user.role)) {
    fail(res, 'Access denied. Insufficient permissions.', 403);
    return;
  }
  next();
};

// Check if user owns resource or is admin
export const requireOwnerOrAdmin = (getOwnerId: (req: Request) => string | undefined) => 
  (req: Request, res: Response, next: NextFunction): void => {
    const ownerId = getOwnerId(req);
    if (!req.user) {
      fail(res, 'Authentication required', 401);
      return;
    }
    if (req.user.role !== Role.ADMIN && req.user.id !== ownerId) {
      fail(res, 'Access denied. You do not own this resource.', 403);
      return;
    }
    next();
  };

// Input validation helpers
export const validate = {
  email: (email: string): boolean => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
  password: (pw: string): { valid: boolean; error?: string } => {
    if (pw.length < 8) return { valid: false, error: 'Password must be at least 8 characters' };
    if (pw.length > 128) return { valid: false, error: 'Password too long' };
    if (!/[A-Z]/.test(pw)) return { valid: false, error: 'Password must contain uppercase letter' };
    if (!/[a-z]/.test(pw)) return { valid: false, error: 'Password must contain lowercase letter' };
    if (!/[0-9]/.test(pw)) return { valid: false, error: 'Password must contain a number' };
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(pw)) return { valid: false, error: 'Password must contain a special character' };
    return { valid: true };
  },
  username: (name: string): boolean => /^[a-zA-Z0-9_]{3,30}$/.test(name),
  folderName: (name: string): boolean => /^[a-zA-Z0-9_\-\s.()\[\]&+,']{1,100}$/.test(name.trim()),
  tagName: (name: string): boolean => /^[a-zA-Z0-9_\-]{1,30}$/.test(name),
  sanitize: (str: string): string => str.replace(/[<>\"'&]/g, '').trim(),
  isUUID: (str: string): boolean => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(str),
  hexColor: (color: string): boolean => /^#[0-9A-Fa-f]{6}$/.test(color),
};

// File magic bytes validation
const FILE_SIGNATURES: Record<string, number[][]> = {
  'image/jpeg': [[0xFF, 0xD8, 0xFF]],
  'image/png': [[0x89, 0x50, 0x4E, 0x47]],
  'image/gif': [[0x47, 0x49, 0x46, 0x38]],
  'image/webp': [[0x52, 0x49, 0x46, 0x46]], // RIFF
  'application/pdf': [[0x25, 0x50, 0x44, 0x46]],
  'application/zip': [[0x50, 0x4B, 0x03, 0x04], [0x50, 0x4B, 0x05, 0x06]],
  'application/x-zip-compressed': [[0x50, 0x4B, 0x03, 0x04]],
  'text/plain': [],
  'text/csv': [],
  'application/json': [],
  'application/msword': [[0xD0, 0xCF, 0x11, 0xE0]],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [[0x50, 0x4B, 0x03, 0x04]],
  'application/vnd.ms-excel': [[0xD0, 0xCF, 0x11, 0xE0]],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': [[0x50, 0x4B, 0x03, 0x04]],
};

export const validateFileType = (buffer: Buffer, mimeType: string): boolean => {
  const signatures = FILE_SIGNATURES[mimeType];
  if (!signatures || signatures.length === 0) return true;
  return signatures.some(sig => sig.every((byte, i) => buffer[i] === byte));
};

// Storage quota check middleware
export const checkStorageQuota = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user) {
    fail(res, 'Authentication required', 401);
    return;
  }
  
  const user = db.findUserById(req.user.id);
  if (!user) {
    fail(res, 'User not found', 404);
    return;
  }
  
  // Admin has unlimited storage
  if (user.role === Role.ADMIN) {
    next();
    return;
  }
  
  const remainingQuota = user.storageQuota - user.storageUsed;
  if (remainingQuota <= 0) {
    fail(res, 'Storage quota exceeded. Please delete some files or contact admin.', 507);
    return;
  }
  
  next();
};

// File upload with enhanced validation
export const upload = multer({
  storage: multer.diskStorage({
    destination: config.uploadDir,
    filename: (_, file, cb) => cb(null, `${uuid()}${path.extname(file.originalname)}`),
  }),
  limits: { fileSize: config.maxFileSize },
  fileFilter: (req, file, cb) => {
    const allowedTypes = Object.keys(config.allowedFileTypes);
    if (!allowedTypes.includes(file.mimetype)) {
      cb(new Error(`File type not allowed. Allowed types: ${allowedTypes.join(', ')}`));
      return;
    }
    // Note: Type-specific size limits are enforced after upload in routes
    // since file.size is not available during fileFilter callback
    cb(null, true);
  },
});

// Upload handler for encrypted files (no MIME type restrictions)
export const uploadEncrypted = multer({
  storage: multer.diskStorage({
    destination: config.uploadDir,
    filename: (_, file, cb) => cb(null, `${uuid()}${path.extname(file.originalname)}`),
  }),
  limits: { fileSize: config.maxFileSize },
  fileFilter: (req, file, cb) => {
    // Only allow .enc files for decryption
    if (!file.originalname.toLowerCase().endsWith('.enc')) {
      cb(new Error('Only encrypted files (.enc) are allowed for decryption'));
      return;
    }
    cb(null, true);
  },
});

// Security headers middleware
export const securityHeaders = (req: Request, res: Response, next: NextFunction): void => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
    "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; " +
    "img-src 'self' data: blob:;"
  );
  next();
};

// Request logging middleware
export const requestLogger = (req: Request, res: Response, next: NextFunction): void => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logLevel = res.statusCode >= 400 ? 'WARN' : 'INFO';
    console.log(`[${logLevel}] ${new Date().toISOString()} ${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
  });
  next();
};

// Error handler
export const errorHandler = (err: Error, req: Request, res: Response, next: NextFunction): void => {
  console.error(`[ERROR] ${new Date().toISOString()} - ${err.message}`);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      fail(res, `File too large. Maximum size is ${Math.round(config.maxFileSize / 1024 / 1024)}MB`, 413);
      return;
    }
    fail(res, err.message, 400);
    return;
  }
  
  // Don't expose internal errors in production
  const message = process.env.NODE_ENV === 'production' 
    ? 'Internal server error' 
    : err.message || 'Internal server error';
    
  fail(res, message, 500);
};

// CORS configuration
export const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'Content-Disposition'],
  credentials: true,
  maxAge: 86400, // 24 hours
};
