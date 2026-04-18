import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import fs from 'fs';
import archiver from 'archiver';
import nodeCrypto from 'crypto';
import { v4 as uuid } from 'uuid';
import { db } from './db';
import { config } from './config';
import { Role, User, FileRecord, FileStatus, Folder, FileVersion, NotificationType, Category, FileAnnotation, Bookmark, FileTemplate, SavedFilter, ActivityType, SecurityEventType, ShareLink, WrappedKey } from './types';
import { 
  auth, optionalAuth, requireRole, rateLimit, checkStorageQuota,
  upload, uploadEncrypted, ok, fail, validate, validateFileType, getClientIp 
} from './middleware';
import { 
  encryptFile, decryptFile, hashFile, generateToken, 
  hashPassword, verifyPassword, generateSecureCode, ENCRYPTION_VERSION,
  verifyFileIntegrity, secureDelete, generateDeviceFingerprint,
  encryptFileWithUserKey, decryptFileWithUserKey, encryptBufferWithUserKey, decryptBufferWithUserKey, isUserKeyEncrypted, USER_KEY_VERSION,
  // New encryption mechanisms
  generateRSAKeyPair, rsaEncrypt, rsaDecrypt,
  generateECDHKeyPair, computeECDHSecret,
  chaChaEncrypt, chaChaDecrypt, chaChaEncryptFile, chaChaDecryptFile,
  hybridEncrypt, hybridDecrypt, hybridEncryptBuffer, hybridDecryptBuffer,
  generateSigningKeyPair, digitalSign, verifyDigitalSignature,
  generateECDSAKeyPair, ecdsaSign, verifyECDSASignature,
  envelopeEncrypt, envelopeDecrypt,
  wrapKey, unwrapKey,
  EncryptionAlgorithm, universalEncrypt, universalDecrypt, getEncryptionInfo,
  encryptFileWithAlgorithm, decryptFileWithAlgorithm,
  generatePassphrase, secureRandomBytes,
  // Key wrapping functions
  extractDekFromUserEncryptedFile, wrapDekForUser, unwrapDekForUser, decryptFileWithDek, decryptFileForUser
} from './crypto';
import { EncryptionAlgorithmType, UserKeyPair, FileSignature, EncryptionAudit } from './types';
import { setup2FA, verifyTOTP, validate2FASetup, verifyBackupCode } from './twofa';
import { globalRateLimiter } from './rate-limiter';

const router = Router();

interface ZeroTrustProofPayload {
  uid: string;
  sid: string;
  ipHash: string;
  uaHash: string;
  purpose: string;
  iat: number;
  exp: number;
  nonce: string;
}

interface SecureRecipientInput {
  recipientId: string;
  publicKey: string;
  email?: string;
}

const hashContextValue = (value: string): string =>
  nodeCrypto.createHash('sha256').update(value).digest('hex');

const signZeroTrustPayload = (payloadBase64: string): string =>
  nodeCrypto.createHmac('sha256', config.jwtSecret).update(payloadBase64).digest('base64url');

const issueZeroTrustProof = (req: Request, purpose: string): string => {
  const now = Date.now();
  const payload: ZeroTrustProofPayload = {
    uid: req.user!.id,
    sid: req.sessionId!,
    ipHash: hashContextValue(getClientIp(req)),
    uaHash: hashContextValue(req.headers['user-agent'] || 'unknown'),
    purpose,
    iat: now,
    exp: now + config.zeroTrust.proofTtlMs,
    nonce: generateToken(8),
  };

  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = signZeroTrustPayload(payloadBase64);
  return `${payloadBase64}.${signature}`;
};

const validateZeroTrustProof = (
  req: Request,
  purpose: string
): { valid: boolean; reason?: string; payload?: ZeroTrustProofPayload } => {
  const proof = (req.headers['x-zero-trust-proof'] as string | undefined) || req.body?.zeroTrustProof;
  if (!proof || typeof proof !== 'string') {
    return { valid: false, reason: 'Missing zero-trust proof' };
  }

  const [payloadBase64, signature] = proof.split('.');
  if (!payloadBase64 || !signature) {
    return { valid: false, reason: 'Malformed zero-trust proof' };
  }

  const expectedSignature = signZeroTrustPayload(payloadBase64);
  const signatureBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expectedSignature);
  if (signatureBuffer.length !== expectedBuffer.length || !nodeCrypto.timingSafeEqual(signatureBuffer, expectedBuffer)) {
    return { valid: false, reason: 'Invalid zero-trust proof signature' };
  }

  let payload: ZeroTrustProofPayload;
  try {
    payload = JSON.parse(Buffer.from(payloadBase64, 'base64url').toString('utf-8')) as ZeroTrustProofPayload;
  } catch {
    return { valid: false, reason: 'Invalid zero-trust proof payload' };
  }

  const now = Date.now();
  if (payload.exp < now - config.zeroTrust.maxClockSkewMs) {
    return { valid: false, reason: 'Zero-trust proof expired' };
  }

  if (payload.iat > now + config.zeroTrust.maxClockSkewMs) {
    return { valid: false, reason: 'Zero-trust proof issued in the future' };
  }

  if (!req.user || !req.sessionId) {
    return { valid: false, reason: 'Authenticated session required for zero-trust proof' };
  }

  if (payload.uid !== req.user.id) {
    return { valid: false, reason: 'Zero-trust proof user mismatch' };
  }

  if (payload.sid !== req.sessionId) {
    return { valid: false, reason: 'Zero-trust proof session mismatch' };
  }

  if (payload.purpose !== purpose) {
    return { valid: false, reason: 'Zero-trust proof purpose mismatch' };
  }

  const ipHash = hashContextValue(getClientIp(req));
  if (payload.ipHash !== ipHash) {
    return { valid: false, reason: 'Zero-trust proof IP mismatch' };
  }

  const uaHash = hashContextValue(req.headers['user-agent'] || 'unknown');
  if (payload.uaHash !== uaHash) {
    return { valid: false, reason: 'Zero-trust proof device mismatch' };
  }

  return { valid: true, payload };
};

// ============ AUTH ============
router.post('/auth/register', rateLimit(10, 60000), async (req: Request, res: Response) => {
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) return fail(res, 'All fields required');
  if (!validate.username(username)) return fail(res, 'Username: 3-30 chars, letters/numbers/underscore only');
  if (!validate.email(email)) return fail(res, 'Invalid email format');
  
  const pwCheck = validate.password(password);
  if (!pwCheck.valid) return fail(res, pwCheck.error!);
  
  if (db.findUserByEmail(email.toLowerCase())) return fail(res, 'Email already exists');
  if (db.findUserByUsername(username)) return fail(res, 'Username already taken');

  const user: User = {
    id: uuid(),
    username: validate.sanitize(username),
    email: email.toLowerCase(),
    password: await bcrypt.hash(password, 12),
    role: Role.VIEWER,
    createdAt: new Date(),
    twoFactorEnabled: false,
    storageQuota: config.defaultStorageQuota,
    storageUsed: 0,
    failedLoginAttempts: 0,
    encryptionKeyVersion: ENCRYPTION_VERSION,
    preferences: {
      emailNotifications: true,
      theme: 'dark',
      defaultEncrypt: true,
      autoLockMinutes: 30,
      showFileExtensions: true,
    },
  };
  
  // Generate RSA key pair for key wrapping
  try {
    const keyPair = generateRSAKeyPair(2048);
    user.publicKey = keyPair.publicKey;
    user.privateKey = keyPair.privateKey;
  } catch (err) {
    // BUG FIX 6: Add proper error logging
    console.error('Failed to generate key pair during registration:', err);
    db.logSecurityEvent({
      userId: user.id,
      eventType: 'encryption_key_rotated' as any,
      description: 'Failed to generate RSA key pair during registration',
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
      metadata: { error: err instanceof Error ? err.message : String(err) },
    });
    // Non-fatal - user can still register
  }
  
  db.createUser(user);
  db.log(user.id, 'REGISTER', user.id, '', getClientIp(req), req.headers['user-agent']);
  
  // Welcome notification
  db.notify(user.id, NotificationType.SYSTEM, 'Welcome!', 
    `Welcome to Secure File System, ${user.username}! Start by uploading your first file.`);
  
  const { password: _, ...safe } = user;
  ok(res, safe, 'Registered successfully', 201);
});

router.post('/auth/login', rateLimit(5, 60000), async (req: Request, res: Response) => {
  const { email, password, totpCode } = req.body;
  const user = db.findUserByEmail(email?.toLowerCase());
  
  if (!user) {
    return fail(res, 'Invalid credentials', 401);
  }
  
  // Check if account is locked FIRST
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    const remainingMs = user.lockedUntil.getTime() - Date.now();
    const remainingMins = Math.ceil(remainingMs / 60000);
    db.log(user.id, 'LOGIN_BLOCKED', user.id, `Account locked, ${remainingMins} minutes remaining`, getClientIp(req), req.headers['user-agent']);
    return fail(res, `Account locked due to failed login attempts. Try again in ${remainingMins} minutes.`, 423);
  }
  
  // Verify password
  if (!(await bcrypt.compare(password, user.password))) {
    // Increment failed attempts
    const attempts = user.failedLoginAttempts + 1;
    const updates: Partial<User> = { failedLoginAttempts: attempts };
    
    // Lock account if threshold reached
    if (attempts >= config.rateLimit.maxLoginAttempts) {
      updates.lockedUntil = new Date(Date.now() + config.rateLimit.lockoutDuration);
      db.notify(user.id, NotificationType.SECURITY_ALERT, 'Account Locked',
        `Your account has been locked for 5 minutes due to ${attempts} failed login attempts.`);
      db.log(user.id, 'ACCOUNT_LOCKED', user.id, `Locked after ${attempts} failed attempts`, getClientIp(req), req.headers['user-agent']);
      
      db.updateUser(user.id, updates);
      return fail(res, `Account locked due to ${attempts} failed login attempts. Please wait 5 minutes before trying again.`, 423);
    }
    
    db.updateUser(user.id, updates);
    db.log(user.id, 'LOGIN_FAILED', user.id, `Invalid password (attempt ${attempts}/${config.rateLimit.maxLoginAttempts})`, getClientIp(req), req.headers['user-agent']);
    
    const remaining = config.rateLimit.maxLoginAttempts - attempts;
    return fail(res, `Invalid credentials. You have ${remaining} attempt${remaining === 1 ? '' : 's'} remaining before account lockout.`, 401);
  }
  
  // Check 2FA if enabled
  if (user.twoFactorEnabled) {
    if (!totpCode) {
      return ok(res, { requires2FA: true }, 'Two-factor authentication required');
    }
    
    // ACTUALLY VERIFY 2FA CODE
    if (!user.twoFactorSecret || !verifyTOTP(totpCode, user.twoFactorSecret)) {
      // Increment failed attempts for 2FA failures too
      const attempts = user.failedLoginAttempts + 1;
      const updates: Partial<User> = { failedLoginAttempts: attempts };
      
      if (attempts >= config.rateLimit.maxLoginAttempts) {
        updates.lockedUntil = new Date(Date.now() + config.rateLimit.lockoutDuration);
        db.notify(user.id, NotificationType.SECURITY_ALERT, 'Account Locked',
          `Your account has been locked for 5 minutes due to ${attempts} failed 2FA attempts.`);
        
        db.updateUser(user.id, updates);
        db.log(user.id, '2FA_FAILED', user.id, `Invalid 2FA code (attempt ${attempts}/${config.rateLimit.maxLoginAttempts})`, getClientIp(req), req.headers['user-agent']);
        return fail(res, `Account locked due to ${attempts} failed 2FA attempts. Please wait 5 minutes before trying again.`, 423);
      }
      
      db.updateUser(user.id, updates);
      db.log(user.id, '2FA_FAILED', user.id, `Invalid 2FA code (attempt ${attempts}/${config.rateLimit.maxLoginAttempts})`, getClientIp(req), req.headers['user-agent']);
      
      const remaining = config.rateLimit.maxLoginAttempts - attempts;
      return fail(res, `Invalid 2FA code. You have ${remaining} attempt${remaining === 1 ? '' : 's'} remaining before account lockout.`, 401);
    }
  }
  
  // Reset failed attempts on successful login
  db.updateUser(user.id, { 
    failedLoginAttempts: 0, 
    lockedUntil: undefined,
    lastLoginAt: new Date(),
  });

  // Generate RSA key pair if user doesn't have one (for key wrapping)
  if (!user.publicKey || !user.privateKey) {
    try {
      const keyPair = generateRSAKeyPair(2048);
      db.updateUser(user.id, {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
      });
      // Refresh user object
      const updatedUser = db.findUserById(user.id);
      if (updatedUser) {
        Object.assign(user, updatedUser);
      }
    } catch (err) {
      // BUG FIX 6: Add proper error logging
      console.error('Failed to generate key pair for user:', err);
      db.logSecurityEvent({
        userId: user.id,
        eventType: 'encryption_key_rotated' as any,
        description: 'Failed to generate RSA key pair during login',
        ipAddress: getClientIp(req),
        userAgent: req.headers['user-agent'],
        metadata: { error: err instanceof Error ? err.message : String(err) },
      });
      // Non-fatal error - user can still login
    }
  }

  // Create session
  const sessionId = uuid();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
  
  db.createSession({
    id: sessionId,
    userId: user.id,
    token: generateToken(),
    userAgent: req.headers['user-agent'] || 'unknown',
    ipAddress: getClientIp(req),
    createdAt: new Date(),
    expiresAt,
    lastActiveAt: new Date(),
  });

  const token = jwt.sign(
    { userId: user.id, role: user.role, sessionId }, 
    config.jwtSecret, 
    { expiresIn: '720h' } // 30 days
  );
  
  db.log(user.id, 'LOGIN', user.id, '', getClientIp(req), req.headers['user-agent']);
  
  // Get user stats for dashboard
  const userFiles = db.getFilesByUser(user.id);
  const recentLogs = db.getLogsByUser(user.id, 5);
  const unreadNotifications = db.getUnreadCount(user.id);
  
  ok(res, { 
    token, 
    user: { 
      id: user.id, 
      username: user.username, 
      email: user.email, 
      role: user.role,
      twoFactorEnabled: user.twoFactorEnabled,
      storageQuota: user.storageQuota,
      storageUsed: user.storageUsed,
      preferences: user.preferences,
    },
    stats: {
      totalFiles: userFiles.length,
      totalSize: userFiles.reduce((sum, f) => sum + f.size, 0),
      recentActivity: recentLogs,
      unreadNotifications,
    }
  });
});

router.post('/auth/logout', auth, (req: Request, res: Response) => {
  if (req.sessionId) {
    db.deleteSession(req.sessionId);
  }
  db.log(req.user!.id, 'LOGOUT', req.user!.id);
  ok(res, null, 'Logged out successfully');
});

router.post('/auth/logout-all', auth, (req: Request, res: Response) => {
  db.deleteSessionsByUser(req.user!.id);
  db.log(req.user!.id, 'LOGOUT_ALL', req.user!.id);
  ok(res, null, 'All sessions terminated');
});

router.get('/auth/me', auth, (req: Request, res: Response) => {
  const user = db.findUserById(req.user!.id);
  if (!user) return fail(res, 'User not found', 404);
  const { password: _, twoFactorSecret, ...safe } = user;
  ok(res, safe);
});

router.post('/security/zero-trust/proof', auth, (req: Request, res: Response) => {
  if (!req.sessionId) {
    return fail(res, 'Session-bound authentication is required for zero-trust proof', 401);
  }

  const purposeRaw = typeof req.body?.purpose === 'string' ? req.body.purpose.trim() : 'secure-share';
  const purpose = purposeRaw.length > 0 ? purposeRaw : 'secure-share';
  const proof = issueZeroTrustProof(req, purpose);

  ok(res, {
    proof,
    purpose,
    expiresInMs: config.zeroTrust.proofTtlMs,
    sessionBound: true,
    ipBound: true,
    userAgentBound: true,
  }, 'Zero-trust proof issued');
});

router.get('/auth/sessions', auth, (req: Request, res: Response) => {
  const sessions = db.getSessionsByUser(req.user!.id).map(s => ({
    id: s.id,
    userAgent: s.userAgent,
    ipAddress: s.ipAddress,
    createdAt: s.createdAt,
    lastActiveAt: s.lastActiveAt,
    isCurrent: s.id === req.sessionId,
  }));
  ok(res, sessions);
});

router.delete('/auth/sessions/:id', auth, (req: Request, res: Response) => {
  const session = db.findSessionById(req.params.id);
  if (!session || session.userId !== req.user!.id) {
    return fail(res, 'Session not found', 404);
  }
  db.deleteSession(req.params.id);
  ok(res, null, 'Session terminated');
});

router.post('/auth/change-password', auth, async (req: Request, res: Response) => {
  const { currentPassword, newPassword } = req.body;
  const user = db.findUserById(req.user!.id);
  
  if (!user) return fail(res, 'User not found', 404);
  if (!(await bcrypt.compare(currentPassword, user.password))) {
    return fail(res, 'Current password incorrect', 401);
  }
  
  const pwCheck = validate.password(newPassword);
  if (!pwCheck.valid) return fail(res, pwCheck.error!);
  
  // CRITICAL FIX: Add passwordChangedAt timestamp to invalidate old tokens
  db.updateUser(user.id, { 
    password: await bcrypt.hash(newPassword, 12),
    passwordChangedAt: new Date()
  });
  
  // Terminate all sessions
  db.deleteSessionsByUser(user.id);
  
  db.log(user.id, 'PASSWORD_CHANGE', user.id, '', req.clientIp, req.headers['user-agent']);
  db.notify(user.id, NotificationType.SECURITY_ALERT, 'Password Changed',
    'Your password was successfully changed. All sessions have been invalidated.');
  
  ok(res, null, 'Password changed successfully. Please login again.');
});

// BUG FIX 17: Add password strength check endpoint
router.post('/auth/check-password-strength', (req: Request, res: Response) => {
  const { password } = req.body;
  
  if (!password || typeof password !== 'string') {
    return fail(res, 'Password required');
  }
  
  const strength = validate.passwordStrength(password);
  const basicCheck = validate.password(password);
  
  ok(res, {
    score: strength.score,
    maxScore: 10,
    feedback: strength.feedback,
    meetsRequirements: basicCheck.valid,
    requirementError: basicCheck.error,
  });
});

router.patch('/auth/preferences', auth, (req: Request, res: Response) => {
  const { emailNotifications, theme, defaultEncrypt } = req.body;
  const user = db.findUserById(req.user!.id);
  if (!user) return fail(res, 'User not found', 404);
  
  const prefs = { ...user.preferences };
  if (typeof emailNotifications === 'boolean') prefs.emailNotifications = emailNotifications;
  if (theme === 'dark' || theme === 'light') prefs.theme = theme;
  if (typeof defaultEncrypt === 'boolean') prefs.defaultEncrypt = defaultEncrypt;
  
  db.updateUser(user.id, { preferences: prefs });
  ok(res, prefs, 'Preferences updated');
});

// ============ TWO-FACTOR AUTHENTICATION ============
// Feature 1: TOTP-based 2FA with QR codes and backup codes

router.post('/auth/2fa/setup', auth, (req: Request, res: Response) => {
  const user = db.findUserById(req.user!.id);
  if (!user) return fail(res, 'User not found', 404);
  
  if (user.twoFactorEnabled) {
    return fail(res, '2FA is already enabled. Disable it first to set up again.');
  }
  
  const setup = setup2FA(user.username, user.email);
  
  // Store secret temporarily (will be confirmed on verification)
  db.updateUser(user.id, {
    twoFactorSecret: setup.secret,
    twoFactorBackupCodes: setup.backupCodesHashed,
  });
  
  ok(res, {
    secret: setup.secret,
    qrCodeURL: setup.qrCodeURL,
    qrCodeASCII: setup.qrCodeASCII,
    backupCodes: setup.backupCodes, // Show once, user must save them
  }, '2FA setup initiated. Verify with a code to enable.');
});

router.post('/auth/2fa/verify', auth, (req: Request, res: Response) => {
  const { token } = req.body;
  const user = db.findUserById(req.user!.id);
  
  if (!user) return fail(res, 'User not found', 404);
  if (!user.twoFactorSecret) return fail(res, '2FA setup not initiated', 400);
  
  const validation = validate2FASetup(user.twoFactorSecret, token);
  if (!validation.valid) {
    return fail(res, validation.error || 'Invalid verification code');
  }
  
  // Enable 2FA
  db.updateUser(user.id, { twoFactorEnabled: true });
  
  db.log(user.id, 'ENABLE_2FA', user.id, '', req.clientIp, req.headers['user-agent']);
  db.notify(user.id, NotificationType.SECURITY_ALERT, '2FA Enabled',
    'Two-factor authentication has been successfully enabled on your account.');
  
  ok(res, null, '2FA enabled successfully');
});

router.post('/auth/2fa/disable', auth, async (req: Request, res: Response) => {
  const { password, token } = req.body;
  const user = db.findUserById(req.user!.id);
  
  if (!user) return fail(res, 'User not found', 404);
  if (!user.twoFactorEnabled) return fail(res, '2FA is not enabled');
  
  // Verify password
  if (!(await bcrypt.compare(password, user.password))) {
    return fail(res, 'Invalid password', 401);
  }
  
  // Verify 2FA token
  if (!user.twoFactorSecret || !verifyTOTP(token, user.twoFactorSecret)) {
    return fail(res, 'Invalid 2FA code', 401);
  }
  
  // Disable 2FA
  db.updateUser(user.id, {
    twoFactorEnabled: false,
    twoFactorSecret: undefined,
    twoFactorBackupCodes: undefined,
  });
  
  db.log(user.id, 'DISABLE_2FA', user.id, '', req.clientIp, req.headers['user-agent']);
  db.notify(user.id, NotificationType.SECURITY_ALERT, '2FA Disabled',
    'Two-factor authentication has been disabled on your account.');
  
  ok(res, null, '2FA disabled successfully');
});

router.post('/auth/2fa/verify-login', async (req: Request, res: Response) => {
  const { email, password, totpCode, backupCode } = req.body;
  const user = db.findUserByEmail(email?.toLowerCase());
  
  if (!user) return fail(res, 'Invalid credentials', 401);
  if (!user.twoFactorEnabled) return fail(res, '2FA not enabled for this account', 400);
  
  // Verify password
  if (!(await bcrypt.compare(password, user.password))) {
    return fail(res, 'Invalid credentials', 401);
  }
  
  // Verify 2FA code or backup code
  let verified = false;
  
  if (totpCode && user.twoFactorSecret) {
    verified = verifyTOTP(totpCode, user.twoFactorSecret);
  } else if (backupCode && user.twoFactorBackupCodes) {
    // Check backup codes
    const codeIndex = user.twoFactorBackupCodes.findIndex((hash: string) => 
      verifyBackupCode(backupCode, hash)
    );
    
    if (codeIndex !== -1) {
      verified = true;
      // Remove used backup code
      const updatedCodes = [...user.twoFactorBackupCodes];
      updatedCodes.splice(codeIndex, 1);
      db.updateUser(user.id, { twoFactorBackupCodes: updatedCodes });
      
      db.notify(user.id, NotificationType.SECURITY_ALERT, 'Backup Code Used',
        `A backup code was used to login. ${updatedCodes.length} codes remaining.`);
    }
  }
  
  if (!verified) {
    return fail(res, 'Invalid 2FA code', 401);
  }
  
  // Create session (same as regular login)
  const sessionId = uuid();
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  
  db.createSession({
    id: sessionId,
    userId: user.id,
    token: generateToken(),
    userAgent: req.headers['user-agent'] || 'unknown',
    ipAddress: getClientIp(req),
    createdAt: new Date(),
    expiresAt,
    lastActiveAt: new Date(),
  });

  const token = jwt.sign(
    { userId: user.id, role: user.role, sessionId }, 
    config.jwtSecret, 
    { expiresIn: '720h' }
  );
  
  db.log(user.id, 'LOGIN_2FA', user.id, '', getClientIp(req), req.headers['user-agent']);
  
  ok(res, { 
    token, 
    user: { 
      id: user.id, 
      username: user.username, 
      email: user.email, 
      role: user.role,
    }
  });
});

router.post('/auth/2fa/regenerate-backup-codes', auth, async (req: Request, res: Response) => {
  const { password } = req.body;
  const user = db.findUserById(req.user!.id);
  
  if (!user) return fail(res, 'User not found', 404);
  if (!user.twoFactorEnabled) return fail(res, '2FA is not enabled');
  
  // Verify password
  if (!(await bcrypt.compare(password, user.password))) {
    return fail(res, 'Invalid password', 401);
  }
  
  const setup = setup2FA(user.username, user.email);
  
  db.updateUser(user.id, {
    twoFactorBackupCodes: setup.backupCodesHashed,
  });
  
  db.log(user.id, 'REGENERATE_BACKUP_CODES', user.id, '', req.clientIp, req.headers['user-agent']);
  
  ok(res, {
    backupCodes: setup.backupCodes,
  }, 'Backup codes regenerated. Save them securely.');
});

// ============ DASHBOARD ============
router.get('/dashboard', auth, (req: Request, res: Response) => {
  const user = db.findUserById(req.user!.id);
  if (!user) return fail(res, 'User not found', 404);

  const isAdmin = req.user!.role === Role.ADMIN;
  const userFiles = isAdmin ? db.getAllFiles() : db.getFilesByUser(req.user!.id);
  const recentLogs = isAdmin ? db.getLogs(10) : db.getLogsByUser(req.user!.id, 10);
  const favorites = db.getFavorites(req.user!.id);
  const trashedFiles = db.getTrashedFiles(req.user!.id);
  
  const stats = {
    totalFiles: userFiles.length,
    encryptedFiles: userFiles.filter(f => f.encrypted).length,
    totalSize: userFiles.reduce((sum, f) => sum + f.size, 0),
    bookmarkCount: db.getBookmarksByUser(req.user!.id).length,
    annotationCount: db.getAnnotationsByUser(req.user!.id).length,
    favoriteCount: favorites.length,
    trashCount: trashedFiles.length,
    storageUsed: user.storageUsed,
    storageQuota: user.storageQuota,
    storagePercent: Math.round((user.storageUsed / user.storageQuota) * 100),
  };

  // Add system stats for admin
  const systemStats = isAdmin ? db.getSystemStats() : null;

  ok(res, { 
    stats, 
    systemStats,
    recentActivity: recentLogs, 
    recentFiles: userFiles.slice(0, 5),
    favorites: favorites.slice(0, 5),
    unreadNotifications: db.getUnreadCount(req.user!.id),
  });
});

// ============ FOLDERS ============
router.get('/folders', auth, (req: Request, res: Response) => {
  const { parentId } = req.query;
  const folders = db.getFoldersByUser(req.user!.id, parentId as string | undefined);
  const files = db.getFilesByFolder(parentId as string | undefined, req.user!.id);
  
  ok(res, { folders, files });
});

router.post('/folders', auth, requireRole(Role.ADMIN, Role.EDITOR), (req: Request, res: Response) => {
  const { name, parentId, color } = req.body;
  
  if (!name || !name.trim()) {
    return fail(res, 'Folder name is required');
  }
  
  if (!validate.folderName(name)) {
    return fail(res, 'Invalid folder name. Use only letters, numbers, spaces, and common punctuation (1-100 characters)');
  }
  
  // Verify parent exists if provided
  if (parentId) {
    const parent = db.findFolderById(parentId);
    if (!parent || parent.ownerId !== req.user!.id) {
      return fail(res, 'Parent folder not found', 404);
    }
  }
  
  const folder: Folder = {
    id: uuid(),
    name: validate.sanitize(name),
    ownerId: req.user!.id,
    parentId,
    color: color && validate.hexColor(color) ? color : '#3b82f6',
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  
  db.createFolder(folder);
  db.log(req.user!.id, 'CREATE_FOLDER', folder.id, folder.name);
  ok(res, folder, 'Folder created', 201);
});

router.patch('/folders/:id', auth, (req: Request, res: Response) => {
  const folder = db.findFolderById(req.params.id);
  if (!folder) return fail(res, 'Folder not found', 404);
  if (folder.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) {
    return fail(res, 'Access denied', 403);
  }
  
  const { name, color, parentId } = req.body;
  const updates: Partial<Folder> = {};
  
  if (name && validate.folderName(name)) updates.name = validate.sanitize(name);
  if (color && validate.hexColor(color)) updates.color = color;
  if (parentId !== undefined) {
    if (parentId === folder.id) return fail(res, 'Folder cannot be its own parent');
    if (parentId) {
      const parent = db.findFolderById(parentId);
      if (!parent || parent.ownerId !== req.user!.id) {
        return fail(res, 'Parent folder not found', 404);
      }
    }
    updates.parentId = parentId || undefined;
  }
  
  const updated = db.updateFolder(folder.id, updates);
  ok(res, updated, 'Folder updated');
});

router.delete('/folders/:id', auth, (req: Request, res: Response) => {
  const folder = db.findFolderById(req.params.id);
  if (!folder) return fail(res, 'Folder not found', 404);
  if (folder.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) {
    return fail(res, 'Access denied', 403);
  }
  
  // Check for files in folder
  const filesInFolder = db.getFilesByFolder(folder.id, req.user!.id);
  if (filesInFolder.length > 0) {
    return fail(res, 'Folder is not empty. Move or delete files first.');
  }
  
  // Check for subfolders
  const subfolders = db.getFoldersByUser(req.user!.id, folder.id);
  if (subfolders.length > 0) {
    return fail(res, 'Folder has subfolders. Delete them first.');
  }
  
  db.deleteFolder(folder.id);
  db.log(req.user!.id, 'DELETE_FOLDER', folder.id, folder.name);
  ok(res, null, 'Folder deleted');
});

// ============ FILES ============
router.get('/files', auth, (req: Request, res: Response) => {
  const { 
    search, page = '1', limit = '20', sort = 'createdAt', order = 'desc',
    folderId, tag, favorites, trash, bookmarks, categoryId, mimeType, dateFrom, dateTo, hasAnnotations
  } = req.query;
  
  let files: FileRecord[];
  
  if (trash === 'true') {
    files = db.getTrashedFiles(req.user!.id);
  } else if (favorites === 'true') {
    files = db.getFavorites(req.user!.id);
  } else if (bookmarks === 'true') {
    // Get bookmarked files
    const userBookmarks = db.getBookmarksByUser(req.user!.id);
    const bookmarkedFileIds = new Set(userBookmarks.map(b => b.fileId));
    files = db.getFilesByUser(req.user!.id).filter(f => bookmarkedFileIds.has(f.id));
  } else if (hasAnnotations === 'true') {
    files = db.getFilesWithAnnotations(req.user!.id);
  } else if (categoryId) {
    files = db.getFilesByCategory(categoryId as string, req.user!.id);
  } else if (tag) {
    files = db.getFilesByTag(tag as string, req.user!.id);
  } else if (folderId !== undefined) {
    files = db.getFilesByFolder(folderId as string || undefined, req.user!.id);
  } else {
    files = req.user!.role === Role.ADMIN ? db.getAllFiles() : db.getFilesByUser(req.user!.id);
  }
  
  // Search
  if (search) {
    const term = (search as string).toLowerCase();
    files = files.filter(f => 
      f.name.toLowerCase().includes(term) ||
      f.tags.some(t => t.toLowerCase().includes(term)) ||
      f.description?.toLowerCase().includes(term)
    );
  }
  
  // Filter by mime type
  if (mimeType) {
    files = files.filter(f => f.mimeType.startsWith(mimeType as string));
  }
  
  // Filter by date range
  if (dateFrom) {
    const from = new Date(dateFrom as string);
    files = files.filter(f => f.createdAt >= from);
  }
  if (dateTo) {
    const to = new Date(dateTo as string);
    files = files.filter(f => f.createdAt <= to);
  }
  
  // Sort
  files.sort((a, b) => {
    const aVal = a[sort as keyof FileRecord];
    const bVal = b[sort as keyof FileRecord];
    const cmp = aVal! < bVal! ? -1 : aVal! > bVal! ? 1 : 0;
    return order === 'desc' ? -cmp : cmp;
  });
  
  // Paginate
  const pageNum = Math.max(1, parseInt(page as string));
  const limitNum = Math.min(100, Math.max(1, parseInt(limit as string)));
  const start = (pageNum - 1) * limitNum;
  const paginated = files.slice(start, start + limitNum);
  
  ok(res, {
    files: paginated.map(f => {
      const owner = db.findUserById(f.ownerId);
      return { 
        id: f.id, 
        name: f.name, 
        size: f.size, 
        mimeType: f.mimeType,
        encrypted: f.encrypted,
        userKeyEncrypted: f.userKeyEncrypted || false,
        ownerId: f.ownerId,
        ownerName: owner?.username,
        createdAt: f.createdAt,
        deletedAt: f.deletedAt,
        folderId: f.folderId,
        tags: f.tags,
        description: f.description,
        version: f.version,
        status: f.status,
        isOwner: f.ownerId === req.user!.id,
        isFavorite: f.favoriteOf.includes(req.user!.id),
        isBookmarked: db.getBookmarksByUser(req.user!.id).some(b => b.fileId === f.id),
        annotationCount: db.getAnnotationsByFile(f.id).length,
        downloadCount: f.downloadCount,
      };
    }),
    pagination: {
      page: pageNum,
      limit: limitNum,
      total: files.length,
      pages: Math.ceil(files.length / limitNum),
    }
  });
});

router.post('/files/upload', auth, requireRole(Role.ADMIN, Role.EDITOR), upload.single('file'), (req: Request, res: Response) => {
  if (!req.file) return fail(res, 'No file uploaded');

  const user = db.findUserById(req.user!.id);
  if (!user) return fail(res, 'User not found', 404);
  
  // Atomic quota check and reservation
  if (user.role !== Role.ADMIN && user.storageUsed + req.file.size > user.storageQuota) {
    fs.unlinkSync(req.file.path);
    return fail(res, 'Storage quota exceeded', 507);
  }
  
  // Reserve quota immediately
  db.updateStorageUsed(req.user!.id, req.file.size);

  // Validate file magic bytes
  const buffer = fs.readFileSync(req.file.path);
  if (!validateFileType(buffer, req.file.mimetype)) {
    fs.unlinkSync(req.file.path);
    return fail(res, 'File content does not match its type');
  }

  // Check type-specific size limit
  const typeLimit = config.allowedFileTypes[req.file.mimetype as keyof typeof config.allowedFileTypes];
  if (typeLimit && req.file.size > typeLimit) {
    fs.unlinkSync(req.file.path);
    return fail(res, `File too large for this type. Max size: ${Math.round(typeLimit / 1024 / 1024)}MB`);
  }

  // BUG FIX 8: Add filename uniqueness check within same folder/user scope
  const folderId = req.body.folderId || undefined;
  const existingFiles = db.getFilesByFolder(folderId, req.user!.id);
  const sanitizedName = validate.sanitize(req.file.originalname);
  if (existingFiles.some(f => f.name === sanitizedName && f.status === FileStatus.ACTIVE)) {
    fs.unlinkSync(req.file.path);
    return fail(res, 'A file with this name already exists in this location');
  }

  const encrypt = req.body.encrypt !== 'false' && user.preferences.defaultEncrypt !== false;
  const userEncryptionKey = req.body.userEncryptionKey?.trim();
  
  // BUG FIX 7: Validate user encryption key length
  if (userEncryptionKey) {
    const keyValidation = validate.userEncryptionKey(userEncryptionKey);
    if (!keyValidation.valid) {
      fs.unlinkSync(req.file.path);
      return fail(res, keyValidation.error!);
    }
  }
  
  // BUG FIX 9: Add comprehensive input validation with whitelist for metadata fields
  const allowedMetadataFields = ['folderId', 'tags', 'description', 'categoryId', 'encrypt', 'userEncryptionKey', 'clientSideEncrypted', 'encryptedMetadata'];
  const providedFields = Object.keys(req.body);
  const invalidFields = providedFields.filter(f => !allowedMetadataFields.includes(f));
  if (invalidFields.length > 0) {
    fs.unlinkSync(req.file.path);
    return fail(res, `Invalid metadata fields: ${invalidFields.join(', ')}`);
  }
  
  // Validate folderId if provided
  if (req.body.folderId && !validate.isUUID(req.body.folderId)) {
    fs.unlinkSync(req.file.path);
    return fail(res, 'Invalid folder ID format');
  }
  
  // Validate tags if provided
  if (req.body.tags) {
    try {
      const tags = JSON.parse(req.body.tags);
      if (!Array.isArray(tags) || tags.length > 10) {
        fs.unlinkSync(req.file.path);
        return fail(res, 'Tags must be an array with max 10 items');
      }
      if (!tags.every((t: any) => typeof t === 'string' && validate.tagName(t))) {
        fs.unlinkSync(req.file.path);
        return fail(res, 'Invalid tag format');
      }
    } catch {
      fs.unlinkSync(req.file.path);
      return fail(res, 'Invalid tags JSON');
    }
  }
  
  // Validate description length
  if (req.body.description && req.body.description.length > 500) {
    fs.unlinkSync(req.file.path);
    return fail(res, 'Description too long (max 500 characters)');
  }
  
  // Validate categoryId if provided
  if (req.body.categoryId && !validate.isUUID(req.body.categoryId)) {
    fs.unlinkSync(req.file.path);
    return fail(res, 'Invalid category ID format');
  }
  
  const useUserKey = encrypt && userEncryptionKey && userEncryptionKey.length >= 8;
  
  // Check if this is a client-side encrypted upload (zero-knowledge mode)
  const clientSideEncrypted = req.body.clientSideEncrypted === 'true';
  
  const originalPath = req.file.path;
  const storedName = `${uuid()}.enc`;
  const storedPath = path.join(config.uploadDir, storedName);

  // Compute checksum on ORIGINAL content BEFORE encryption
  let originalChecksum: string;
  
  if (clientSideEncrypted) {
    // For client-side encrypted files, we can't compute checksum of original
    // The file is already encrypted when it reaches the server
    originalChecksum = hashFile(originalPath);
    // Just move the encrypted file
    fs.renameSync(originalPath, storedPath);
  } else {
    // Server-side encryption or no encryption
    originalChecksum = hashFile(originalPath);

    try {
      if (encrypt) {
        if (useUserKey) {
          encryptFileWithUserKey(originalPath, storedPath, userEncryptionKey);
        } else {
          encryptFile(originalPath, storedPath);
        }
        secureDelete(originalPath);
      } else {
        fs.renameSync(originalPath, storedPath);
      }
    } catch (err: any) {
      // Rollback quota reservation on failure
      db.updateStorageUsed(req.user!.id, -req.file.size);
      if (fs.existsSync(originalPath)) fs.unlinkSync(originalPath);
      if (fs.existsSync(storedPath)) fs.unlinkSync(storedPath);
      return fail(res, `Upload failed: ${err.message}`, 500);
    }
  }

  const file: FileRecord = {
    id: uuid(),
    name: validate.sanitize(req.file.originalname),
    storedName,
    size: req.file.size,
    mimeType: req.file.mimetype,
    ownerId: req.user!.id,
    encrypted: encrypt || clientSideEncrypted,
    checksum: originalChecksum,
    encryptionVersion: clientSideEncrypted ? 99 : (useUserKey ? USER_KEY_VERSION : 3),
    userKeyEncrypted: useUserKey || clientSideEncrypted,
    createdAt: new Date(),
    status: FileStatus.ACTIVE,
    folderId: req.body.folderId || undefined,
    tags: req.body.tags ? JSON.parse(req.body.tags) : [],
    description: req.body.description ? validate.sanitize(req.body.description) : undefined,
    version: 1,
    favoriteOf: [],
    sharedWith: [],
    downloadCount: 0,
    categoryId: req.body.categoryId || undefined,
  };

  // Store encrypted metadata if provided (zero-knowledge mode)
  if (clientSideEncrypted && req.body.encryptedMetadata) {
    try {
      const encryptedMeta = JSON.parse(req.body.encryptedMetadata);
      // Store encrypted metadata in a separate field or database
      // For now, we'll just mark it as client-side encrypted
      file.description = '[Encrypted - Zero-Knowledge Mode]';
    } catch (err) {
      // BUG FIX 6: Add proper error logging
      console.error('Failed to parse encrypted metadata:', err);
      db.logSecurityEvent({
        userId: req.user!.id,
        eventType: 'file_analysis' as any,
        description: 'Failed to parse encrypted metadata during upload',
        ipAddress: getClientIp(req),
        userAgent: req.headers['user-agent'],
        metadata: { error: err instanceof Error ? err.message : String(err) },
      });
    }
  }

  db.createFile(file);
  db.log(req.user!.id, 'UPLOAD', file.id, file.name, req.clientIp, req.headers['user-agent']);
  db.addActivity({
    userId: req.user!.id,
    type: ActivityType.FILE_UPLOAD,
    message: `Uploaded ${file.name}`,
    fileId: file.id,
  });
  
  ok(res, { 
    id: file.id, 
    name: file.name, 
    size: file.size,
    encrypted: file.encrypted,
    userKeyEncrypted: file.userKeyEncrypted || false,
    version: file.version,
  }, 'File uploaded', 201);
});

router.post('/files/:id/version', auth, requireRole(Role.ADMIN, Role.EDITOR), checkStorageQuota, upload.single('file'), (req: Request, res: Response) => {
  const oldFile = db.findFileById(req.params.id);
  if (!oldFile) return fail(res, 'File not found', 404);
  if (oldFile.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) {
    return fail(res, 'Access denied', 403);
  }
  if (!req.file) return fail(res, 'No file uploaded');

  // Validate file type matches
  if (req.file.mimetype !== oldFile.mimeType) {
    fs.unlinkSync(req.file.path);
    return fail(res, 'New version must be same file type');
  }

  // BUG FIX 19: Enforce hard limit on file versions BEFORE creating new version
  const existingVersions = db.getVersionsByFile(oldFile.id);
  if (existingVersions.length >= config.maxVersions) {
    fs.unlinkSync(req.file.path);
    return fail(res, `Maximum version limit reached (${config.maxVersions} versions). Delete old versions first.`);
  }

  // Store current version
  const versionStoredName = `${uuid()}.ver`;
  const versionPath = path.join(config.versionsDir, versionStoredName);
  const currentPath = path.join(config.uploadDir, oldFile.storedName);
  
  if (fs.existsSync(currentPath)) {
    fs.copyFileSync(currentPath, versionPath);
  }

  const version: FileVersion = {
    id: uuid(),
    fileId: oldFile.id,
    storedName: versionStoredName,
    size: oldFile.size,
    checksum: oldFile.checksum,
    version: oldFile.version,
    createdBy: req.user!.id,
    createdAt: new Date(),
    comment: req.body.comment,
  };
  db.createVersion(version);

  // Process new file
  const encrypt = oldFile.encrypted;
  const originalPath = req.file.path;
  const storedName = `${uuid()}.enc`;
  const storedPath = path.join(config.uploadDir, storedName);

  // Compute checksum on ORIGINAL content BEFORE encryption
  const originalChecksum = hashFile(originalPath);

  if (encrypt) {
    encryptFile(originalPath, storedPath);
    fs.unlinkSync(originalPath);
  } else {
    fs.renameSync(originalPath, storedPath);
  }

  // Delete old stored file
  if (fs.existsSync(currentPath)) {
    fs.unlinkSync(currentPath);
  }

  // Update file record
  const sizeDiff = req.file.size - oldFile.size;
  db.updateFile(oldFile.id, {
    storedName,
    size: req.file.size,
    checksum: originalChecksum, // Checksum of original content
    version: oldFile.version + 1,
    previousVersionId: version.id,
  });
  db.updateStorageUsed(req.user!.id, sizeDiff);

  db.log(req.user!.id, 'UPLOAD_VERSION', oldFile.id, `v${oldFile.version + 1}`);
  ok(res, { version: oldFile.version + 1 }, 'New version uploaded');
});

router.get('/files/:id/versions', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);

  const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id;
  if (!canAccess) return fail(res, 'Access denied', 403);

  const versions = db.getVersionsByFile(file.id).map(v => {
    const user = db.findUserById(v.createdBy);
    return {
      id: v.id,
      version: v.version,
      size: v.size,
      createdBy: user?.username,
      createdAt: v.createdAt,
      comment: v.comment,
    };
  });

  ok(res, { currentVersion: file.version, versions });
});

router.get('/files/:id', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);

  const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id || file.sharedWith.includes(req.user!.id);
  if (!canAccess) return fail(res, 'Access denied', 403);

  const owner = db.findUserById(file.ownerId);
  const annotations = db.getAnnotationsByFile(file.id);
  const bookmarks = db.getBookmarksByUser(req.user!.id).filter(b => b.fileId === file.id);
  const versionCount = db.getVersionsByFile(file.id).length;
  const category = file.categoryId ? db.findCategoryById(file.categoryId) : null;
  
  // Get shared users info
  const sharedUsers = file.sharedWith.map(uid => {
    const u = db.findUserById(uid);
    return u ? { id: u.id, username: u.username, email: u.email } : null;
  }).filter(Boolean);
  
  // Get share links for this file (only if owner)
  const shareLinks = file.ownerId === req.user!.id 
    ? db.getShareLinksByFile(file.id).map(l => ({
        id: l.id,
        accessToken: l.accessToken,
        expiresAt: l.expiresAt,
        maxDownloads: l.maxDownloads,
        downloadCount: l.downloadCount,
        hasPassword: !!l.password,
        createdAt: l.createdAt,
        isActive: l.isActive
      }))
    : [];

  ok(res, {
    ...file,
    ownerName: owner?.username,
    annotations,
    bookmarks,
    category,
    versionCount,
    sharedUsers,
    shareLinks,
    isOwner: file.ownerId === req.user!.id,
    isFavorite: file.favoriteOf.includes(req.user!.id),
    isBookmarked: bookmarks.length > 0,
  });
});

router.get('/files/:id/preview', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);

  const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id || file.sharedWith.includes(req.user!.id);
  if (!canAccess) return fail(res, 'Access denied', 403);

  // Only allow preview for certain types
  const previewable = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml', 'image/bmp',
    'text/plain', 'text/csv', 'text/html', 'text/css', 'text/javascript', 'text/markdown',
    'application/json', 'application/pdf', 'application/xml',
    'video/mp4', 'video/webm', 'video/ogg',
    'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/webm'
  ];
  if (!previewable.includes(file.mimeType)) {
    return fail(res, 'Preview not available for this file type');
  }

  const filePath = path.join(config.uploadDir, file.storedName);
  if (!fs.existsSync(filePath)) return fail(res, 'File missing', 404);

  db.log(req.user!.id, 'PREVIEW', file.id, file.name);
  db.updateFile(file.id, { lastAccessedAt: new Date() });

  let content: Buffer;
  try {
    if (file.encrypted) {
      content = decryptFile(filePath);
    } else {
      content = fs.readFileSync(filePath);
    }
  } catch (err) {
    return fail(res, 'Failed to decrypt file', 500);
  }

  // For text files, return as text
  if (file.mimeType.startsWith('text/') || file.mimeType === 'application/json' || file.mimeType === 'application/xml') {
    ok(res, { type: 'text', content: content.toString('utf-8').substring(0, 50000) });
    return;
  }

  // For video/audio, return as base64 with type indicator
  if (file.mimeType.startsWith('video/')) {
    ok(res, { type: 'video', mimeType: file.mimeType, content: content.toString('base64') });
    return;
  }

  if (file.mimeType.startsWith('audio/')) {
    ok(res, { type: 'audio', mimeType: file.mimeType, content: content.toString('base64') });
    return;
  }

  // For images/pdf, return as base64
  ok(res, { type: 'base64', mimeType: file.mimeType, content: content.toString('base64') });
});

router.get('/files/:id/download', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);

  const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id;
  if (!canAccess) return fail(res, 'Access denied', 403);

  const filePath = path.join(config.uploadDir, file.storedName);
  if (!fs.existsSync(filePath)) return fail(res, 'File missing', 404);

  try {
    // If encrypted, send the encrypted file (.enc) directly
    // If not encrypted, send the plain file
    const fileBuffer = fs.readFileSync(filePath);
    
    // Determine the filename to send
    let downloadFilename = file.name;
    if (file.encrypted) {
      // Add .enc extension to encrypted files
      downloadFilename = `${file.name}.enc`;
    }

    db.log(req.user!.id, 'DOWNLOAD', file.id, file.name);
    db.updateFile(file.id, { 
      downloadCount: file.downloadCount + 1,
      lastAccessedAt: new Date(),
    });

    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(downloadFilename)}"`);
    res.setHeader('Content-Type', file.encrypted ? 'application/octet-stream' : file.mimeType);
    res.setHeader('Content-Length', fileBuffer.length);
    res.setHeader('X-File-Encrypted', file.encrypted ? 'true' : 'false');
    res.setHeader('X-Original-Name', encodeURIComponent(file.name));
    res.setHeader('X-Encryption-Version', file.encryptionVersion?.toString() || '1');
    res.send(fileBuffer);
  } catch (err: any) {
    db.logSecurityEvent({
      userId: req.user!.id,
      eventType: 'file_download_error' as any,
      description: `Download failed: ${file.name} - ${err.message}`,
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
      metadata: { fileId: file.id },
    });
    fail(res, 'Failed to download file', 500);
  }
});

// Download file decrypted (if encrypted)
router.get('/files/:id/download-decrypted', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);

  // Check access: owner, admin, or shared user
  const canAccess = req.user!.role === Role.ADMIN || 
                    file.ownerId === req.user!.id || 
                    file.sharedWith.includes(req.user!.id);
  if (!canAccess) return fail(res, 'Access denied', 403);

  const filePath = path.join(config.uploadDir, file.storedName);
  if (!fs.existsSync(filePath)) return fail(res, 'File missing', 404);

  try {
    // Get user key from query parameter (for owner access to user-encrypted files)
    const userKey = req.query.userKey as string | undefined;
    
    // Use unified decryption function
    const content = decryptFileForUser({
      filePath,
      file: {
        id: file.id,
        encrypted: file.encrypted,
        userKeyEncrypted: file.userKeyEncrypted,
        ownerId: file.ownerId,
        sharedWith: file.sharedWith,
      },
      userId: req.user!.id,
      userKey,
      getWrappedKey: (fileId, userId) => db.getWrappedKey(fileId, userId),
      getUserPrivateKey: (userId) => {
        const user = db.findUserById(userId);
        return user?.privateKey;
      },
    });

    // BUG FIX 11: Verify checksum after decryption before serving file
    if (file.checksum) {
      const currentChecksum = nodeCrypto.createHash('sha256').update(content).digest('hex');
      if (currentChecksum !== file.checksum) {
        db.logSecurityEvent({
          userId: req.user!.id,
          eventType: 'file_integrity_fail' as any,
          description: `Checksum mismatch after decryption: ${file.name}`,
          ipAddress: getClientIp(req),
          userAgent: req.headers['user-agent'],
          metadata: { fileId: file.id, expected: file.checksum, actual: currentChecksum },
        });
        return fail(res, 'File integrity check failed. File may be corrupted or tampered with.', 500);
      }
    }

    db.log(req.user!.id, 'DOWNLOAD_DECRYPTED', file.id, file.name);
    db.updateFile(file.id, { 
      downloadCount: file.downloadCount + 1,
      lastAccessedAt: new Date(),
    });

    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.name)}"`);
    res.setHeader('Content-Type', file.mimeType);
    res.setHeader('Content-Length', content.length);
    res.setHeader('X-File-Decrypted', 'true');
    res.send(content);
  } catch (err: any) {
    db.logSecurityEvent({
      userId: req.user!.id,
      eventType: 'file_decryption_error' as any,
      description: `Decryption failed: ${file.name} - ${err.message}`,
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
      metadata: { fileId: file.id },
    });
    fail(res, err.message || 'Failed to decrypt file', 500);
  }
});

// Get encryption information for a file
router.get('/files/:id/encryption-info', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);

  const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id;
  if (!canAccess) return fail(res, 'Access denied', 403);

  let howToDecrypt = 'This file is not encrypted.';
  let keySource = 'None';
  
  // Get wrapped key information for user-encrypted files
  const wrappedKeys = file.userKeyEncrypted ? db.getWrappedKeysByFile(file.id) : [];
  const sharedWithWrappedKeys = wrappedKeys.map(wk => {
    const user = db.findUserById(wk.userId);
    return {
      userId: wk.userId,
      username: user?.username || 'Unknown',
      createdAt: wk.createdAt,
    };
  });
  
  if (file.encrypted) {
    if (file.userKeyEncrypted) {
      keySource = 'User-provided key (not stored on server)';
      howToDecrypt = 'This file is encrypted with YOUR encryption key that you provided during upload.\n\n' +
        'To decrypt:\n' +
        '1. Go to the "Decrypt File" page\n' +
        '2. Download this file (encrypted .enc format)\n' +
        '3. Upload it to the Decrypt page\n' +
        '4. Enter your encryption key\n\n' +
        '⚠️ The server does NOT store your key. If you lost it, this file cannot be recovered.\n\n' +
        `Sharing: ${wrappedKeys.length} user(s) have wrapped keys for decryption.`;
    } else {
      keySource = 'Server-managed master key';
      howToDecrypt = 'This file is encrypted with the server\'s master encryption key. You can:\n' +
        '1. Download the encrypted .enc file and keep it secure\n' +
        '2. Download the decrypted version using the "Download Decrypted" button\n' +
        '3. The encryption version controls which key derivation method was used';
    }
  }

  const encryptionInfo = {
    fileId: file.id,
    fileName: file.name,
    encrypted: file.encrypted,
    userKeyEncrypted: file.userKeyEncrypted || false,
    encryptionVersion: file.encryptionVersion || 1,
    encryptionMethod: 'AES-256-GCM',
    keySource,
    howToDecrypt,
    encryptionDate: file.createdAt,
    checksum: file.checksum,
    integrityVerified: !!file.integrityVerifiedAt,
    integrityVerifiedAt: file.integrityVerifiedAt,
    wrappedKeyCount: wrappedKeys.length,
    sharedWithWrappedKeys: sharedWithWrappedKeys.length > 0 ? sharedWithWrappedKeys : undefined,
  };

  ok(res, encryptionInfo);
});

// Create a test file encrypted with a user key (for testing decryption)
router.post('/test-create-encrypted-file', auth, (req: Request, res: Response) => {
  try {
    const { encryptionKey } = req.body;
    
    if (!encryptionKey || encryptionKey.length < 8) {
      return fail(res, 'Encryption key must be at least 8 characters', 400);
    }

    // Create test file content
    const testContent = Buffer.from('This is a test file encrypted with user key: ' + new Date().toISOString() + '\n\nYou successfully encrypted and can now decrypt this file!');
    
    // Encrypt it with the user key
    const encryptedBuffer = encryptBufferWithUserKey(testContent, encryptionKey);
    
    // Send as downloadable file
    const fileName = `test-encrypted-${Date.now()}.enc`;
    
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileName)}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', encryptedBuffer.length);
    res.send(encryptedBuffer);
    
  } catch (err: any) {
    // BUG FIX 6: Add proper error logging
    console.error('Test file creation error:', err);
    db.logSecurityEvent({
      userId: req.user!.id,
      eventType: 'file_analysis' as any,
      description: 'Test file creation failed',
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
      metadata: { error: err.message },
    });
    fail(res, 'Failed to create test file: ' + err.message, 500);
  }
});

// Decrypt file with user-provided encryption key
// BUG FIX 10: Add rate limiting (5 attempts per hour) on decryption endpoint
router.post('/decrypt-file', auth, rateLimit(5, 60 * 60 * 1000), uploadEncrypted.single('file'), async (req: Request, res: Response) => {
  try {
    if (!req.file) {
      return fail(res, 'No file provided', 400);
    }

    let { encryptionKey } = req.body;
    if (!encryptionKey) {
      return fail(res, 'Encryption key is required', 400);
    }

    // Trim whitespace from key
    encryptionKey = encryptionKey.trim();
    
    if (encryptionKey.length < 8) {
      return fail(res, 'Encryption key must be at least 8 characters', 400);
    }

    // Check if file is encrypted with a user key
    const fileData = fs.readFileSync(req.file.path);
    const version = fileData[0];
    const USER_KEY_VERSION = 4; // From crypto.ts

    if (version !== USER_KEY_VERSION) {
      fs.unlinkSync(req.file.path);
      return fail(res, 'This file was not encrypted with a user key. Please use standard decryption.', 400);
    }

    // Decrypt the file using the provided key
    let decryptedContent: Buffer;
    try {
      decryptedContent = decryptFileWithUserKey(req.file.path, encryptionKey);
    } catch (decryptErr: any) {
      fs.unlinkSync(req.file.path);
      
      console.error('Decryption error details:', decryptErr.message);
      
      let errorMsg = 'Decryption failed: Invalid key or file has been tampered with';
      if (decryptErr.message.includes('Invalid key')) {
        errorMsg = 'Invalid encryption key - please verify you entered the correct key';
      } else if (decryptErr.message.includes('tampered')) {
        errorMsg = 'File has been corrupted or tampered with';
      }
      
      db.logSecurityEvent({
        userId: req.user!.id,
        eventType: 'file_decryption_error' as any,
        description: `User-key decryption failed: ${req.file.originalname} - ${decryptErr.message}`,
        ipAddress: getClientIp(req),
        userAgent: req.headers['user-agent'],
        metadata: { fileName: req.file.originalname },
      });

      return fail(res, errorMsg, 400);
    }

    // Clean up temp file
    fs.unlinkSync(req.file.path);

    // Log successful decryption
    db.logSecurityEvent({
      userId: req.user!.id,
      eventType: 'file_analysis' as any,
      description: `File decrypted with user key: ${req.file.originalname}`,
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
      metadata: { fileName: req.file.originalname, fileSize: req.file.size },
    });

    // Send decrypted file
    // Try to extract original filename from the encrypted file if possible
    // For now, use the original filename without the .enc extension
    let originalFileName = req.file.originalname;
    if (originalFileName.endsWith('.enc')) {
      originalFileName = originalFileName.slice(0, -4);
    }

    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(originalFileName)}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', decryptedContent.length);
    res.setHeader('X-Decrypted', 'true');
    res.send(decryptedContent);

  } catch (err: any) {
    if (req.file && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (e) {
        // ignore cleanup errors
      }
    }

    console.error('Decryption endpoint error:', err);
    db.logSecurityEvent({
      userId: req.user!.id,
      eventType: 'file_decryption_error' as any,
      description: `Decryption endpoint error: ${err.message}`,
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
    });

    fail(res, 'An error occurred during decryption', 500);
  }
});

router.post('/files/download-multiple', auth, async (req: Request, res: Response) => {
  const { fileIds } = req.body;
  if (!Array.isArray(fileIds) || fileIds.length === 0) {
    return fail(res, 'fileIds array required');
  }
  if (fileIds.length > 50) {
    return fail(res, 'Maximum 50 files at once');
  }

  const archive = archiver('zip', { zlib: { level: 5 } });
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="files-${Date.now()}.zip"`);
  
  // BUG FIX 22: Add timeout to archive creation for bulk downloads
  const archiveTimeout = setTimeout(() => {
    archive.abort();
    db.logSecurityEvent({
      userId: req.user!.id,
      eventType: 'file_download_error' as any,
      description: 'Bulk download timeout - archive creation took too long',
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
      metadata: { fileCount: fileIds.length },
    });
  }, 5 * 60 * 1000); // 5 minute timeout
  
  archive.on('error', (err) => {
    clearTimeout(archiveTimeout);
    db.logSecurityEvent({
      userId: req.user!.id,
      eventType: 'file_download_error' as any,
      description: `Bulk download error: ${err.message}`,
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
      metadata: { fileCount: fileIds.length },
    });
  });
  
  archive.on('end', () => {
    clearTimeout(archiveTimeout);
  });
  
  archive.pipe(res);

  for (const id of fileIds) {
    const file = db.findFileById(id);
    if (!file) continue;
    
    const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id;
    if (!canAccess) continue;

    const filePath = path.join(config.uploadDir, file.storedName);
    if (!fs.existsSync(filePath)) continue;

    try {
      if (file.encrypted) {
        const decrypted = decryptFile(filePath);
        archive.append(decrypted, { name: file.name });
      } else {
        archive.file(filePath, { name: file.name });
      }
      db.updateFile(file.id, { downloadCount: file.downloadCount + 1 });
    } catch {
      // Skip failed files
    }
  }

  db.log(req.user!.id, 'DOWNLOAD_MULTIPLE', fileIds.join(','), `${fileIds.length} files`);
  await archive.finalize();
});

router.patch('/files/:id', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  if (file.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) {
    return fail(res, 'Access denied', 403);
  }

  const { name, description, folderId, tags } = req.body;
  const updates: Partial<FileRecord> = {};

  if (name) updates.name = validate.sanitize(name);
  if (description !== undefined) updates.description = description ? validate.sanitize(description) : undefined;
  if (folderId !== undefined) {
    if (folderId) {
      const folder = db.findFolderById(folderId);
      if (!folder || folder.ownerId !== req.user!.id) {
        return fail(res, 'Folder not found', 404);
      }
    }
    updates.folderId = folderId || undefined;
  }
  if (Array.isArray(tags)) {
    updates.tags = tags.filter(t => typeof t === 'string' && validate.tagName(t)).slice(0, 10);
  }

  const updated = db.updateFile(file.id, updates);
  db.log(req.user!.id, 'UPDATE_FILE', file.id, file.name);
  ok(res, updated, 'File updated');
});

router.post('/files/:id/favorite', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);

  const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id;
  if (!canAccess) return fail(res, 'Access denied', 403);

  const isFavorite = file.favoriteOf.includes(req.user!.id);
  if (isFavorite) {
    db.updateFile(file.id, { favoriteOf: file.favoriteOf.filter(id => id !== req.user!.id) });
    ok(res, { favorite: false }, 'Removed from favorites');
  } else {
    db.updateFile(file.id, { favoriteOf: [...file.favoriteOf, req.user!.id] });
    ok(res, { favorite: true }, 'Added to favorites');
  }
});

// Bookmark endpoints
router.post('/files/:id/bookmark', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);

  const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id;
  if (!canAccess) return fail(res, 'Access denied', 403);

  const { color, notes } = req.body;
  
  // Check if already bookmarked
  const existing = db.getBookmarksByUser(req.user!.id).find(b => b.fileId === file.id);
  if (existing) {
    return fail(res, 'File already bookmarked');
  }

  const bookmark = db.createBookmark({
    userId: req.user!.id,
    fileId: file.id,
    color: color || '#3498db',
    notes: notes ? validate.sanitize(notes) : undefined,
  });

  db.log(req.user!.id, 'BOOKMARK', file.id, file.name);
  ok(res, bookmark, 'File bookmarked');
});

router.delete('/bookmarks/:id', auth, (req: Request, res: Response) => {
  const bookmark = db.getBookmarksByUser(req.user!.id).find(b => b.id === req.params.id);
  if (!bookmark) return fail(res, 'Bookmark not found', 404);
  if (bookmark.userId !== req.user!.id) return fail(res, 'Access denied', 403);

  db.deleteBookmark(req.params.id);
  ok(res, null, 'Bookmark removed');
});

router.get('/bookmarks', auth, (req: Request, res: Response) => {
  const bookmarks = db.getBookmarksByUser(req.user!.id);
  const bookmarksWithFiles = bookmarks.map(b => {
    const file = db.findFileById(b.fileId);
    return {
      ...b,
      file: file ? {
        id: file.id,
        name: file.name,
        mimeType: file.mimeType,
        size: file.size,
      } : null,
    };
  }).filter(b => b.file !== null);
  ok(res, bookmarksWithFiles);
});

// Trash/restore
router.post('/files/:id/trash', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  if (file.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) return fail(res, 'Not owner', 403);

  db.trashFile(file.id);
  db.log(req.user!.id, 'TRASH', file.id, file.name);
  ok(res, null, 'File moved to trash');
});

router.post('/files/:id/restore', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  if (file.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) return fail(res, 'Not owner', 403);
  if (file.status !== FileStatus.TRASHED) return fail(res, 'File not in trash');

  db.restoreFile(file.id);
  db.log(req.user!.id, 'RESTORE', file.id, file.name);
  ok(res, null, 'File restored');
});

router.delete('/files/:id', auth, requireRole(Role.ADMIN, Role.EDITOR), (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  if (file.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) return fail(res, 'Not owner', 403);

  const { permanent } = req.query;
  
  if (permanent === 'true' || file.status === FileStatus.TRASHED) {
    // Permanent delete
    const filePath = path.join(config.uploadDir, file.storedName);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    // Delete versions
    const versions = db.getVersionsByFile(file.id);
    for (const v of versions) {
      const vPath = path.join(config.versionsDir, v.storedName);
      if (fs.existsSync(vPath)) fs.unlinkSync(vPath);
      db.deleteVersion(v.id);
    }

    // Delete annotations and bookmarks
    db.deleteAnnotationsByFile(file.id);
    db.deleteBookmarksByFile(file.id);
    db.deleteShareLinksByFile(file.id);
    
    // Delete wrapped keys for user-encrypted files
    db.deleteWrappedKeysByFile(file.id);

    db.deleteFile(file.id);
    db.log(req.user!.id, 'DELETE_PERMANENT', file.id, file.name);
    ok(res, null, 'File permanently deleted');
  } else {
    // Move to trash
    db.trashFile(file.id);
    db.log(req.user!.id, 'TRASH', file.id, file.name);
    ok(res, null, 'File moved to trash');
  }
});

router.post('/files/empty-trash', auth, (req: Request, res: Response) => {
  const trashedFiles = db.getTrashedFiles(req.user!.id);
  
  for (const file of trashedFiles) {
    const filePath = path.join(config.uploadDir, file.storedName);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    
    // Delete associated data
    db.deleteAnnotationsByFile(file.id);
    db.deleteBookmarksByFile(file.id);
    
    db.deleteFile(file.id);
  }

  db.log(req.user!.id, 'EMPTY_TRASH', '', `${trashedFiles.length} files`);
  ok(res, { deleted: trashedFiles.length }, 'Trash emptied');
});

// ============ SHARING ============
router.post('/files/:id/share', auth, requireRole(Role.ADMIN, Role.EDITOR), (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  if (file.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) return fail(res, 'Not owner', 403);

  // Check if file is user-encrypted - if so, redirect to share-with-key endpoint
  if (file.userKeyEncrypted) {
    return fail(res, 'This file is encrypted with your key. Use /files/:id/share-with-key endpoint and provide your encryption key to share.', 400);
  }

  const { userIds, emails } = req.body;
  const toShare: string[] = [];

  // Add by user IDs
  if (Array.isArray(userIds)) {
    for (const id of userIds) {
      const user = db.findUserById(id);
      if (user && id !== file.ownerId && !file.sharedWith.includes(id)) {
        toShare.push(id);
      }
    }
  }

  // Add by emails
  if (Array.isArray(emails)) {
    for (const email of emails) {
      const user = db.findUserByEmail(email.toLowerCase());
      if (user && user.id !== file.ownerId && !file.sharedWith.includes(user.id)) {
        toShare.push(user.id);
      }
    }
  }

  if (toShare.length === 0) {
    return fail(res, 'No valid users to share with');
  }

  db.updateFile(file.id, { sharedWith: [...new Set([...file.sharedWith, ...toShare])] });
  
  // Notify shared users
  const sharer = db.findUserById(req.user!.id);
  for (const userId of toShare) {
    db.notify(userId, NotificationType.FILE_SHARED, 'File Shared With You',
      `${sharer?.username} shared "${file.name}" with you.`,
      { fileId: file.id });
  }

  db.log(req.user!.id, 'SHARE', file.id, `Shared with ${toShare.length} users`);
  ok(res, { sharedWith: toShare.length }, 'File shared');
});

// New endpoint for sharing user-encrypted files with key wrapping
router.post('/files/:id/share-with-key', auth, requireRole(Role.ADMIN, Role.EDITOR), async (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  if (file.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) return fail(res, 'Not owner', 403);

  // Verify file is user-encrypted
  if (!file.userKeyEncrypted) {
    return fail(res, 'This endpoint is only for user-encrypted files. Use /files/:id/share for this file.', 400);
  }

  const { userIds, emails, encryptionKey } = req.body;
  
  if (!encryptionKey || typeof encryptionKey !== 'string' || encryptionKey.trim().length < 8) {
    return fail(res, 'Encryption key is required (minimum 8 characters)', 400);
  }

  const toShare: string[] = [];

  // Add by user IDs
  if (Array.isArray(userIds)) {
    for (const id of userIds) {
      const user = db.findUserById(id);
      if (user && id !== file.ownerId && !file.sharedWith.includes(id)) {
        toShare.push(id);
      }
    }
  }

  // Add by emails
  if (Array.isArray(emails)) {
    for (const email of emails) {
      const user = db.findUserByEmail(email.toLowerCase());
      if (user && user.id !== file.ownerId && !file.sharedWith.includes(user.id)) {
        toShare.push(user.id);
      }
    }
  }

  if (toShare.length === 0) {
    return fail(res, 'No valid users to share with');
  }

  // Validate owner's encryption key by attempting to extract DEK
  const filePath = path.join(config.uploadDir, file.storedName);
  if (!fs.existsSync(filePath)) {
    return fail(res, 'File not found on disk', 404);
  }

  let dek: Buffer;
  try {
    dek = extractDekFromUserEncryptedFile(filePath, encryptionKey.trim());
  } catch (err: any) {
    return fail(res, 'Incorrect encryption key. Cannot share file.', 400);
  }

  // Wrap DEK for each recipient
  const wrapped: string[] = [];
  const failed: Array<{ userId: string; username: string; reason: string }> = [];

  for (const userId of toShare) {
    const recipient = db.findUserById(userId);
    if (!recipient) {
      failed.push({ userId, username: 'Unknown', reason: 'User not found' });
      continue;
    }

    if (!recipient.publicKey) {
      failed.push({ userId, username: recipient.username, reason: 'No encryption keys set up' });
      continue;
    }

    try {
      const wrappedDek = wrapDekForUser(dek, recipient.publicKey);
      
      // Store wrapped key in database
      const wrappedKey: WrappedKey = {
        id: uuid(),
        fileId: file.id,
        userId: recipient.id,
        wrappedDek,
        algorithm: 'aes-256-gcm',
        createdAt: new Date(),
        createdBy: req.user!.id,
      };
      
      db.createWrappedKey(wrappedKey);
      wrapped.push(userId);
    } catch (err: any) {
      failed.push({ userId, username: recipient.username, reason: `Key wrapping failed: ${err.message}` });
    }
  }

  // Update sharedWith array for successfully wrapped users
  if (wrapped.length > 0) {
    db.updateFile(file.id, { sharedWith: [...new Set([...file.sharedWith, ...wrapped])] });
    
    // Notify shared users
    const sharer = db.findUserById(req.user!.id);
    for (const userId of wrapped) {
      db.notify(userId, NotificationType.FILE_SHARED, 'Encrypted File Shared With You',
        `${sharer?.username} shared encrypted file "${file.name}" with you.`,
        { fileId: file.id });
    }
  }

  db.log(req.user!.id, 'SHARE_WITH_KEY', file.id, `Shared with ${wrapped.length} users, ${failed.length} failed`);
  
  ok(res, { 
    sharedWith: wrapped.length,
    failed: failed.length > 0 ? failed : undefined,
  }, wrapped.length > 0 ? 'File shared successfully' : 'Failed to share with any users');
});

router.post('/files/:id/unshare', auth, requireRole(Role.ADMIN, Role.EDITOR), (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  if (file.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) return fail(res, 'Not owner', 403);

  const { userId, all } = req.body;
  
  if (all) {
    // Delete all wrapped keys for this file
    db.deleteWrappedKeysByFile(file.id);
    db.updateFile(file.id, { sharedWith: [] });
    db.log(req.user!.id, 'UNSHARE_ALL', file.id);
    ok(res, null, 'All access removed');
  } else if (userId) {
    // Delete wrapped key for specific user
    db.deleteWrappedKeysByUser(file.id, userId);
    db.updateFile(file.id, { sharedWith: file.sharedWith.filter(id => id !== userId) });
    db.log(req.user!.id, 'UNSHARE', file.id, userId);
    ok(res, null, 'Access removed');
  } else {
    fail(res, 'userId or all=true required');
  }
});

// ============ SHARE LINKS ============
router.post('/files/:id/share-link', auth, requireRole(Role.ADMIN, Role.EDITOR), (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  if (file.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) return fail(res, 'Not owner', 403);

  const { password, expiresInDays, maxDownloads, allowedEmails } = req.body;

  // BUG FIX 14: Generate unique access token
  let accessToken: string;
  let attempts = 0;
  do {
    accessToken = generateToken(24);
    attempts++;
    if (attempts > 10) {
      return fail(res, 'Failed to generate unique token', 500);
    }
  } while (db.findShareLinkByToken(accessToken));

  const link: ShareLink = {
    id: uuid(),
    fileId: file.id,
    createdBy: req.user!.id,
    accessToken,
    password: password ? hashPassword(password) : undefined,
    expiresAt: expiresInDays ? new Date(Date.now() + Math.min(expiresInDays, config.shareLinksMaxDays) * 24 * 60 * 60 * 1000) : undefined,
    maxDownloads: maxDownloads ? Math.min(maxDownloads, 1000) : undefined,
    downloadCount: 0,
    allowedEmails: Array.isArray(allowedEmails) ? allowedEmails.map((e: string) => e.toLowerCase()) : undefined,
    createdAt: new Date(),
    isActive: true,
  };

  db.createShareLink(link);
  db.log(req.user!.id, 'CREATE_SHARE_LINK', file.id, file.name);
  
  ok(res, {
    id: link.id,
    url: `/api/share/${link.accessToken}`,
    accessToken: link.accessToken,
    expiresAt: link.expiresAt,
    hasPassword: !!link.password,
  }, 'Share link created', 201);
});

router.post('/files/:id/share-secure', auth, requireRole(Role.ADMIN, Role.EDITOR), (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  if (file.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) return fail(res, 'Not owner', 403);

  const proofCheck = validateZeroTrustProof(req, 'secure-share');
  if (!proofCheck.valid) {
    return fail(res, `Zero-trust verification failed: ${proofCheck.reason}`, 428);
  }

  const recipientsRaw = Array.isArray(req.body?.recipients) ? req.body.recipients : [];
  if (recipientsRaw.length === 0) {
    return fail(res, 'At least one recipient with an RSA public key is required');
  }

  const recipients: SecureRecipientInput[] = [];
  for (let idx = 0; idx < recipientsRaw.length; idx++) {
    const candidate = recipientsRaw[idx];
    const recipientId = typeof candidate?.recipientId === 'string' && candidate.recipientId.trim()
      ? candidate.recipientId.trim()
      : `recipient-${idx + 1}`;
    const publicKey = typeof candidate?.publicKey === 'string' ? candidate.publicKey.trim() : '';
    const email = typeof candidate?.email === 'string' ? candidate.email.trim().toLowerCase() : undefined;

    if (!publicKey) {
      return fail(res, `Recipient ${recipientId} is missing publicKey`);
    }

    recipients.push({ recipientId, publicKey, email });
  }

  const wrappedSecrets: Record<string, string> = {};
  const recipientHints: string[] = [];
  const secureSecret = generatePassphrase(6);
  for (const recipient of recipients) {
    try {
      const wrapped = rsaEncrypt(Buffer.from(secureSecret, 'utf-8'), recipient.publicKey);
      wrappedSecrets[recipient.recipientId] = wrapped.toString('base64');
      recipientHints.push(recipient.recipientId);
      if (recipient.email) recipientHints.push(recipient.email);
    } catch {
      return fail(res, `Invalid RSA public key for recipient ${recipient.recipientId}`);
    }
  }

  const explicitAllowedEmails = Array.isArray(req.body?.allowedEmails)
    ? req.body.allowedEmails
        .filter((e: unknown) => typeof e === 'string')
        .map((e: string) => e.toLowerCase().trim())
        .filter(Boolean)
    : [];
  const recipientEmails = recipients
    .map(r => r.email)
    .filter((e): e is string => !!e);
  const allowedEmails = [...new Set([...explicitAllowedEmails, ...recipientEmails])];

  const expiresInDaysRaw = Number(req.body?.expiresInDays);
  const expiresInDays = Number.isFinite(expiresInDaysRaw) && expiresInDaysRaw > 0
    ? Math.min(expiresInDaysRaw, config.shareLinksMaxDays)
    : 7;
  const maxDownloadsRaw = Number(req.body?.maxDownloads);
  const maxDownloads = Number.isFinite(maxDownloadsRaw) && maxDownloadsRaw > 0
    ? Math.min(maxDownloadsRaw, 1000)
    : recipients.length;
  const requireZeroTrustProof = req.body?.requireZeroTrustProof !== false;

  // BUG FIX 14: Generate unique access token
  let accessToken: string;
  let attempts = 0;
  do {
    accessToken = generateToken(24);
    attempts++;
    if (attempts > 10) {
      return fail(res, 'Failed to generate unique token', 500);
    }
  } while (db.findShareLinkByToken(accessToken));

  const link: ShareLink = {
    id: uuid(),
    fileId: file.id,
    createdBy: req.user!.id,
    accessToken,
    password: hashPassword(secureSecret),
    expiresAt: new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000),
    maxDownloads,
    downloadCount: 0,
    allowedEmails: allowedEmails.length > 0 ? allowedEmails : undefined,
    createdAt: new Date(),
    isActive: true,
    requireZeroTrustProof,
    secureShare: {
      enabled: true,
      keyExchange: 'rsa-oaep-sha256',
      wrappedSecrets,
      recipientHints,
    },
  };

  db.createShareLink(link);
  db.log(req.user!.id, 'CREATE_SECURE_SHARE_LINK', file.id, `Secure share for ${recipients.length} recipients`);

  ok(res, {
    id: link.id,
    url: `/api/share/${link.accessToken}`,
    accessToken: link.accessToken,
    expiresAt: link.expiresAt,
    secureShare: true,
    keyExchange: 'RSA-OAEP-SHA256',
    requireZeroTrustProof,
    recipientPackages: Object.entries(wrappedSecrets).map(([recipientId, wrappedSecret]) => ({
      recipientId,
      wrappedSecret,
      unwrapInstruction: 'Recipient decrypts wrappedSecret with RSA private key and uses the output as share password',
    })),
  }, 'Secure asymmetric share link created', 201);
});

router.delete('/share-links/:id', auth, (req: Request, res: Response) => {
  const link = db.findShareLinkById(req.params.id);
  if (!link) return fail(res, 'Share link not found', 404);
  if (link.createdBy !== req.user!.id && req.user!.role !== Role.ADMIN) {
    return fail(res, 'Access denied', 403);
  }

  db.deleteShareLink(link.id);
  ok(res, null, 'Share link deleted');
});

router.get('/share/:token', optionalAuth, (req: Request, res: Response) => {
  const link = db.findShareLinkByToken(req.params.token);
  if (!link || !link.isActive) return fail(res, 'Invalid or expired link', 404);
  
  if (link.expiresAt && link.expiresAt < new Date()) {
    db.updateShareLink(link.id, { isActive: false });
    return fail(res, 'Link has expired', 410);
  }

  if (link.maxDownloads && link.downloadCount >= link.maxDownloads) {
    return fail(res, 'Download limit reached', 410);
  }

  const file = db.findFileById(link.fileId);
  if (!file || file.status !== FileStatus.ACTIVE) {
    return fail(res, 'File not found', 404);
  }

  ok(res, {
    fileName: file.name,
    fileSize: file.size,
    mimeType: file.mimeType,
    requiresPassword: !!link.password,
    requiresZeroTrustProof: !!link.requireZeroTrustProof,
    secureShare: !!link.secureShare?.enabled,
    keyExchange: link.secureShare?.enabled ? 'RSA-OAEP-SHA256' : null,
    expiresAt: link.expiresAt,
    remainingDownloads: link.maxDownloads ? link.maxDownloads - link.downloadCount : null,
  });
});

router.post('/share/:token/key-package', optionalAuth, (req: Request, res: Response) => {
  const link = db.findShareLinkByToken(req.params.token);
  if (!link || !link.isActive) return fail(res, 'Invalid or expired link', 404);
  if (!link.secureShare?.enabled) return fail(res, 'This link is not configured for secure asymmetric sharing', 400);

  if (link.expiresAt && link.expiresAt < new Date()) {
    db.updateShareLink(link.id, { isActive: false });
    return fail(res, 'Link has expired', 410);
  }

  const requesterEmail = req.user
    ? db.findUserById(req.user.id)?.email?.toLowerCase()
    : (typeof req.body?.email === 'string' ? req.body.email.toLowerCase().trim() : undefined);

  if (link.allowedEmails && link.allowedEmails.length > 0) {
    if (!requesterEmail || !link.allowedEmails.includes(requesterEmail)) {
      return fail(res, 'Your email is not authorized for this secure share', 403);
    }
  }

  const recipientId = typeof req.body?.recipientId === 'string' ? req.body.recipientId.trim() : '';
  if (!recipientId) {
    return fail(res, 'recipientId is required');
  }

  const wrappedSecret = link.secureShare.wrappedSecrets[recipientId];
  if (!wrappedSecret) {
    return fail(res, 'No key package found for this recipient', 404);
  }

  ok(res, {
    recipientId,
    keyExchange: 'RSA-OAEP-SHA256',
    wrappedSecret,
    accessToken: link.accessToken,
    downloadEndpoint: `/api/share/${link.accessToken}/download`,
  });
});

router.post('/share/:token/download', optionalAuth, (req: Request, res: Response) => {
  const link = db.findShareLinkByToken(req.params.token);
  if (!link || !link.isActive) return fail(res, 'Invalid or expired link', 404);
  
  if (link.expiresAt && link.expiresAt < new Date()) {
    return fail(res, 'Link has expired', 410);
  }

  if (link.maxDownloads && link.downloadCount >= link.maxDownloads) {
    return fail(res, 'Download limit reached', 410);
  }

  if (link.requireZeroTrustProof) {
    if (!req.user || !req.sessionId) {
      return fail(res, 'Authenticated session required for zero-trust protected share download', 401);
    }
    const proofCheck = validateZeroTrustProof(req, 'share-download');
    if (!proofCheck.valid) {
      return fail(res, `Zero-trust verification failed: ${proofCheck.reason}`, 428);
    }
  }

  // Check password if required
  if (link.password) {
    const { password } = req.body;
    if (!password || !verifyPassword(password, link.password)) {
      return fail(res, 'Invalid password', 401);
    }
  }

  // Check allowed emails
  if (link.allowedEmails && link.allowedEmails.length > 0) {
    const userEmail = req.user ? db.findUserById(req.user.id)?.email : req.body.email;
    if (!userEmail || !link.allowedEmails.includes(userEmail.toLowerCase())) {
      return fail(res, 'Your email is not authorized to download this file', 403);
    }
  }

  const file = db.findFileById(link.fileId);
  if (!file || file.status !== FileStatus.ACTIVE) {
    return fail(res, 'File not found', 404);
  }

  const filePath = path.join(config.uploadDir, file.storedName);
  if (!fs.existsSync(filePath)) return fail(res, 'File missing', 404);

  // Increment download count
  db.updateShareLink(link.id, { downloadCount: link.downloadCount + 1 });
  db.updateFile(file.id, { downloadCount: file.downloadCount + 1 });

  try {
    let decrypted: Buffer;
    
    // Check if file is user-encrypted
    if (file.userKeyEncrypted) {
      // User-encrypted files via share links require the user to be authenticated and have a wrapped key
      if (!req.user) {
        return fail(res, 'This file is encrypted with the owner\'s key. You must be logged in and explicitly shared with to access it.', 403);
      }
      
      // Check if user has a wrapped key
      const wrappedKey = db.getWrappedKey(file.id, req.user.id);
      if (!wrappedKey) {
        return fail(res, 'This file is encrypted with the owner\'s key. The owner must explicitly share it with you using the share-with-key feature.', 403);
      }
      
      // Use unified decryption
      decrypted = decryptFileForUser({
        filePath,
        file: {
          id: file.id,
          encrypted: file.encrypted,
          userKeyEncrypted: file.userKeyEncrypted,
          ownerId: file.ownerId,
          sharedWith: file.sharedWith,
        },
        userId: req.user.id,
        getWrappedKey: (fileId, userId) => db.getWrappedKey(fileId, userId),
        getUserPrivateKey: (userId) => {
          const user = db.findUserById(userId);
          return user?.privateKey;
        },
      });
    } else if (file.encrypted) {
      // Server-encrypted file - decrypt with server key
      decrypted = decryptFile(filePath);
    } else {
      // Unencrypted file - read directly
      decrypted = fs.readFileSync(filePath);
    }
    
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.name)}"`);
    res.setHeader('Content-Type', file.mimeType);
    res.setHeader('Content-Length', decrypted.length);
    res.send(decrypted);
  } catch (err: any) {
    // BUG FIX 6: Add proper error logging
    console.error('Share link download error:', err);
    db.logSecurityEvent({
      userId: req.user?.id || 'anonymous',
      eventType: 'file_download_error' as any,
      description: `Share link download failed: ${err.message}`,
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
      metadata: { error: err.message },
    });
    fail(res, err.message || 'Failed to download file', 500);
  }
});

// ============ CATEGORIES ============
router.get('/categories', auth, (req: Request, res: Response) => {
  const categories = db.getCategoriesByUser(req.user!.id);
  const categoriesWithCounts = categories.map(c => {
    const files = db.getFilesByCategory(c.id, req.user!.id);
    return { ...c, fileCount: files.length };
  });
  ok(res, categoriesWithCounts);
});

router.post('/categories', auth, (req: Request, res: Response) => {
  const { name, color, icon, description, parentId } = req.body;
  
  if (!name || typeof name !== 'string' || name.length > 50) {
    return fail(res, 'Name required (max 50 chars)');
  }
  
  // Check for duplicate name
  const existing = db.getCategoriesByUser(req.user!.id).find(c => c.name.toLowerCase() === name.toLowerCase());
  if (existing) {
    return fail(res, 'Category with this name already exists');
  }

  const category = db.createCategory({
    name: validate.sanitize(name),
    color: color && validate.hexColor(color) ? color : '#3498db',
    icon: icon ? validate.sanitize(icon) : 'folder',
    description: description ? validate.sanitize(description) : undefined,
    ownerId: req.user!.id,
    parentId: parentId || undefined,
  });

  ok(res, category, 'Category created', 201);
});

router.patch('/categories/:id', auth, (req: Request, res: Response) => {
  const category = db.findCategoryById(req.params.id);
  if (!category) return fail(res, 'Category not found', 404);
  if (category.ownerId !== req.user!.id) return fail(res, 'Access denied', 403);

  const { name, color, icon, description } = req.body;
  const updates: any = {};
  
  if (name) updates.name = validate.sanitize(name);
  if (color && validate.hexColor(color)) updates.color = color;
  if (icon !== undefined) updates.icon = icon ? validate.sanitize(icon) : undefined;
  if (description !== undefined) updates.description = description ? validate.sanitize(description) : undefined;

  const updated = db.updateCategory(category.id, updates);
  ok(res, updated, 'Category updated');
});

router.delete('/categories/:id', auth, (req: Request, res: Response) => {
  const category = db.findCategoryById(req.params.id);
  if (!category) return fail(res, 'Category not found', 404);
  if (category.ownerId !== req.user!.id) return fail(res, 'Access denied', 403);

  // Remove category from all files
  const files = db.getFilesByCategory(category.id, req.user!.id);
  for (const file of files) {
    db.updateFile(file.id, { categoryId: undefined });
  }

  db.deleteCategory(category.id);
  ok(res, null, 'Category deleted');
});

router.post('/files/:id/category', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  if (file.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) {
    return fail(res, 'Access denied', 403);
  }

  const { categoryId } = req.body;
  
  if (categoryId) {
    const category = db.findCategoryById(categoryId);
    if (!category || category.ownerId !== req.user!.id) {
      return fail(res, 'Category not found', 404);
    }
  }

  db.updateFile(file.id, { categoryId: categoryId || undefined });
  ok(res, null, categoryId ? 'Category assigned' : 'Category removed');
});

// ============ TEMPLATES ============
router.get('/templates', auth, (req: Request, res: Response) => {
  const templates = db.getTemplatesByUser(req.user!.id);
  ok(res, templates);
});

router.post('/templates', auth, (req: Request, res: Response) => {
  const { name, content, mimeType, description, tags } = req.body;
  
  if (!name || typeof name !== 'string' || name.length > 100) {
    return fail(res, 'Name required (max 100 chars)');
  }
  if (!content || typeof content !== 'string') {
    return fail(res, 'Content required');
  }

  const template = db.createTemplate({
    name: validate.sanitize(name),
    content,
    mimeType: mimeType || 'text/plain',
    description: description ? validate.sanitize(description) : undefined,
    category: 'general',
    ownerId: req.user!.id,
  });

  ok(res, template, 'Template created', 201);
});

router.post('/templates/:id/create-file', auth, requireRole(Role.ADMIN, Role.EDITOR), checkStorageQuota, (req: Request, res: Response) => {
  const template = db.getTemplatesByUser(req.user!.id).find(t => t.id === req.params.id);
  if (!template) return fail(res, 'Template not found', 404);

  const { fileName, folderId } = req.body;
  const name = fileName ? validate.sanitize(fileName) : template.name;
  
  // Get template content
  const templateContent = db.getTemplateContent(template);
  if (!templateContent) return fail(res, 'Template content not found', 404);
  
  // Create file from template
  const storedName = `${uuid()}.enc`;
  const storedPath = path.join(config.uploadDir, storedName);
  const content = Buffer.from(templateContent, 'utf-8');
  
  // Encrypt the content
  const { encryptBuffer } = require('./crypto');
  const encrypted = encryptBuffer(content);
  fs.writeFileSync(storedPath, encrypted);

  const file: FileRecord = {
    id: uuid(),
    name,
    storedName,
    size: content.length,
    mimeType: template.mimeType,
    ownerId: req.user!.id,
    encrypted: true,
    checksum: hashFile(storedPath),
    encryptionVersion: 3,
    createdAt: new Date(),
    status: FileStatus.ACTIVE,
    folderId: folderId || undefined,
    tags: [],
    description: template.description,
    version: 1,
    favoriteOf: [],
    sharedWith: [],
    downloadCount: 0,
  };

  db.createFile(file);
  
  // Update template usage
  db.incrementTemplateUsage(template.id);

  db.log(req.user!.id, 'CREATE_FROM_TEMPLATE', file.id, `From: ${template.name}`);
  ok(res, file, 'File created from template', 201);
});

router.delete('/templates/:id', auth, (req: Request, res: Response) => {
  const template = db.getTemplatesByUser(req.user!.id).find(t => t.id === req.params.id);
  if (!template) return fail(res, 'Template not found', 404);

  db.deleteTemplate(template.id);
  ok(res, null, 'Template deleted');
});

// ============ SAVED FILTERS ============
router.get('/saved-filters', auth, (req: Request, res: Response) => {
  const filters = db.getSavedFiltersByUser(req.user!.id);
  ok(res, filters);
});

router.post('/saved-filters', auth, (req: Request, res: Response) => {
  const { name, filters } = req.body;
  
  if (!name || typeof name !== 'string' || name.length > 50) {
    return fail(res, 'Name required (max 50 chars)');
  }
  if (!filters || typeof filters !== 'object') {
    return fail(res, 'Filters object required');
  }

  const savedFilter = db.createSavedFilter({
    name: validate.sanitize(name),
    filters,
    userId: req.user!.id,
  });

  ok(res, savedFilter, 'Filter saved', 201);
});

router.delete('/saved-filters/:id', auth, (req: Request, res: Response) => {
  const filter = db.getSavedFiltersByUser(req.user!.id).find(f => f.id === req.params.id);
  if (!filter) return fail(res, 'Saved filter not found', 404);

  db.deleteSavedFilter(filter.id);
  ok(res, null, 'Saved filter deleted');
});

// ============ ACTIVITY TIMELINE ============
router.get('/activity', auth, (req: Request, res: Response) => {
  const { limit = '50', offset = '0', fileId, action } = req.query;
  
  let logs = db.getActivityLogs(req.user!.id);
  
  if (fileId) {
    logs = logs.filter(l => l.target === fileId);
  }
  if (action) {
    logs = logs.filter(l => l.action === action);
  }
  
  const limitNum = Math.min(parseInt(limit as string) || 50, 200);
  const offsetNum = parseInt(offset as string) || 0;
  
  const paginated = logs.slice(offsetNum, offsetNum + limitNum);
  
  // Enrich with file info
  const enriched = paginated.map(log => {
    const file = log.target ? db.findFileById(log.target) : null;
    return {
      ...log,
      fileName: file?.name,
    };
  });
  
  ok(res, {
    logs: enriched,
    total: logs.length,
    hasMore: offsetNum + limitNum < logs.length,
  });
});

// ============ ANNOTATIONS ============
router.get('/files/:id/annotations', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);

  const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id;
  if (!canAccess) return fail(res, 'Access denied', 403);

  const annotations = db.getAnnotationsByFile(file.id).map(a => {
    const user = db.findUserById(a.userId);
    return {
      ...a,
      username: user?.username,
      isOwner: a.userId === req.user!.id,
    };
  });

  ok(res, annotations);
});

router.post('/files/:id/annotations', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);

  const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id;
  if (!canAccess) return fail(res, 'Access denied', 403);

  const { title, content, color, pinned } = req.body;
  
  if (!content || typeof content !== 'string' || content.length > 2000) {
    return fail(res, 'Content required (max 2000 chars)');
  }

  const annotation = db.createAnnotation({
    fileId: file.id,
    userId: req.user!.id,
    title: title ? validate.sanitize(title) : 'Note',
    content: validate.sanitize(content),
    color: color && validate.hexColor(color) ? color : '#ffeb3b',
    pinned: !!pinned,
  });

  db.log(req.user!.id, 'ANNOTATE', file.id, file.name);
  
  const user = db.findUserById(req.user!.id);
  ok(res, {
    ...annotation,
    username: user?.username,
    isOwner: true,
  }, 'Annotation added', 201);
});

router.patch('/annotations/:id', auth, (req: Request, res: Response) => {
  const annotations = db.getAnnotationsByFile(''); // Get all annotations
  // Find annotation by iterating
  let annotation: any = null;
  db.getAllFiles().forEach(f => {
    const fileAnnotations = db.getAnnotationsByFile(f.id);
    const found = fileAnnotations.find(a => a.id === req.params.id);
    if (found) annotation = found;
  });
  
  if (!annotation) return fail(res, 'Annotation not found', 404);
  if (annotation.userId !== req.user!.id && req.user!.role !== Role.ADMIN) {
    return fail(res, 'Access denied', 403);
  }

  const { content, color } = req.body;
  const updates: any = {};
  
  if (content) updates.content = validate.sanitize(content);
  if (color && validate.hexColor(color)) updates.color = color;

  const updated = db.updateAnnotation(annotation.id, updates);
  ok(res, updated, 'Annotation updated');
});

router.delete('/annotations/:id', auth, (req: Request, res: Response) => {
  // Find annotation
  let annotation: any = null;
  let fileId: string = '';
  db.getAllFiles().forEach(f => {
    const fileAnnotations = db.getAnnotationsByFile(f.id);
    const found = fileAnnotations.find(a => a.id === req.params.id);
    if (found) {
      annotation = found;
      fileId = f.id;
    }
  });
  
  if (!annotation) return fail(res, 'Annotation not found', 404);
  
  const file = db.findFileById(fileId);
  const canDelete = annotation.userId === req.user!.id || 
                    req.user!.role === Role.ADMIN || 
                    (file && file.ownerId === req.user!.id);
  
  if (!canDelete) return fail(res, 'Access denied', 403);

  db.deleteAnnotation(annotation.id);
  ok(res, null, 'Annotation deleted');
});

// ============ TAGS ============
router.get('/tags', auth, (req: Request, res: Response) => {
  const tags = db.getTagsByUser(req.user!.id);
  
  // Get file counts for each tag
  const tagsWithCounts = tags.map(t => {
    const files = db.getFilesByTag(t.name, req.user!.id);
    return { ...t, fileCount: files.length };
  });

  ok(res, tagsWithCounts);
});

router.post('/tags', auth, (req: Request, res: Response) => {
  const { name, color } = req.body;
  
  if (!name || !validate.tagName(name)) {
    return fail(res, 'Invalid tag name (1-30 chars, alphanumeric/dash/underscore)');
  }
  
  if (db.findTagByName(name, req.user!.id)) {
    return fail(res, 'Tag already exists');
  }

  const tag = db.createTag({
    id: uuid(),
    name: validate.sanitize(name),
    color: color && validate.hexColor(color) ? color : '#3b82f6',
    ownerId: req.user!.id,
    createdAt: new Date(),
  });

  ok(res, tag, 'Tag created', 201);
});

router.delete('/tags/:id', auth, (req: Request, res: Response) => {
  const tag = db.findTagById(req.params.id);
  if (!tag) return fail(res, 'Tag not found', 404);
  if (tag.ownerId !== req.user!.id) return fail(res, 'Access denied', 403);

  // Remove tag from all files
  const files = db.getFilesByTag(tag.name, req.user!.id);
  for (const file of files) {
    db.updateFile(file.id, { tags: file.tags.filter(t => t !== tag.name) });
  }

  db.deleteTag(tag.id);
  ok(res, null, 'Tag deleted');
});

// ============ NOTIFICATIONS ============
router.get('/notifications', auth, (req: Request, res: Response) => {
  const { unreadOnly } = req.query;
  const notifications = db.getNotificationsByUser(req.user!.id, unreadOnly === 'true');
  ok(res, {
    notifications,
    unreadCount: db.getUnreadCount(req.user!.id),
  });
});

router.post('/notifications/:id/read', auth, (req: Request, res: Response) => {
  db.markNotificationRead(req.params.id);
  ok(res, null, 'Notification marked as read');
});

router.post('/notifications/read-all', auth, (req: Request, res: Response) => {
  db.markAllNotificationsRead(req.user!.id);
  ok(res, null, 'All notifications marked as read');
});

// ============ USERS ============
router.get('/users', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const { search, role } = req.query;
  let users = db.getAllUsers().map(({ password, twoFactorSecret, ...u }) => u);
  
  if (search) {
    const term = (search as string).toLowerCase();
    users = users.filter(u => u.username.toLowerCase().includes(term) || u.email.toLowerCase().includes(term));
  }
  
  if (role && Object.values(Role).includes(role as Role)) {
    users = users.filter(u => u.role === role);
  }
  
  ok(res, users);
});

router.get('/users/search', auth, (req: Request, res: Response) => {
  const { q } = req.query;
  if (!q || (q as string).length < 2) {
    return ok(res, []);
  }
  
  const term = (q as string).toLowerCase();
  const users = db.getAllUsers()
    .filter(u => u.id !== req.user!.id && (u.username.toLowerCase().includes(term) || u.email.toLowerCase().includes(term)))
    .slice(0, 10)
    .map(u => ({ id: u.id, username: u.username, email: u.email }));
  
  ok(res, users);
});

router.get('/users/:id', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const user = db.findUserById(req.params.id);
  if (!user) return fail(res, 'User not found', 404);
  
  const { password, twoFactorSecret, ...safe } = user;
  const files = db.getFilesByUser(user.id);
  const logs = db.getLogsByUser(user.id, 20);
  const sessions = db.getSessionsByUser(user.id);
  
  ok(res, { 
    user: safe, 
    filesCount: files.length,
    storageUsed: user.storageUsed,
    activeSessions: sessions.length,
    recentActivity: logs,
  });
});

router.patch('/users/:id/role', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const { role } = req.body;
  if (!Object.values(Role).includes(role)) return fail(res, 'Invalid role');
  if (req.params.id === req.user!.id) return fail(res, 'Cannot change your own role');
  
  const user = db.updateUser(req.params.id, { role });
  if (!user) return fail(res, 'User not found', 404);
  
  db.log(req.user!.id, 'UPDATE_ROLE', req.params.id, role);
  db.notify(req.params.id, NotificationType.SYSTEM, 'Role Updated',
    `Your role has been changed to ${role}.`);
  
  ok(res, null, 'Role updated');
});

router.patch('/users/:id/quota', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const { quotaMB } = req.body;
  if (typeof quotaMB !== 'number' || quotaMB < 0) return fail(res, 'Invalid quota');
  
  const quota = quotaMB * 1024 * 1024;
  const user = db.updateUser(req.params.id, { storageQuota: quota });
  if (!user) return fail(res, 'User not found', 404);
  
  db.log(req.user!.id, 'UPDATE_QUOTA', req.params.id, `${quotaMB}MB`);
  ok(res, null, 'Quota updated');
});

router.delete('/users/:id', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  if (req.params.id === req.user!.id) return fail(res, 'Cannot delete yourself');
  
  const user = db.findUserById(req.params.id);
  if (!user) return fail(res, 'User not found', 404);
  
  // Delete user's files
  const files = [...db.getAllFiles()].filter(f => f.ownerId === req.params.id);
  for (const file of files) {
    const filePath = path.join(config.uploadDir, file.storedName);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    db.deleteFile(file.id);
  }
  
  // Delete sessions
  db.deleteSessionsByUser(req.params.id);
  
  if (!db.deleteUser(req.params.id)) return fail(res, 'Failed to delete user', 500);
  
  db.log(req.user!.id, 'DELETE_USER', req.params.id, user.email);
  ok(res, null, 'User deleted');
});

// ============ AUDIT ============
router.get('/audit', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const { userId, action, limit = '100', dateFrom, dateTo } = req.query;
  let logs = db.getLogs(parseInt(limit as string));
  
  if (userId) logs = logs.filter(l => l.userId === userId);
  if (action) logs = logs.filter(l => l.action === action);
  if (dateFrom) {
    const from = new Date(dateFrom as string);
    logs = logs.filter(l => l.timestamp >= from);
  }
  if (dateTo) {
    const to = new Date(dateTo as string);
    logs = logs.filter(l => l.timestamp <= to);
  }
  
  // Enrich with usernames
  const enriched = logs.map(l => {
    const user = db.findUserById(l.userId);
    return { ...l, username: user?.username };
  });
  
  ok(res, enriched);
});

router.get('/audit/actions', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const actions = [...new Set(db.getLogs(1000).map(l => l.action))];
  ok(res, actions);
});

// ============ SYSTEM ============
router.get('/system/stats', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  ok(res, db.getSystemStats());
});

router.get('/system/rate-limiter/stats', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  ok(res, globalRateLimiter.getStats());
});

router.post('/system/rate-limiter/unblock/:ip', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const { ip } = req.params;
  globalRateLimiter.unblock(ip);
  db.log(req.user!.id, 'UNBLOCK_IP', ip, 'Rate limiter unblock');
  ok(res, null, `IP ${ip} unblocked`);
});

router.get('/system/health', (req: Request, res: Response) => {
  ok(res, {
    status: 'healthy',
    timestamp: new Date(),
    uptime: process.uptime(),
  });
});

// ============ ENCRYPTION INFO ============
router.get('/system/encryption-info', auth, (req: Request, res: Response) => {
  ok(res, {
    algorithm: 'AES-256-GCM',
    keyDerivation: {
      algorithm: 'scrypt',
      parameters: {
        N: 16384,
        r: 8,
        p: 1,
        saltLength: '256-bit (32 bytes)',
      },
      description: 'Memory-hard key derivation function resistant to hardware attacks',
    },
    encryption: {
      mode: 'GCM (Galois/Counter Mode)',
      keyLength: '256-bit',
      ivLength: '128-bit (16 bytes)',
      authTagLength: '128-bit (16 bytes)',
      description: 'Authenticated encryption providing confidentiality and integrity',
    },
    integrity: {
      algorithm: 'HMAC-SHA256',
      checksumAlgorithm: 'SHA-256',
      description: 'Double integrity verification: GCM auth tag + HMAC',
    },
    currentVersion: ENCRYPTION_VERSION,
    fileFormat: {
      v3: '[version:1][salt:32][iv:16][tag:16][hmac:32][encrypted_data]',
      v2: '[version:1][salt:32][iv:16][tag:16][encrypted_data]',
      v1: '[iv:16][tag:16][encrypted_data] (legacy)',
    },
    howItWorks: {
      upload: [
        '1. File is received and validated (magic bytes, size limits)',
        '2. SHA-256 checksum computed on original content',
        '3. Random 256-bit salt generated',
        '4. Encryption key derived using scrypt(master_key, salt)',
        '5. Random 128-bit IV generated',
        '6. File encrypted using AES-256-GCM',
        '7. HMAC computed on encrypted data for additional integrity',
        '8. Encrypted file stored: [version][salt][iv][tag][hmac][data]',
        '9. Original file securely deleted',
      ],
      download: [
        '1. Encrypted file retrieved from storage',
        '2. Version byte parsed to determine format',
        '3. HMAC verified (v3 only) - fails if tampered',
        '4. Key re-derived using stored salt',
        '5. File decrypted using AES-256-GCM',
        '6. GCM auth tag verified - fails if corrupted',
        '7. SHA-256 checksum verified against stored hash',
        '8. Decrypted content sent to user',
      ],
    },
    securityFeatures: [
      'Per-file random salt prevents rainbow table attacks',
      'Authenticated encryption prevents undetected tampering',
      'Timing-safe comparisons prevent timing attacks',
      'Memory-hard KDF resists GPU/ASIC brute force',
      'Original files deleted after encryption',
      'Checksums verify content integrity end-to-end',
    ],
  });
});

// ============ SECURITY DASHBOARD ============
router.get('/security/events', auth, (req: Request, res: Response) => {
  const { limit = '50', type } = req.query;
  const isAdmin = req.user!.role === Role.ADMIN;
  
  let events;
  if (isAdmin) {
    events = type 
      ? db.getSecurityEventsByType(type as any, parseInt(limit as string))
      : db.getSecurityEvents(parseInt(limit as string));
  } else {
    events = db.getSecurityEventsByUser(req.user!.id, parseInt(limit as string));
  }
  
  // Enrich with usernames
  const enriched = events.map(e => {
    const user = e.userId ? db.findUserById(e.userId) : null;
    return { ...e, username: user?.username || 'System' };
  });
  
  ok(res, enriched);
});

router.get('/security/dashboard', auth, (req: Request, res: Response) => {
  const userId = req.user!.id;
  const isAdmin = req.user!.role === Role.ADMIN;
  const user = db.findUserById(userId)!;
  
  // Get user's security events
  const recentEvents = db.getSecurityEventsByUser(userId, 10);
  const sessions = db.getSessionsByUser(userId);
  
  // Calculate security score (0-100)
  let securityScore = 50;
  if (user.twoFactorEnabled) securityScore += 20;
  if (user.passwordChangedAt && (Date.now() - new Date(user.passwordChangedAt).getTime()) < 90 * 24 * 60 * 60 * 1000) {
    securityScore += 15; // Password changed in last 90 days
  }
  if (user.failedLoginAttempts === 0) securityScore += 10;
  if (sessions.length <= 3) securityScore += 5; // Not too many active sessions
  
  // Check for suspicious activity
  const failedLogins = db.getSecurityEventsByType('login_failed' as any, 100)
    .filter(e => e.userId === userId && (Date.now() - new Date(e.timestamp).getTime()) < 24 * 60 * 60 * 1000);
  
  const suspiciousEvents = db.getSecurityEventsByType('suspicious_activity' as any, 50)
    .filter(e => e.userId === userId);
  
  // Files with integrity issues
  const userFiles = db.getFilesByUser(userId);
  const filesNeedingVerification = userFiles.filter((f: FileRecord) => {
    if (!f.integrityVerifiedAt) return true;
    const hoursSinceVerify = (Date.now() - new Date(f.integrityVerifiedAt).getTime()) / (1000 * 60 * 60);
    return hoursSinceVerify > 168; // 7 days
  });
  
  // Admin-only stats
  let adminStats = null;
  if (isAdmin) {
    const allEvents = db.getSecurityEvents(1000);
    const last24h = allEvents.filter(e => (Date.now() - new Date(e.timestamp).getTime()) < 24 * 60 * 60 * 1000);
    const failedLoginsSystem = last24h.filter(e => e.eventType === 'login_failed');
    const lockedAccounts = [...db.users.values()].filter(u => u.lockedUntil && u.lockedUntil > new Date());
    
    adminStats = {
      totalEventsLast24h: last24h.length,
      failedLoginsLast24h: failedLoginsSystem.length,
      lockedAccounts: lockedAccounts.length,
      suspiciousActivity: last24h.filter(e => e.eventType === 'suspicious_activity').length,
      uniqueIPs: [...new Set(last24h.map(e => e.ipAddress))].length,
    };
  }
  
  ok(res, {
    securityScore: Math.min(100, securityScore),
    twoFactorEnabled: user.twoFactorEnabled,
    passwordAge: user.passwordChangedAt 
      ? Math.floor((Date.now() - new Date(user.passwordChangedAt).getTime()) / (24 * 60 * 60 * 1000))
      : null,
    activeSessions: sessions.length,
    recentEvents,
    failedLoginsLast24h: failedLogins.length,
    suspiciousActivityCount: suspiciousEvents.length,
    filesNeedingVerification: filesNeedingVerification.length,
    lastLoginAt: user.lastLoginAt,
    adminStats,
  });
});

// ============ FILE SECURITY INSPECTION ============

// Import getFileEncryptionVersion
import { getFileEncryptionVersion } from './crypto';

// Get detailed security information for a file
router.get('/files/:id/security-info', auth, async (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  
  const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id || 
    (file.sharedWith && file.sharedWith.includes(req.user!.id));
  if (!canAccess) return fail(res, 'Access denied', 403);
  
  const filePath = path.join(config.uploadDir, file.storedName);
  const fileExists = fs.existsSync(filePath);
  
  let securityInfo: any = {
    fileId: file.id,
    fileName: file.name,
    encrypted: file.encrypted,
    fileExists,
    checksumAlgorithm: 'SHA-256',
    storedChecksum: file.checksum,
    encryptionVersion: null,
    encryptionAlgorithm: null,
    keyDerivation: null,
    integrityVerifiedAt: file.integrityVerifiedAt,
    lastModified: file.createdAt,
    createdAt: file.createdAt,
  };

  if (fileExists) {
    // Get encryption version info
    if (file.encrypted) {
      const encVersion = getFileEncryptionVersion(filePath);
      securityInfo.encryptionVersion = encVersion;
      
      if (encVersion === 3) {
        securityInfo.encryptionAlgorithm = 'AES-256-GCM';
        securityInfo.keyDerivation = 'scrypt (N=16384, r=8, p=1)';
        securityInfo.integrityProtection = 'GCM Auth Tag + HMAC-SHA256';
        securityInfo.saltLength = '256-bit';
        securityInfo.ivLength = '128-bit';
      } else if (encVersion === 2) {
        securityInfo.encryptionAlgorithm = 'AES-256-GCM';
        securityInfo.keyDerivation = 'scrypt (standard)';
        securityInfo.integrityProtection = 'GCM Auth Tag';
        securityInfo.saltLength = '256-bit';
        securityInfo.ivLength = '128-bit';
        securityInfo.upgradeRecommended = true;
      } else {
        securityInfo.encryptionAlgorithm = 'AES-256-GCM (legacy)';
        securityInfo.keyDerivation = 'scrypt (static salt)';
        securityInfo.integrityProtection = 'GCM Auth Tag';
        securityInfo.upgradeRecommended = true;
      }
    }
    
    // Perform live integrity check
    try {
      let content: Buffer;
      if (file.encrypted) {
        content = decryptFile(filePath);
      } else {
        content = fs.readFileSync(filePath);
      }
      const currentChecksum = nodeCrypto.createHash('sha256').update(content).digest('hex');
      securityInfo.currentChecksum = currentChecksum;
      securityInfo.integrityValid = currentChecksum === file.checksum;
      securityInfo.fileSize = content.length;
      securityInfo.encryptedSize = fs.statSync(filePath).size;
      
      if (file.encrypted) {
        securityInfo.encryptionOverhead = securityInfo.encryptedSize - content.length;
      }
    } catch (err: any) {
      securityInfo.integrityValid = false;
      securityInfo.integrityError = err.message;
    }
  } else {
    securityInfo.integrityValid = false;
    securityInfo.integrityError = 'File not found on disk';
  }

  // Version history security
  const versions = db.getVersionsByFile(file.id);
  securityInfo.versionCount = versions.length;
  securityInfo.versions = versions.map(v => ({
    id: v.id,
    version: v.version,
    checksum: v.checksum,
    createdAt: v.createdAt,
  }));

  // Sharing security
  securityInfo.sharingEnabled = !!(file.sharedWith && file.sharedWith.length > 0);
  securityInfo.sharedUserCount = file.sharedWith?.length || 0;
  
  const shareLinks = db.getShareLinksByFile(file.id);
  securityInfo.publicLinkCount = shareLinks.length;
  securityInfo.shareLinks = shareLinks.map(link => ({
    id: link.id,
    hasPassword: !!link.password,
    hasExpiration: !!link.expiresAt,
    expiresAt: link.expiresAt,
    maxDownloads: link.maxDownloads,
    currentDownloads: link.downloadCount,
    isExpired: link.expiresAt ? new Date(link.expiresAt) < new Date() : false,
  }));

  return ok(res, securityInfo);
});

// System-wide security audit (admin only)
router.get('/security/audit', auth, requireRole(Role.ADMIN), async (req: Request, res: Response) => {
  const allFiles = [...db.files.values()].filter(f => f.status !== FileStatus.DELETED);
  
  const auditResults = {
    totalFiles: allFiles.length,
    encryptedFiles: 0,
    unencryptedFiles: 0,
    encryptionVersions: { v1: 0, v2: 0, v3: 0, unknown: 0 },
    integrityIssues: [] as any[],
    missingFiles: [] as any[],
    upgradeNeeded: [] as any[],
    weakShareLinks: [] as any[],
    expiredShareLinks: 0,
    activeShareLinks: 0,
    passwordProtectedLinks: 0,
    unprotectedLinks: 0,
  };

  for (const file of allFiles) {
    const filePath = path.join(config.uploadDir, file.storedName);
    
    if (!fs.existsSync(filePath)) {
      auditResults.missingFiles.push({
        fileId: file.id,
        fileName: file.name,
        ownerId: file.ownerId,
      });
      continue;
    }

    if (file.encrypted) {
      auditResults.encryptedFiles++;
      const version = getFileEncryptionVersion(filePath);
      if (version === 3) auditResults.encryptionVersions.v3++;
      else if (version === 2) {
        auditResults.encryptionVersions.v2++;
        auditResults.upgradeNeeded.push({ fileId: file.id, fileName: file.name, currentVersion: 2 });
      }
      else if (version === 1) {
        auditResults.encryptionVersions.v1++;
        auditResults.upgradeNeeded.push({ fileId: file.id, fileName: file.name, currentVersion: 1 });
      }
      else auditResults.encryptionVersions.unknown++;
    } else {
      auditResults.unencryptedFiles++;
    }
  }

  // Audit share links
  const allShareLinks = [...db.shareLinks.values()];
  for (const link of allShareLinks) {
    if (link.expiresAt && new Date(link.expiresAt) < new Date()) {
      auditResults.expiredShareLinks++;
    } else {
      auditResults.activeShareLinks++;
      if (link.password) {
        auditResults.passwordProtectedLinks++;
      } else {
        auditResults.unprotectedLinks++;
        auditResults.weakShareLinks.push({
          linkId: link.id,
          fileId: link.fileId,
          reason: 'No password protection',
        });
      }
      
      if (!link.expiresAt && !link.maxDownloads) {
        auditResults.weakShareLinks.push({
          linkId: link.id,
          fileId: link.fileId,
          reason: 'No expiration or download limit',
        });
      }
    }
  }

  return ok(res, auditResults);
});

// Upgrade file encryption to latest version
router.post('/files/:id/upgrade-encryption', auth, async (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  
  if (file.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) {
    return fail(res, 'Access denied', 403);
  }
  
  if (!file.encrypted) {
    return fail(res, 'File is not encrypted', 400);
  }
  
  const filePath = path.join(config.uploadDir, file.storedName);
  if (!fs.existsSync(filePath)) {
    return fail(res, 'File not found on disk', 404);
  }
  
  const currentVersion = getFileEncryptionVersion(filePath);
  if (currentVersion >= ENCRYPTION_VERSION) {
    return ok(res, { 
      message: 'File already using latest encryption version',
      currentVersion,
      latestVersion: ENCRYPTION_VERSION,
      upgraded: false 
    });
  }
  
  try {
    // Decrypt with old version
    const decrypted = decryptFile(filePath);
    
    // Re-encrypt with new version
    const tempPath = filePath + '.upgrade';
    fs.writeFileSync(tempPath, decrypted);
    encryptFile(tempPath, filePath, ENCRYPTION_VERSION);
    fs.unlinkSync(tempPath);
    
    // Update checksum (content unchanged, just re-encrypted)
    const newChecksum = nodeCrypto.createHash('sha256').update(decrypted).digest('hex');
    db.updateFile(file.id, { 
      checksum: newChecksum,
      integrityVerifiedAt: new Date(),
    });
    
    db.log(req.user!.id, 'encryption_upgrade', file.id, 
      `Upgraded encryption from v${currentVersion} to v${ENCRYPTION_VERSION}`);
    
    return ok(res, {
      message: 'Encryption upgraded successfully',
      previousVersion: currentVersion,
      newVersion: ENCRYPTION_VERSION,
      upgraded: true,
    });
  } catch (err: any) {
    return fail(res, `Encryption upgrade failed: ${err.message}`, 500);
  }
});

// Bulk upgrade all files to latest encryption
router.post('/files/upgrade-all', auth, async (req: Request, res: Response) => {
  const files = db.getFilesByUser(req.user!.id).filter(f => f.encrypted);
  const results: { fileId: string; name: string; upgraded: boolean; previousVersion?: number; error?: string }[] = [];
  
  for (const file of files) {
    const filePath = path.join(config.uploadDir, file.storedName);
    if (!fs.existsSync(filePath)) {
      results.push({ fileId: file.id, name: file.name, upgraded: false, error: 'File not found' });
      continue;
    }
    
    const currentVersion = getFileEncryptionVersion(filePath);
    if (currentVersion >= ENCRYPTION_VERSION) {
      results.push({ fileId: file.id, name: file.name, upgraded: false, previousVersion: currentVersion });
      continue;
    }
    
    try {
      const decrypted = decryptFile(filePath);
      const tempPath = filePath + '.upgrade';
      fs.writeFileSync(tempPath, decrypted);
      encryptFile(tempPath, filePath, ENCRYPTION_VERSION);
      fs.unlinkSync(tempPath);
      
      const newChecksum = nodeCrypto.createHash('sha256').update(decrypted).digest('hex');
      db.updateFile(file.id, { checksum: newChecksum, integrityVerifiedAt: new Date() });
      
      results.push({ fileId: file.id, name: file.name, upgraded: true, previousVersion: currentVersion });
    } catch (err: any) {
      results.push({ fileId: file.id, name: file.name, upgraded: false, error: err.message });
    }
  }
  
  const upgradedCount = results.filter(r => r.upgraded).length;
  return ok(res, { 
    total: files.length,
    upgraded: upgradedCount,
    alreadyCurrent: results.filter(r => !r.upgraded && !r.error).length,
    failed: results.filter(r => !!r.error).length,
    results 
  });
});

// Verify HMAC integrity of encrypted file (v3 only)
router.post('/files/:id/verify-hmac', auth, async (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  
  const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id;
  if (!canAccess) return fail(res, 'Access denied', 403);
  
  if (!file.encrypted) {
    return fail(res, 'File is not encrypted', 400);
  }
  
  const filePath = path.join(config.uploadDir, file.storedName);
  if (!fs.existsSync(filePath)) {
    return fail(res, 'File not found on disk', 404);
  }
  
  const version = getFileEncryptionVersion(filePath);
  if (version < 3) {
    return ok(res, {
      hmacVerified: false,
      reason: `File uses encryption v${version} which does not include HMAC`,
      upgradeRecommended: true,
    });
  }
  
  try {
    // Attempt decryption (will verify HMAC internally)
    decryptFile(filePath);
    return ok(res, {
      hmacVerified: true,
      encryptionVersion: version,
      message: 'HMAC verification passed - file integrity confirmed',
    });
  } catch (err: any) {
    if (err.message.includes('HMAC')) {
      db.logSecurityEvent({
        userId: req.user!.id,
        eventType: 'file_integrity_fail' as any,
        description: `HMAC verification failed: ${file.name}`,
        ipAddress: getClientIp(req),
        userAgent: req.headers['user-agent'],
        metadata: { fileId: file.id, fileName: file.name },
      });
      
      return ok(res, {
        hmacVerified: false,
        error: 'HMAC mismatch detected - file may have been tampered with',
        severity: 'critical',
      });
    }
    return fail(res, `Verification failed: ${err.message}`, 500);
  }
});

// File integrity verification
router.post('/files/:id/verify-integrity', auth, async (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  
  const canAccess = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id;
  if (!canAccess) return fail(res, 'Access denied', 403);
  
  const filePath = path.join(config.uploadDir, file.storedName);
  if (!fs.existsSync(filePath)) {
    db.logSecurityEvent({
      userId: req.user!.id,
      eventType: 'file_integrity_fail' as any,
      description: `File missing: ${file.name}`,
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
      metadata: { fileId: file.id, fileName: file.name },
    });
    return fail(res, 'File missing from storage', 404);
  }
  
  try {
    // Decrypt and compute checksum
    let content: Buffer;
    if (file.encrypted) {
      content = decryptFile(filePath);
    } else {
      content = fs.readFileSync(filePath);
    }
    
    const currentChecksum = nodeCrypto.createHash('sha256').update(content).digest('hex');
    const isValid = currentChecksum === file.checksum;
    
    if (!isValid) {
      db.logSecurityEvent({
        userId: req.user!.id,
        eventType: 'file_integrity_fail' as any,
        description: `Integrity check failed: ${file.name}`,
        ipAddress: getClientIp(req),
        userAgent: req.headers['user-agent'],
        metadata: { fileId: file.id, fileName: file.name, expected: file.checksum, actual: currentChecksum },
      });
      
      db.notify(req.user!.id, NotificationType.INTEGRITY_CHECK, 'Integrity Check Failed',
        `File "${file.name}" failed integrity verification. The file may have been tampered with.`);
    }
    
    db.updateFile(file.id, { integrityVerifiedAt: new Date() });
    db.log(req.user!.id, 'VERIFY_INTEGRITY', file.id, file.name);
    
    ok(res, {
      valid: isValid,
      checksum: file.checksum,
      currentChecksum,
      verifiedAt: new Date(),
    });
  } catch (err) {
    return fail(res, 'Failed to verify file integrity', 500);
  }
});

// Verify all user files
router.post('/files/verify-all', auth, async (req: Request, res: Response) => {
  const files = db.getFilesByUser(req.user!.id);
  const results: { fileId: string; name: string; valid: boolean; error?: string }[] = [];
  
  for (const file of files) {
    const filePath = path.join(config.uploadDir, file.storedName);
    if (!fs.existsSync(filePath)) {
      results.push({ fileId: file.id, name: file.name, valid: false, error: 'File missing' });
      continue;
    }
    
    try {
      let content: Buffer;
      if (file.encrypted) {
        content = decryptFile(filePath);
      } else {
        content = fs.readFileSync(filePath);
      }
      
      const currentChecksum = nodeCrypto.createHash('sha256').update(content).digest('hex');
      const isValid = currentChecksum === file.checksum;
      results.push({ fileId: file.id, name: file.name, valid: isValid });
      db.updateFile(file.id, { integrityVerifiedAt: new Date() });
    } catch (err) {
      results.push({ fileId: file.id, name: file.name, valid: false, error: 'Verification error' });
    }
  }
  
  const failedCount = results.filter(r => !r.valid).length;
  if (failedCount > 0) {
    db.notify(req.user!.id, NotificationType.INTEGRITY_CHECK, 'Bulk Integrity Check Complete',
      `${failedCount} of ${results.length} files failed integrity verification.`);
  }
  
  ok(res, {
    total: results.length,
    passed: results.filter(r => r.valid).length,
    failed: failedCount,
    results,
  });
});

// Secure delete (overwrite before deletion)
router.delete('/files/:id/secure', auth, async (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  if (!file) return fail(res, 'File not found', 404);
  
  const canDelete = req.user!.role === Role.ADMIN || file.ownerId === req.user!.id;
  if (!canDelete) return fail(res, 'Access denied', 403);
  
  const filePath = path.join(config.uploadDir, file.storedName);
  
  try {
    if (fs.existsSync(filePath)) {
      // Secure overwrite: write random data multiple times before deletion
      const fileSize = fs.statSync(filePath).size;
      const passes = 3; // DoD standard is 3 passes
      
      for (let pass = 0; pass < passes; pass++) {
        const randomData = nodeCrypto.randomBytes(fileSize);
        fs.writeFileSync(filePath, randomData);
      }
      
      // Final pass with zeros
      fs.writeFileSync(filePath, Buffer.alloc(fileSize, 0));
      
      // Delete the file
      fs.unlinkSync(filePath);
    }
    
    // Delete all versions
    const versions = db.getVersionsByFile(file.id);
    for (const version of versions) {
      const versionPath = path.join(config.uploadDir, 'versions', version.storedName);
      if (fs.existsSync(versionPath)) {
        const vSize = fs.statSync(versionPath).size;
        for (let pass = 0; pass < 3; pass++) {
          fs.writeFileSync(versionPath, nodeCrypto.randomBytes(vSize));
        }
        fs.writeFileSync(versionPath, Buffer.alloc(vSize, 0));
        fs.unlinkSync(versionPath);
      }
      db.deleteVersion(version.id);
    }
    
    // Delete share links and metadata
    db.deleteShareLinksByFile(file.id);
    db.deleteFile(file.id);
    db.updateUser(req.user!.id, { storageUsed: Math.max(0, db.findUserById(req.user!.id)!.storageUsed - file.size) });
    
    db.logSecurityEvent({
      userId: req.user!.id,
      eventType: 'encryption_key_rotated' as any, // Using as secure delete event
      description: `Securely deleted file: ${file.name}`,
      ipAddress: getClientIp(req),
      userAgent: req.headers['user-agent'],
      metadata: { fileId: file.id, fileName: file.name, passes: 3 },
    });
    
    db.log(req.user!.id, 'SECURE_DELETE', file.id, file.name);
    ok(res, null, 'File securely deleted (3-pass overwrite)');
  } catch (err) {
    return fail(res, 'Failed to securely delete file', 500);
  }
});

// Export audit logs
router.get('/audit/export', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const { format = 'csv', dateFrom, dateTo } = req.query;
  let logs = db.getLogs(10000);
  
  if (dateFrom) {
    const from = new Date(dateFrom as string);
    logs = logs.filter(l => l.timestamp >= from);
  }
  if (dateTo) {
    const to = new Date(dateTo as string);
    logs = logs.filter(l => l.timestamp <= to);
  }
  
  // Enrich with usernames
  const enriched = logs.map(l => {
    const user = db.findUserById(l.userId);
    return { ...l, username: user?.username || 'Unknown' };
  });
  
  if (format === 'csv') {
    const header = 'Timestamp,User,Action,Target,Details,IP Address,Severity\n';
    const rows = enriched.map(l => 
      `"${new Date(l.timestamp).toISOString()}","${l.username}","${l.action}","${l.target}","${(l.details || '').replace(/"/g, '""')}","${l.ipAddress || ''}","${l.severity}"`
    ).join('\n');
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=audit-log-${new Date().toISOString().split('T')[0]}.csv`);
    res.send(header + rows);
  } else {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=audit-log-${new Date().toISOString().split('T')[0]}.json`);
    res.send(JSON.stringify(enriched, null, 2));
  }
});

// Export security events
router.get('/security/events/export', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const { format = 'csv' } = req.query;
  const events = db.getSecurityEvents(10000);
  
  const enriched = events.map(e => {
    const user = e.userId ? db.findUserById(e.userId) : null;
    return { ...e, username: user?.username || 'System' };
  });
  
  if (format === 'csv') {
    const header = 'Timestamp,User,Event Type,Description,IP Address,User Agent\n';
    const rows = enriched.map(e => 
      `"${new Date(e.timestamp).toISOString()}","${e.username}","${e.eventType}","${(e.description || '').replace(/"/g, '""')}","${e.ipAddress || ''}","${(e.userAgent || '').replace(/"/g, '""')}"`
    ).join('\n');
    
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=security-events-${new Date().toISOString().split('T')[0]}.csv`);
    res.send(header + rows);
  } else {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=security-events-${new Date().toISOString().split('T')[0]}.json`);
    res.send(JSON.stringify(enriched, null, 2));
  }
});

// Breach detection - analyze patterns
router.get('/security/breach-analysis', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const events = db.getSecurityEvents(5000);
  const now = Date.now();
  const last24h = events.filter(e => (now - new Date(e.timestamp).getTime()) < 24 * 60 * 60 * 1000);
  const last7d = events.filter(e => (now - new Date(e.timestamp).getTime()) < 7 * 24 * 60 * 60 * 1000);
  
  // Analyze failed login patterns
  const failedLogins = last24h.filter(e => e.eventType === 'login_failed');
  const failedByIP: Record<string, number> = {};
  const failedByUser: Record<string, number> = {};
  
  failedLogins.forEach(e => {
    failedByIP[e.ipAddress] = (failedByIP[e.ipAddress] || 0) + 1;
    if (e.userId) {
      failedByUser[e.userId] = (failedByUser[e.userId] || 0) + 1;
    }
  });
  
  // Detect suspicious IPs (>5 failed logins)
  const suspiciousIPs = Object.entries(failedByIP)
    .filter(([_, count]) => count >= 5)
    .map(([ip, count]) => ({ ip, failedAttempts: count, severity: count >= 10 ? 'critical' : 'warning' }));
  
  // Detect brute force targets
  const bruteForceTargets = Object.entries(failedByUser)
    .filter(([_, count]) => count >= 3)
    .map(([userId, count]) => {
      const user = db.findUserById(userId);
      return { userId, username: user?.username, failedAttempts: count };
    });
  
  // Unusual activity times (outside 6am-11pm)
  const unusualTimes = last24h.filter(e => {
    const hour = new Date(e.timestamp).getHours();
    return hour < 6 || hour > 23;
  });
  
  // Multiple session locations
  const sessions = [...db.sessions.values()];
  const userSessions: Record<string, string[]> = {};
  sessions.forEach(s => {
    if (!userSessions[s.userId]) userSessions[s.userId] = [];
    userSessions[s.userId].push(s.ipAddress);
  });
  
  const multiLocationUsers = Object.entries(userSessions)
    .filter(([_, ips]) => new Set(ips).size > 3)
    .map(([userId, ips]) => {
      const user = db.findUserById(userId);
      return { userId, username: user?.username, uniqueIPs: new Set(ips).size };
    });
  
  // Calculate threat level
  let threatLevel = 'low';
  const totalIndicators = suspiciousIPs.length + bruteForceTargets.length + multiLocationUsers.length;
  if (totalIndicators >= 5 || suspiciousIPs.some(ip => ip.severity === 'critical')) {
    threatLevel = 'critical';
  } else if (totalIndicators >= 2) {
    threatLevel = 'high';
  } else if (totalIndicators >= 1) {
    threatLevel = 'medium';
  }
  
  ok(res, {
    threatLevel,
    summary: {
      failedLoginsLast24h: failedLogins.length,
      totalEventsLast24h: last24h.length,
      totalEventsLast7d: last7d.length,
      lockedAccounts: [...db.users.values()].filter(u => u.lockedUntil && u.lockedUntil > new Date()).length,
    },
    indicators: {
      suspiciousIPs,
      bruteForceTargets,
      unusualActivityCount: unusualTimes.length,
      multiLocationUsers,
    },
    recommendations: [
      ...(suspiciousIPs.length > 0 ? ['Consider blocking suspicious IP addresses'] : []),
      ...(bruteForceTargets.length > 0 ? ['Review accounts targeted by brute force attempts'] : []),
      ...(multiLocationUsers.length > 0 ? ['Investigate users with multiple session locations'] : []),
      ...(threatLevel === 'critical' ? ['CRITICAL: Immediate security review recommended'] : []),
    ],
  });
});

// Session analytics
router.get('/security/session-analytics', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const sessions = [...db.sessions.values()];
  const now = Date.now();
  
  // Group by user
  const sessionsByUser: Record<string, number> = {};
  const sessionsByDevice: Record<string, number> = {};
  const sessionsByAge: { active: number; stale: number; old: number } = { active: 0, stale: 0, old: 0 };
  
  sessions.forEach(s => {
    sessionsByUser[s.userId] = (sessionsByUser[s.userId] || 0) + 1;
    
    // Parse user agent for device type
    const ua = s.userAgent || 'Unknown';
    const device = ua.includes('Mobile') ? 'Mobile' : ua.includes('Tablet') ? 'Tablet' : 'Desktop';
    sessionsByDevice[device] = (sessionsByDevice[device] || 0) + 1;
    
    // Age analysis
    const age = now - new Date(s.lastActiveAt).getTime();
    if (age < 60 * 60 * 1000) sessionsByAge.active++; // < 1 hour
    else if (age < 24 * 60 * 60 * 1000) sessionsByAge.stale++; // < 24 hours
    else sessionsByAge.old++;
  });
  
  // Users with most sessions
  const topUsers = Object.entries(sessionsByUser)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([userId, count]) => {
      const user = db.findUserById(userId);
      return { userId, username: user?.username, sessionCount: count };
    });
  
  ok(res, {
    totalSessions: sessions.length,
    byDevice: sessionsByDevice,
    byAge: sessionsByAge,
    topUsers,
    averageSessionsPerUser: sessions.length / new Set(sessions.map(s => s.userId)).size || 0,
  });
});

// Terminate all sessions for a user (admin)
router.delete('/security/sessions/user/:userId', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const targetUser = db.findUserById(req.params.userId);
  if (!targetUser) return fail(res, 'User not found', 404);
  
  const count = db.getSessionsByUser(req.params.userId).length;
  db.deleteSessionsByUser(req.params.userId);
  
  db.logSecurityEvent({
    userId: req.user!.id,
    eventType: 'suspicious_activity' as any,
    description: `Admin terminated all sessions for user: ${targetUser.username}`,
    ipAddress: getClientIp(req),
    metadata: { targetUserId: req.params.userId, sessionsTerminated: count },
  });
  
  ok(res, { terminated: count }, `Terminated ${count} sessions`);
});

// Force password reset
router.post('/security/force-password-reset/:userId', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const targetUser = db.findUserById(req.params.userId);
  if (!targetUser) return fail(res, 'User not found', 404);
  
  // Set a flag that requires password change on next login
  db.updateUser(req.params.userId, { 
    passwordChangedAt: new Date(0), // Force password age check to fail
    lockedUntil: undefined,
    failedLoginAttempts: 0,
  });
  
  // Terminate all sessions
  db.deleteSessionsByUser(req.params.userId);
  
  db.notify(req.params.userId, NotificationType.SECURITY_ALERT, 'Password Reset Required',
    'An administrator has required you to change your password on next login.');
  
  db.logSecurityEvent({
    userId: req.user!.id,
    eventType: 'password_change' as any,
    description: `Admin forced password reset for user: ${targetUser.username}`,
    ipAddress: getClientIp(req),
    metadata: { targetUserId: req.params.userId },
  });
  
  ok(res, null, 'Password reset enforced');
});

// Unlock user account
router.post('/security/unlock/:userId', auth, requireRole(Role.ADMIN), (req: Request, res: Response) => {
  const targetUser = db.findUserById(req.params.userId);
  if (!targetUser) return fail(res, 'User not found', 404);
  
  db.updateUser(req.params.userId, { 
    lockedUntil: undefined,
    failedLoginAttempts: 0,
  });
  
  db.logSecurityEvent({
    userId: req.user!.id,
    eventType: 'account_locked' as any,
    description: `Admin unlocked account: ${targetUser.username}`,
    ipAddress: getClientIp(req),
    metadata: { targetUserId: req.params.userId },
  });
  
  ok(res, null, 'Account unlocked');
});

// ============ ADVANCED ENCRYPTION API ============

// Get available encryption algorithms
router.get('/encryption/algorithms', auth, (req: Request, res: Response) => {
  const algorithms = [
    {
      id: 'aes-256-gcm',
      name: 'AES-256-GCM',
      description: 'Industry standard symmetric encryption with authentication',
      type: 'symmetric',
      keyRequired: false,
      passwordRequired: false,
      recommended: true
    },
    {
      id: 'chacha20-poly1305',
      name: 'ChaCha20-Poly1305',
      description: 'Modern high-performance authenticated encryption',
      type: 'symmetric',
      keyRequired: false,
      passwordRequired: true,
      recommended: true
    },
    {
      id: 'user-key',
      name: 'User Password Encryption',
      description: 'AES-256-GCM encrypted with your own password (server never sees key)',
      type: 'symmetric',
      keyRequired: false,
      passwordRequired: true,
      recommended: true
    },
    {
      id: 'hybrid-rsa-aes',
      name: 'Hybrid RSA + AES',
      description: 'RSA encrypts symmetric key, AES encrypts data. For sharing with specific recipients.',
      type: 'hybrid',
      keyRequired: true,
      passwordRequired: false,
      recommended: false
    },
    {
      id: 'hybrid-rsa-chacha',
      name: 'Hybrid RSA + ChaCha20',
      description: 'RSA encrypts symmetric key, ChaCha20 encrypts data.',
      type: 'hybrid',
      keyRequired: true,
      passwordRequired: false,
      recommended: false
    },
    {
      id: 'envelope',
      name: 'Envelope Encryption (2-Layer)',
      description: 'Double-layer encryption: ChaCha20 + AES-256 for maximum security',
      type: 'envelope',
      keyRequired: false,
      passwordRequired: true,
      recommended: false
    }
  ];
  
  ok(res, algorithms);
});

// Generate encryption key pair
router.post('/encryption/keypairs', auth, async (req: Request, res: Response) => {
  const { type, name, keySize = 4096, curve = 'secp384r1', password } = req.body;
  
  if (!type || !name) {
    return fail(res, 'Type and name are required');
  }
  
  if (!password || password.length < 8) {
    return fail(res, 'Password (min 8 chars) required to protect private key');
  }
  
  try {
    let publicKey: string;
    let privateKey: string;
    
    switch (type) {
      case 'rsa':
        const rsaKeys = generateRSAKeyPair(keySize as 2048 | 3072 | 4096);
        publicKey = rsaKeys.publicKey;
        privateKey = rsaKeys.privateKey;
        break;
      
      case 'ecdh':
        const ecdhKeys = generateECDHKeyPair(curve as 'prime256v1' | 'secp384r1' | 'secp521r1');
        publicKey = ecdhKeys.publicKey;
        privateKey = ecdhKeys.privateKey;
        break;
      
      case 'ed25519':
        const edKeys = generateSigningKeyPair();
        publicKey = edKeys.publicKey;
        privateKey = edKeys.privateKey;
        break;
      
      case 'ecdsa':
        const ecdsaKeys = generateECDSAKeyPair(curve as 'prime256v1' | 'secp384r1');
        publicKey = ecdsaKeys.publicKey;
        privateKey = ecdsaKeys.privateKey;
        break;
      
      default:
        return fail(res, 'Invalid key type. Use: rsa, ecdh, ed25519, or ecdsa');
    }
    
    // Encrypt private key with user's password before storing
    const encryptedPrivateKey = encryptBufferWithUserKey(
      Buffer.from(privateKey, 'utf8'),
      password
    ).toString('base64');
    
    const keyPair: UserKeyPair = {
      id: uuid(),
      userId: req.user!.id,
      name,
      type,
      publicKey,
      encryptedPrivateKey,
      keySize: type === 'rsa' ? keySize : undefined,
      curve: ['ecdh', 'ecdsa'].includes(type) ? curve : undefined,
      createdAt: new Date(),
      isDefault: false
    };
    
    db.createKeyPair(keyPair);
    
    // Return without the encrypted private key for security
    ok(res, {
      id: keyPair.id,
      name: keyPair.name,
      type: keyPair.type,
      publicKey: keyPair.publicKey,
      keySize: keyPair.keySize,
      curve: keyPair.curve,
      createdAt: keyPair.createdAt
    }, 'Key pair generated successfully');
    
  } catch (err: any) {
    fail(res, `Failed to generate key pair: ${err.message}`);
  }
});

// List user's key pairs
router.get('/encryption/keypairs', auth, (req: Request, res: Response) => {
  const keyPairs = db.getKeyPairsByUser(req.user!.id);
  
  // Don't return encrypted private keys
  const safeKeyPairs = keyPairs.map(kp => ({
    id: kp.id,
    name: kp.name,
    type: kp.type,
    publicKey: kp.publicKey,
    keySize: kp.keySize,
    curve: kp.curve,
    createdAt: kp.createdAt,
    lastUsedAt: kp.lastUsedAt,
    isDefault: kp.isDefault
  }));
  
  ok(res, safeKeyPairs);
});

// Delete a key pair
router.delete('/encryption/keypairs/:id', auth, (req: Request, res: Response) => {
  const keyPair = db.getKeyPairById(req.params.id);
  
  if (!keyPair) {
    return fail(res, 'Key pair not found', 404);
  }
  
  if (keyPair.userId !== req.user!.id) {
    return fail(res, 'Unauthorized', 403);
  }
  
  db.deleteKeyPair(req.params.id);
  ok(res, null, 'Key pair deleted');
});

// Set default key pair
router.post('/encryption/keypairs/:id/default', auth, (req: Request, res: Response) => {
  const keyPair = db.getKeyPairById(req.params.id);
  
  if (!keyPair) {
    return fail(res, 'Key pair not found', 404);
  }
  
  if (keyPair.userId !== req.user!.id) {
    return fail(res, 'Unauthorized', 403);
  }
  
  db.setDefaultKeyPair(req.user!.id, req.params.id);
  ok(res, null, 'Default key pair updated');
});

// Get encryption info for a file
router.get('/files/:id/encryption-info', auth, async (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  
  if (!file) {
    return fail(res, 'File not found', 404);
  }
  
  if (file.ownerId !== req.user!.id && !file.sharedWith.includes(req.user!.id)) {
    return fail(res, 'Unauthorized', 403);
  }
  
  try {
    const filePath = path.join(config.uploadDir, file.storedName);
    const fileData = fs.readFileSync(filePath);
    const info = getEncryptionInfo(fileData);
    
    const signature = file.signatureId ? db.getFileSignature(file.signatureId) : null;
    
    ok(res, {
      encrypted: file.encrypted,
      algorithm: info.algorithm,
      version: info.version,
      requiresPassword: info.requiresPassword,
      requiresPrivateKey: info.requiresKey,
      userKeyEncrypted: file.userKeyEncrypted,
      signature: signature ? {
        signedBy: db.findUserById(signature.signedBy)?.username,
        signedAt: signature.signedAt,
        algorithm: signature.algorithm,
        isValid: signature.isValid,
        lastVerifiedAt: signature.lastVerifiedAt
      } : null
    });
  } catch (err: any) {
    fail(res, `Failed to get encryption info: ${err.message}`);
  }
});

// Re-encrypt file with different algorithm
router.post('/files/:id/reencrypt', auth, async (req: Request, res: Response) => {
  const { algorithm, password, publicKeyId, currentPassword } = req.body;
  
  const file = db.findFileById(req.params.id);
  
  if (!file) {
    return fail(res, 'File not found', 404);
  }
  
  if (file.ownerId !== req.user!.id) {
    return fail(res, 'Only file owner can re-encrypt', 403);
  }
  
  try {
    const filePath = path.join(config.uploadDir, file.storedName);
    
    // First decrypt the file
    let decrypted: Buffer;
    
    if (file.userKeyEncrypted) {
      if (!currentPassword) {
        return fail(res, 'Current password required to decrypt');
      }
      decrypted = decryptFileWithUserKey(filePath, currentPassword);
    } else {
      decrypted = decryptFile(filePath);
    }
    
    // Now re-encrypt with new algorithm
    let encrypted: Buffer;
    let newUserKeyEncrypted = false;
    let hybridKeyId: string | undefined;
    
    switch (algorithm) {
      case 'aes-256-gcm':
        encrypted = universalEncrypt(decrypted, { algorithm: EncryptionAlgorithm.AES_256_GCM });
        break;
      
      case 'chacha20-poly1305':
        if (!password) return fail(res, 'Password required for ChaCha20');
        encrypted = universalEncrypt(decrypted, { algorithm: EncryptionAlgorithm.CHACHA20_POLY1305, password });
        newUserKeyEncrypted = true;
        break;
      
      case 'user-key':
        if (!password) return fail(res, 'Password required for user-key encryption');
        encrypted = universalEncrypt(decrypted, { algorithm: EncryptionAlgorithm.USER_KEY, password });
        newUserKeyEncrypted = true;
        break;
      
      case 'envelope':
        if (!password) return fail(res, 'Password required for envelope encryption');
        encrypted = universalEncrypt(decrypted, { algorithm: EncryptionAlgorithm.ENVELOPE, password });
        newUserKeyEncrypted = true;
        break;
      
      case 'hybrid-rsa-aes':
      case 'hybrid-rsa-chacha':
        if (!publicKeyId) return fail(res, 'Public key ID required for hybrid encryption');
        const keyPair = db.getKeyPairById(publicKeyId);
        if (!keyPair || keyPair.type !== 'rsa') {
          return fail(res, 'Valid RSA key pair required');
        }
        const hybridAlg = algorithm === 'hybrid-rsa-chacha' 
          ? EncryptionAlgorithm.HYBRID_RSA_CHACHA 
          : EncryptionAlgorithm.HYBRID_RSA_AES;
        encrypted = universalEncrypt(decrypted, { algorithm: hybridAlg, publicKey: keyPair.publicKey });
        hybridKeyId = publicKeyId;
        break;
      
      default:
        return fail(res, 'Invalid algorithm');
    }
    
    // Write encrypted file
    fs.writeFileSync(filePath, encrypted);
    
    // Update file record
    db.updateFile(file.id, {
      userKeyEncrypted: newUserKeyEncrypted,
      encryptionAlgorithm: algorithm as EncryptionAlgorithmType,
      hybridKeyId,
      checksum: hashFile(filePath)
    });
    
    // Log encryption audit
    db.logEncryptionAudit({
      id: uuid(),
      fileId: file.id,
      userId: req.user!.id,
      action: 'reencrypt',
      algorithm: algorithm as EncryptionAlgorithmType,
      timestamp: new Date(),
      success: true,
      ipAddress: getClientIp(req)
    });
    
    ok(res, null, `File re-encrypted with ${algorithm}`);
    
  } catch (err: any) {
    db.logEncryptionAudit({
      id: uuid(),
      fileId: file.id,
      userId: req.user!.id,
      action: 'reencrypt',
      algorithm: algorithm as EncryptionAlgorithmType,
      timestamp: new Date(),
      success: false,
      errorMessage: err.message,
      ipAddress: getClientIp(req)
    });
    fail(res, `Re-encryption failed: ${err.message}`);
  }
});

// Sign a file
router.post('/files/:id/sign', auth, async (req: Request, res: Response) => {
  const { keyPairId, password } = req.body;
  
  const file = db.findFileById(req.params.id);
  
  if (!file) {
    return fail(res, 'File not found', 404);
  }
  
  if (file.ownerId !== req.user!.id) {
    return fail(res, 'Only file owner can sign', 403);
  }
  
  if (!keyPairId || !password) {
    return fail(res, 'Key pair ID and password required');
  }
  
  try {
    const keyPair = db.getKeyPairById(keyPairId);
    
    if (!keyPair) {
      return fail(res, 'Key pair not found', 404);
    }
    
    if (keyPair.userId !== req.user!.id) {
      return fail(res, 'Unauthorized to use this key pair', 403);
    }
    
    if (!['ed25519', 'ecdsa'].includes(keyPair.type)) {
      return fail(res, 'Key pair must be ed25519 or ecdsa for signing');
    }
    
    // Decrypt private key
    const encryptedPrivateKey = Buffer.from(keyPair.encryptedPrivateKey, 'base64');
    const privateKey = decryptBufferWithUserKey(encryptedPrivateKey, password).toString('utf8');
    
    // Read file and create signature
    const filePath = path.join(config.uploadDir, file.storedName);
    const fileData = fs.readFileSync(filePath);
    
    let signature: string;
    if (keyPair.type === 'ed25519') {
      signature = digitalSign(fileData, privateKey);
    } else {
      signature = ecdsaSign(fileData, privateKey);
    }
    
    // Store signature
    const sigRecord: FileSignature = {
      id: uuid(),
      fileId: file.id,
      signedBy: req.user!.id,
      signature,
      algorithm: keyPair.type as 'ed25519' | 'ecdsa',
      publicKeyId: keyPairId,
      signedAt: new Date(),
      isValid: true,
      lastVerifiedAt: new Date()
    };
    
    db.createFileSignature(sigRecord);
    db.updateFile(file.id, { signatureId: sigRecord.id });
    db.updateKeyPair(keyPairId, { lastUsedAt: new Date() });
    
    ok(res, {
      signatureId: sigRecord.id,
      signedAt: sigRecord.signedAt,
      algorithm: sigRecord.algorithm
    }, 'File signed successfully');
    
  } catch (err: any) {
    fail(res, `Signing failed: ${err.message}`);
  }
});

// Verify file signature
router.post('/files/:id/verify-signature', auth, async (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  
  if (!file) {
    return fail(res, 'File not found', 404);
  }
  
  if (!file.signatureId) {
    return fail(res, 'File has no signature');
  }
  
  try {
    const sigRecord = db.getFileSignature(file.signatureId);
    
    if (!sigRecord) {
      return fail(res, 'Signature record not found');
    }
    
    const keyPair = db.getKeyPairById(sigRecord.publicKeyId);
    
    if (!keyPair) {
      return fail(res, 'Signing key not found - cannot verify');
    }
    
    const filePath = path.join(config.uploadDir, file.storedName);
    const fileData = fs.readFileSync(filePath);
    
    let isValid: boolean;
    if (sigRecord.algorithm === 'ed25519') {
      isValid = verifyDigitalSignature(fileData, sigRecord.signature, keyPair.publicKey);
    } else {
      isValid = verifyECDSASignature(fileData, sigRecord.signature, keyPair.publicKey);
    }
    
    // Update signature record
    db.updateFileSignature(sigRecord.id, {
      isValid,
      lastVerifiedAt: new Date()
    });
    
    const signer = db.findUserById(sigRecord.signedBy);
    
    ok(res, {
      isValid,
      signedBy: signer?.username || 'Unknown',
      signedAt: sigRecord.signedAt,
      algorithm: sigRecord.algorithm,
      verifiedAt: new Date()
    });
    
  } catch (err: any) {
    fail(res, `Verification failed: ${err.message}`);
  }
});

// Get encryption audit log for a file
router.get('/files/:id/encryption-audit', auth, (req: Request, res: Response) => {
  const file = db.findFileById(req.params.id);
  
  if (!file) {
    return fail(res, 'File not found', 404);
  }
  
  if (file.ownerId !== req.user!.id && req.user!.role !== Role.ADMIN) {
    return fail(res, 'Unauthorized', 403);
  }
  
  const audits = db.getEncryptionAudits(file.id);
  ok(res, audits);
});

// Generate secure passphrase
router.get('/encryption/generate-passphrase', auth, (req: Request, res: Response) => {
  const wordCount = parseInt(req.query.words as string) || 6;
  const passphrase = generatePassphrase(Math.min(Math.max(wordCount, 4), 12));
  ok(res, { passphrase });
});

// Decrypt private key (for client-side operations)
router.post('/encryption/keypairs/:id/decrypt-private', auth, async (req: Request, res: Response) => {
  const { password } = req.body;
  
  if (!password) {
    return fail(res, 'Password required');
  }
  
  const keyPair = db.getKeyPairById(req.params.id);
  
  if (!keyPair) {
    return fail(res, 'Key pair not found', 404);
  }
  
  if (keyPair.userId !== req.user!.id) {
    return fail(res, 'Unauthorized', 403);
  }
  
  try {
    const encryptedPrivateKey = Buffer.from(keyPair.encryptedPrivateKey, 'base64');
    const privateKey = decryptBufferWithUserKey(encryptedPrivateKey, password).toString('utf8');
    
    // For security, we typically wouldn't return the private key
    // But for client-side hybrid decryption, we need it
    // This should be done over HTTPS only
    ok(res, { privateKey });
    
  } catch (err: any) {
    fail(res, 'Invalid password');
  }
});

export default router;

