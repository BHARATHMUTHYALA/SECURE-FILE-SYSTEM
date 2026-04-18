/**
 * Two-Factor Authentication (2FA) Module
 * Feature 1: TOTP-based 2FA with QR codes and backup codes
 */

import crypto from 'crypto';
import { generateSecureCode } from './crypto';

// Base32 encoding/decoding for TOTP secrets
const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function encodeBase32(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';
  
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    
    while (bits >= 5) {
      output += base32Chars[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  
  if (bits > 0) {
    output += base32Chars[(value << (5 - bits)) & 31];
  }
  
  // Add padding
  while (output.length % 8 !== 0) {
    output += '=';
  }
  
  return output;
}

function decodeBase32(encoded: string): Buffer {
  const cleanStr = encoded.toUpperCase().replace(/=+$/, '');
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  
  for (let i = 0; i < cleanStr.length; i++) {
    const idx = base32Chars.indexOf(cleanStr[i]);
    if (idx === -1) continue;
    
    value = (value << 5) | idx;
    bits += 5;
    
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  
  return Buffer.from(output);
}

/**
 * Generate a TOTP secret (base32 encoded)
 */
export function generateTOTPSecret(): string {
  const buffer = crypto.randomBytes(20); // 160 bits
  return encodeBase32(buffer);
}

/**
 * Generate TOTP code for a given secret and time
 */
export function generateTOTP(secret: string, timeStep: number = 30, time?: number): string {
  const epoch = Math.floor((time || Date.now()) / 1000);
  const counter = Math.floor(epoch / timeStep);
  
  const secretBuffer = decodeBase32(secret);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigInt64BE(BigInt(counter));
  
  const hmac = crypto.createHmac('sha1', secretBuffer);
  hmac.update(counterBuffer);
  const hash = hmac.digest();
  
  const offset = hash[hash.length - 1] & 0xf;
  const code = (
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff)
  ) % 1000000;
  
  return code.toString().padStart(6, '0');
}

/**
 * Verify TOTP code (allows for time drift)
 */
export function verifyTOTP(token: string, secret: string, window: number = 1): boolean {
  if (!token || token.length !== 6 || !/^\d{6}$/.test(token)) {
    return false;
  }
  
  const timeStep = 30;
  const currentTime = Date.now();
  
  // Check current time and adjacent windows
  for (let i = -window; i <= window; i++) {
    const time = currentTime + (i * timeStep * 1000);
    const expectedCode = generateTOTP(secret, timeStep, time);
    
    if (token === expectedCode) {
      return true;
    }
  }
  
  return false;
}

/**
 * Generate QR code data URL for TOTP setup
 * Format: otpauth://totp/Label?secret=SECRET&issuer=ISSUER
 */
export function generateTOTPQRCodeURL(
  secret: string,
  accountName: string,
  issuer: string = 'SecureFileSystem'
): string {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  
  return `otpauth://totp/${label}?${params.toString()}`;
}

/**
 * Generate backup codes for 2FA recovery
 */
export function generateBackupCodes(count: number = 10): string[] {
  const codes: string[] = [];
  
  for (let i = 0; i < count; i++) {
    // Generate 8-character alphanumeric code
    const code = generateSecureCode(8);
    // Format as XXXX-XXXX for readability
    codes.push(`${code.slice(0, 4)}-${code.slice(4, 8)}`);
  }
  
  return codes;
}

/**
 * Hash backup code for storage
 */
export function hashBackupCode(code: string): string {
  return crypto.createHash('sha256').update(code.toUpperCase().replace('-', '')).digest('hex');
}

/**
 * Verify backup code against stored hash
 */
export function verifyBackupCode(code: string, hashedCode: string): boolean {
  const normalized = code.toUpperCase().replace('-', '');
  const hash = crypto.createHash('sha256').update(normalized).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(hashedCode));
}

/**
 * Generate QR code as ASCII art (simple version for terminal display)
 */
export function generateQRCodeASCII(data: string): string {
  // This is a simplified version - in production, use a proper QR code library
  // For now, just return the URL that can be used with a QR code generator
  return `
╔════════════════════════════════════════╗
║  Scan this QR code with your 2FA app  ║
║                                        ║
║  Or manually enter the secret:         ║
║  ${data.split('secret=')[1]?.split('&')[0] || 'N/A'}                    ║
║                                        ║
║  Use Google Authenticator, Authy,     ║
║  or any TOTP-compatible app            ║
╚════════════════════════════════════════╝

Full URL: ${data}
`;
}

/**
 * Validate 2FA setup
 */
export function validate2FASetup(secret: string, token: string): { valid: boolean; error?: string } {
  if (!secret || secret.length < 16) {
    return { valid: false, error: 'Invalid secret format' };
  }
  
  if (!token || token.length !== 6 || !/^\d{6}$/.test(token)) {
    return { valid: false, error: 'Token must be 6 digits' };
  }
  
  if (!verifyTOTP(token, secret)) {
    return { valid: false, error: 'Invalid verification code' };
  }
  
  return { valid: true };
}

export interface TwoFactorSetup {
  secret: string;
  qrCodeURL: string;
  qrCodeASCII: string;
  backupCodes: string[];
  backupCodesHashed: string[];
}

/**
 * Complete 2FA setup for a user
 */
export function setup2FA(username: string, email: string): TwoFactorSetup {
  const secret = generateTOTPSecret();
  const qrCodeURL = generateTOTPQRCodeURL(secret, email);
  const qrCodeASCII = generateQRCodeASCII(qrCodeURL);
  const backupCodes = generateBackupCodes(10);
  const backupCodesHashed = backupCodes.map(hashBackupCode);
  
  return {
    secret,
    qrCodeURL,
    qrCodeASCII,
    backupCodes,
    backupCodesHashed,
  };
}
