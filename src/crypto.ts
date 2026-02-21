import crypto from 'crypto';
import fs from 'fs';
import { config } from './config';

// Enhanced encryption constants
const ALGORITHM = 'aes-256-gcm';
const IV_LEN = 16;
const TAG_LEN = 16;
const SALT_LEN = 32;
const KEY_LEN = 32;
const SCRYPT_N = 16384; // CPU/memory cost parameter (increased for security)
const SCRYPT_R = 8;     // Block size parameter
const SCRYPT_P = 1;     // Parallelization parameter

// Current encryption version
export const ENCRYPTION_VERSION = 3;
// User-key encryption version
export const USER_KEY_VERSION = 4;

// Derive key using enhanced scrypt parameters (server-managed key)
const deriveKey = (salt: Buffer, keyVersion = ENCRYPTION_VERSION): Buffer => {
  if (keyVersion >= 3) {
    // Version 3: Enhanced scrypt with better parameters
    return crypto.scryptSync(config.encryptionKey, salt, KEY_LEN, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
    });
  }
  // Version 2: Standard scrypt
  return crypto.scryptSync(config.encryptionKey, salt, KEY_LEN);
};

// Derive key from USER-PROVIDED password/key
const deriveUserKey = (userKey: string, salt: Buffer): Buffer => {
  return crypto.scryptSync(userKey, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
};

// Derive HMAC key from user key
const deriveUserHmacKey = (userKey: string, salt: Buffer): Buffer => {
  return crypto.scryptSync(userKey + ':hmac', salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
};

// Get legacy key (for backward compatibility with version 1)
const getLegacyKey = () => crypto.scryptSync(config.encryptionKey, 'salt', KEY_LEN);

// Additional derived key for HMAC integrity checking
const deriveHmacKey = (salt: Buffer): Buffer => {
  return crypto.scryptSync(config.encryptionKey + ':hmac', salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
};

export const encryptFile = (inputPath: string, outputPath: string, version = ENCRYPTION_VERSION): void => {
  const salt = crypto.randomBytes(SALT_LEN);
  const key = deriveKey(salt, version);
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const input = fs.readFileSync(inputPath);
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  const tag = cipher.getAuthTag();
  
  // Version 3 format: [version(1)][salt(32)][iv(16)][tag(16)][hmac(32)][encrypted data]
  const versionByte = Buffer.from([version]);
  
  if (version >= 3) {
    // Add HMAC for additional integrity verification
    const hmacKey = deriveHmacKey(salt);
    const hmac = crypto.createHmac('sha256', hmacKey);
    hmac.update(encrypted);
    const hmacDigest = hmac.digest();
    fs.writeFileSync(outputPath, Buffer.concat([versionByte, salt, iv, tag, hmacDigest, encrypted]));
  } else {
    // Version 2 format (backward compatible)
    fs.writeFileSync(outputPath, Buffer.concat([versionByte, salt, iv, tag, encrypted]));
  }
};

export const decryptFile = (inputPath: string): Buffer => {
  const data = fs.readFileSync(inputPath);
  const version = data[0];
  
  if (version === 0x03) {
    // Version 3 format with HMAC
    const salt = data.subarray(1, 1 + SALT_LEN);
    const iv = data.subarray(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
    const tag = data.subarray(1 + SALT_LEN + IV_LEN, 1 + SALT_LEN + IV_LEN + TAG_LEN);
    const storedHmac = data.subarray(1 + SALT_LEN + IV_LEN + TAG_LEN, 1 + SALT_LEN + IV_LEN + TAG_LEN + 32);
    const encrypted = data.subarray(1 + SALT_LEN + IV_LEN + TAG_LEN + 32);
    
    // Verify HMAC first
    const hmacKey = deriveHmacKey(salt);
    const hmac = crypto.createHmac('sha256', hmacKey);
    hmac.update(encrypted);
    const computedHmac = hmac.digest();
    
    if (!crypto.timingSafeEqual(storedHmac, computedHmac)) {
      throw new Error('File integrity check failed: HMAC mismatch');
    }
    
    const key = deriveKey(salt, 3);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } else if (version === 0x02) {
    // Version 2 format with salt
    const salt = data.subarray(1, 1 + SALT_LEN);
    const iv = data.subarray(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
    const tag = data.subarray(1 + SALT_LEN + IV_LEN, 1 + SALT_LEN + IV_LEN + TAG_LEN);
    const encrypted = data.subarray(1 + SALT_LEN + IV_LEN + TAG_LEN);
    const key = deriveKey(salt, 2);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } else {
    // Legacy format (version 1, no version byte)
    const iv = data.subarray(0, IV_LEN);
    const tag = data.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const encrypted = data.subarray(IV_LEN + TAG_LEN);
    const decipher = crypto.createDecipheriv(ALGORITHM, getLegacyKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }
};

export const encryptBuffer = (input: Buffer, version = ENCRYPTION_VERSION): Buffer => {
  const salt = crypto.randomBytes(SALT_LEN);
  const key = deriveKey(salt, version);
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  const tag = cipher.getAuthTag();
  const versionByte = Buffer.from([version]);
  
  if (version >= 3) {
    const hmacKey = deriveHmacKey(salt);
    const hmac = crypto.createHmac('sha256', hmacKey);
    hmac.update(encrypted);
    const hmacDigest = hmac.digest();
    return Buffer.concat([versionByte, salt, iv, tag, hmacDigest, encrypted]);
  }
  return Buffer.concat([versionByte, salt, iv, tag, encrypted]);
};

export const decryptBuffer = (data: Buffer): Buffer => {
  const version = data[0];
  
  if (version === 0x03) {
    const salt = data.subarray(1, 1 + SALT_LEN);
    const iv = data.subarray(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
    const tag = data.subarray(1 + SALT_LEN + IV_LEN, 1 + SALT_LEN + IV_LEN + TAG_LEN);
    const storedHmac = data.subarray(1 + SALT_LEN + IV_LEN + TAG_LEN, 1 + SALT_LEN + IV_LEN + TAG_LEN + 32);
    const encrypted = data.subarray(1 + SALT_LEN + IV_LEN + TAG_LEN + 32);
    
    const hmacKey = deriveHmacKey(salt);
    const hmac = crypto.createHmac('sha256', hmacKey);
    hmac.update(encrypted);
    const computedHmac = hmac.digest();
    
    if (!crypto.timingSafeEqual(storedHmac, computedHmac)) {
      throw new Error('Data integrity check failed: HMAC mismatch');
    }
    
    const key = deriveKey(salt, 3);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } else if (version === 0x02) {
    const salt = data.subarray(1, 1 + SALT_LEN);
    const iv = data.subarray(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
    const tag = data.subarray(1 + SALT_LEN + IV_LEN, 1 + SALT_LEN + IV_LEN + TAG_LEN);
    const encrypted = data.subarray(1 + SALT_LEN + IV_LEN + TAG_LEN);
    const key = deriveKey(salt, 2);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } else {
    const iv = data.subarray(0, IV_LEN);
    const tag = data.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const encrypted = data.subarray(IV_LEN + TAG_LEN);
    const decipher = crypto.createDecipheriv(ALGORITHM, getLegacyKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }
};

// ============ USER-KEY SYMMETRIC ENCRYPTION ============
// These functions use a USER-PROVIDED key instead of the server key
// The server NEVER stores or knows the user's encryption key

/**
 * Encrypt a file using a USER-PROVIDED encryption key
 * Format: [version:0x04][salt:32][iv:16][tag:16][hmac:32][encrypted_data]
 */
export const encryptFileWithUserKey = (inputPath: string, outputPath: string, userKey: string): void => {
  if (!userKey || userKey.length < 8) {
    throw new Error('Encryption key must be at least 8 characters');
  }
  
  const salt = crypto.randomBytes(SALT_LEN);
  const key = deriveUserKey(userKey, salt);
  const iv = crypto.randomBytes(IV_LEN);
  
  const input = fs.readFileSync(inputPath);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  const tag = cipher.getAuthTag();
  
  // Add HMAC for integrity verification
  const hmacKey = deriveUserHmacKey(userKey, salt);
  const hmac = crypto.createHmac('sha256', hmacKey);
  hmac.update(encrypted);
  const hmacDigest = hmac.digest();
  
  // Version 4 format: [version(1)][salt(32)][iv(16)][tag(16)][hmac(32)][encrypted data]
  const versionByte = Buffer.from([USER_KEY_VERSION]);
  fs.writeFileSync(outputPath, Buffer.concat([versionByte, salt, iv, tag, hmacDigest, encrypted]));
};

/**
 * Decrypt a file using a USER-PROVIDED encryption key
 * Returns the decrypted content as a Buffer
 */
export const decryptFileWithUserKey = (inputPath: string, userKey: string): Buffer => {
  if (!userKey) {
    throw new Error('Decryption key is required');
  }
  
  const data = fs.readFileSync(inputPath);
  const version = data[0];
  
  if (version !== USER_KEY_VERSION) {
    throw new Error('This file was not encrypted with a user key. Use standard decryption.');
  }
  
  const salt = data.subarray(1, 1 + SALT_LEN);
  const iv = data.subarray(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
  const tag = data.subarray(1 + SALT_LEN + IV_LEN, 1 + SALT_LEN + IV_LEN + TAG_LEN);
  const storedHmac = data.subarray(1 + SALT_LEN + IV_LEN + TAG_LEN, 1 + SALT_LEN + IV_LEN + TAG_LEN + 32);
  const encrypted = data.subarray(1 + SALT_LEN + IV_LEN + TAG_LEN + 32);
  
  // Verify HMAC first
  const hmacKey = deriveUserHmacKey(userKey, salt);
  const hmac = crypto.createHmac('sha256', hmacKey);
  hmac.update(encrypted);
  const computedHmac = hmac.digest();
  
  if (!crypto.timingSafeEqual(storedHmac, computedHmac)) {
    throw new Error('Decryption failed: Invalid key or file has been tampered with');
  }
  
  const key = deriveUserKey(userKey, salt);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  
  try {
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch (err) {
    throw new Error('Decryption failed: Invalid key');
  }
};

/**
 * Encrypt a buffer using a USER-PROVIDED encryption key
 */
export const encryptBufferWithUserKey = (input: Buffer, userKey: string): Buffer => {
  if (!userKey || userKey.length < 8) {
    throw new Error('Encryption key must be at least 8 characters');
  }
  
  const salt = crypto.randomBytes(SALT_LEN);
  const key = deriveUserKey(userKey, salt);
  const iv = crypto.randomBytes(IV_LEN);
  
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  const tag = cipher.getAuthTag();
  
  const hmacKey = deriveUserHmacKey(userKey, salt);
  const hmac = crypto.createHmac('sha256', hmacKey);
  hmac.update(encrypted);
  const hmacDigest = hmac.digest();
  
  const versionByte = Buffer.from([USER_KEY_VERSION]);
  return Buffer.concat([versionByte, salt, iv, tag, hmacDigest, encrypted]);
};

/**
 * Decrypt a buffer using a USER-PROVIDED encryption key
 */
export const decryptBufferWithUserKey = (data: Buffer, userKey: string): Buffer => {
  if (!userKey) {
    throw new Error('Decryption key is required');
  }
  
  const version = data[0];
  if (version !== USER_KEY_VERSION) {
    throw new Error('This data was not encrypted with a user key');
  }
  
  const salt = data.subarray(1, 1 + SALT_LEN);
  const iv = data.subarray(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
  const tag = data.subarray(1 + SALT_LEN + IV_LEN, 1 + SALT_LEN + IV_LEN + TAG_LEN);
  const storedHmac = data.subarray(1 + SALT_LEN + IV_LEN + TAG_LEN, 1 + SALT_LEN + IV_LEN + TAG_LEN + 32);
  const encrypted = data.subarray(1 + SALT_LEN + IV_LEN + TAG_LEN + 32);
  
  const hmacKey = deriveUserHmacKey(userKey, salt);
  const hmac = crypto.createHmac('sha256', hmacKey);
  hmac.update(encrypted);
  const computedHmac = hmac.digest();
  
  if (!crypto.timingSafeEqual(storedHmac, computedHmac)) {
    throw new Error('Decryption failed: Invalid key or data has been tampered with');
  }
  
  const key = deriveUserKey(userKey, salt);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  
  try {
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch (err) {
    throw new Error('Decryption failed: Invalid key');
  }
};

/**
 * Check if a file uses user-key encryption
 */
export const isUserKeyEncrypted = (filePath: string): boolean => {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buffer = Buffer.alloc(1);
    fs.readSync(fd, buffer, 0, 1, 0);
    fs.closeSync(fd);
    return buffer[0] === USER_KEY_VERSION;
  } catch {
    return false;
  }
};

export const hashFile = (path: string): string => 
  crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex');

export const hashBuffer = (buffer: Buffer): string =>
  crypto.createHash('sha256').update(buffer).digest('hex');

export const hashString = (str: string): string =>
  crypto.createHash('sha256').update(str).digest('hex');

export const generateToken = (len = 32): string => 
  crypto.randomBytes(len).toString('hex');

export const generateSecureCode = (length = 6): string => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Excluding confusing chars
  let result = '';
  const randomBytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    result += chars[randomBytes[i] % chars.length];
  }
  return result;
};

// Hash password for share links
export const hashPassword = (password: string): string => {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
};

export const verifyPassword = (password: string, storedHash: string): boolean => {
  const [salt, hash] = storedHash.split(':');
  const verifyHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(verifyHash));
};

// Base32 encode/decode helper (RFC 4648)
const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const encodeBase32 = (buffer: Buffer): string => {
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
  return output;
};

const decodeBase32 = (encoded: string): Buffer => {
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
};

// Generate TOTP secret for 2FA
export const generateTOTPSecret = (): string => {
  return encodeBase32(crypto.randomBytes(20));
};

// Simple TOTP verification (in production, use a proper TOTP library)
export const verifyTOTP = (token: string, secret: string): boolean => {
  // This is a simplified version - in production use speakeasy or similar
  const timeStep = 30;
  const currentTime = Math.floor(Date.now() / 1000 / timeStep);
  
  for (let i = -1; i <= 1; i++) {
    const time = currentTime + i;
    const hmac = crypto.createHmac('sha1', decodeBase32(secret));
    const timeBuffer = Buffer.alloc(8);
    timeBuffer.writeBigInt64BE(BigInt(time));
    hmac.update(timeBuffer);
    const hash = hmac.digest();
    const offset = hash[hash.length - 1] & 0xf;
    const code = ((hash[offset] & 0x7f) << 24 |
                  (hash[offset + 1] & 0xff) << 16 |
                  (hash[offset + 2] & 0xff) << 8 |
                  (hash[offset + 3] & 0xff)) % 1000000;
    if (code.toString().padStart(6, '0') === token) {
      return true;
    }
  }
  return false;
};

// Create a secure hash for URLs
export const createUrlSafeHash = (data: string): string => {
  return crypto.createHash('sha256')
    .update(data + config.jwtSecret)
    .digest('base64url')
    .substring(0, 32);
};

// ============ ENHANCED SECURITY FUNCTIONS ============

// Verify file integrity without decrypting
export const verifyFileIntegrity = (filePath: string, expectedChecksum: string): boolean => {
  try {
    const currentChecksum = hashFile(filePath);
    return crypto.timingSafeEqual(
      Buffer.from(currentChecksum),
      Buffer.from(expectedChecksum)
    );
  } catch {
    return false;
  }
};

// Get encryption version from encrypted file
export const getFileEncryptionVersion = (filePath: string): number => {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buffer = Buffer.alloc(1);
    fs.readSync(fd, buffer, 0, 1, 0);
    fs.closeSync(fd);
    const version = buffer[0];
    // Version 1 files don't have a version byte, they start with IV
    return version === 0x02 || version === 0x03 ? version : 1;
  } catch {
    return 0;
  }
};

// Re-encrypt file with latest encryption version
export const upgradeFileEncryption = (filePath: string, outputPath: string): boolean => {
  try {
    const currentVersion = getFileEncryptionVersion(filePath);
    if (currentVersion >= ENCRYPTION_VERSION) {
      return false; // Already at latest version
    }
    
    const decrypted = decryptFile(filePath);
    const tempPath = filePath + '.tmp';
    fs.writeFileSync(tempPath, decrypted);
    encryptFile(tempPath, outputPath, ENCRYPTION_VERSION);
    fs.unlinkSync(tempPath);
    return true;
  } catch {
    return false;
  }
};

// Secure random string generator for various purposes
export const generateSecureId = (length = 16): string => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const randomBytes = crypto.randomBytes(length);
  for (let i = 0; i < length; i++) {
    result += chars[randomBytes[i] % chars.length];
  }
  return result;
};

// Secure deletion - overwrite file before deletion
export const secureDelete = (filePath: string, passes = 3): boolean => {
  try {
    if (!fs.existsSync(filePath)) return false;
    
    const stats = fs.statSync(filePath);
    const size = stats.size;
    
    for (let i = 0; i < passes; i++) {
      // Overwrite with random data
      const randomData = crypto.randomBytes(size);
      fs.writeFileSync(filePath, randomData);
    }
    
    // Final overwrite with zeros
    fs.writeFileSync(filePath, Buffer.alloc(size, 0));
    
    // Delete the file
    fs.unlinkSync(filePath);
    return true;
  } catch {
    // Fallback to regular delete
    try {
      fs.unlinkSync(filePath);
      return true;
    } catch {
      return false;
    }
  }
};

// Generate a fingerprint for device/session tracking
export const generateDeviceFingerprint = (userAgent: string, ipAddress: string): string => {
  return crypto.createHash('sha256')
    .update(userAgent + ipAddress + config.jwtSecret)
    .digest('hex')
    .substring(0, 32);
};

// Constant-time string comparison
export const secureCompare = (a: string, b: string): boolean => {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
};

// Generate HMAC for data signing
export const signData = (data: string): string => {
  return crypto.createHmac('sha256', config.jwtSecret)
    .update(data)
    .digest('hex');
};

// Verify HMAC signature
export const verifySignature = (data: string, signature: string): boolean => {
  const expected = signData(data);
  return secureCompare(expected, signature);
};
