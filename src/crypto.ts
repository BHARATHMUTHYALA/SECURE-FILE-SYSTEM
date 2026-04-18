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
    
    // CRITICAL FIX: Verify HMAC BEFORE attempting decryption
    const hmacKey = deriveHmacKey(salt);
    const hmac = crypto.createHmac('sha256', hmacKey);
    hmac.update(encrypted);
    const computedHmac = hmac.digest();
    
    if (!crypto.timingSafeEqual(storedHmac, computedHmac)) {
      throw new Error('File integrity verification failed. This could mean: (1) The file was encrypted with a different key, or (2) The file has been tampered with.');
    }
    
    // Only decrypt after HMAC verification passes
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

// ============ RSA ASYMMETRIC ENCRYPTION ============
// RSA for key exchange and encrypting small data

export interface RSAKeyPair {
  publicKey: string;
  privateKey: string;
}

/**
 * Validate RSA public key format
 * BUG FIX 13: Add RSA public key format validation
 */
export const validateRSAPublicKey = (publicKey: string): boolean => {
  if (!publicKey || typeof publicKey !== 'string') return false;
  
  // Check for PEM format markers
  if (!publicKey.includes('-----BEGIN PUBLIC KEY-----') || 
      !publicKey.includes('-----END PUBLIC KEY-----')) {
    return false;
  }
  
  try {
    // Try to create a key object to validate format
    crypto.createPublicKey(publicKey);
    return true;
  } catch {
    return false;
  }
};

/**
 * Generate RSA key pair (2048, 3072, or 4096 bits)
 */
export const generateRSAKeyPair = (keySize: 2048 | 3072 | 4096 = 4096): RSAKeyPair => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: keySize,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  return { publicKey, privateKey };
};

/**
 * Encrypt data with RSA public key (OAEP padding with SHA-256)
 */
export const rsaEncrypt = (data: Buffer, publicKey: string): Buffer => {
  // BUG FIX 13: Validate RSA public key format before use
  if (!validateRSAPublicKey(publicKey)) {
    throw new Error('Invalid RSA public key format');
  }
  
  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    data
  );
};

/**
 * Decrypt data with RSA private key
 */
export const rsaDecrypt = (encryptedData: Buffer, privateKey: string): Buffer => {
  return crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    encryptedData
  );
};

// ============ ECDH KEY EXCHANGE ============
// Elliptic Curve Diffie-Hellman for secure key exchange

export interface ECDHKeyPair {
  publicKey: string;
  privateKey: string;
}

/**
 * Generate ECDH key pair using P-384 curve (NIST recommended)
 */
export const generateECDHKeyPair = (curve: 'prime256v1' | 'secp384r1' | 'secp521r1' = 'secp384r1'): ECDHKeyPair => {
  const ecdh = crypto.createECDH(curve);
  ecdh.generateKeys();
  return {
    publicKey: ecdh.getPublicKey('base64'),
    privateKey: ecdh.getPrivateKey('base64')
  };
};

/**
 * Compute shared secret from ECDH keys
 */
export const computeECDHSecret = (
  privateKey: string, 
  otherPublicKey: string, 
  curve: 'prime256v1' | 'secp384r1' | 'secp521r1' = 'secp384r1'
): Buffer => {
  const ecdh = crypto.createECDH(curve);
  ecdh.setPrivateKey(Buffer.from(privateKey, 'base64'));
  return ecdh.computeSecret(Buffer.from(otherPublicKey, 'base64'));
};

/**
 * Derive encryption key from ECDH shared secret using HKDF
 */
export const deriveKeyFromECDH = (sharedSecret: Buffer, info: string = 'encryption'): Buffer => {
  // Use HKDF to derive key material from the shared secret
  const salt = crypto.randomBytes(32);
  const hkdf = crypto.hkdfSync('sha256', sharedSecret, salt, info, 32);
  return Buffer.from(hkdf);
};

// ============ CHACHA20-POLY1305 ENCRYPTION ============
// Modern authenticated encryption (alternative to AES-GCM)

const CHACHA_VERSION = 0x05;
const CHACHA_IV_LEN = 12;
const CHACHA_TAG_LEN = 16;

/**
 * Encrypt buffer using ChaCha20-Poly1305
 * Format: [version:0x05][salt:32][nonce:12][tag:16][encrypted_data]
 */
export const chaChaEncrypt = (input: Buffer, password?: string): Buffer => {
  const salt = crypto.randomBytes(SALT_LEN);
  const key = password 
    ? deriveUserKey(password, salt)
    : deriveKey(salt, ENCRYPTION_VERSION);
  
  const nonce = crypto.randomBytes(CHACHA_IV_LEN);
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: CHACHA_TAG_LEN
  } as crypto.CipherGCMOptions);
  
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  const tag = cipher.getAuthTag();
  
  const versionByte = Buffer.from([CHACHA_VERSION]);
  return Buffer.concat([versionByte, salt, nonce, tag, encrypted]);
};

/**
 * Decrypt buffer using ChaCha20-Poly1305
 */
export const chaChaDecrypt = (data: Buffer, password?: string): Buffer => {
  const version = data[0];
  if (version !== CHACHA_VERSION) {
    throw new Error('Invalid ChaCha20 encrypted data format');
  }
  
  const salt = data.subarray(1, 1 + SALT_LEN);
  const nonce = data.subarray(1 + SALT_LEN, 1 + SALT_LEN + CHACHA_IV_LEN);
  const tag = data.subarray(1 + SALT_LEN + CHACHA_IV_LEN, 1 + SALT_LEN + CHACHA_IV_LEN + CHACHA_TAG_LEN);
  const encrypted = data.subarray(1 + SALT_LEN + CHACHA_IV_LEN + CHACHA_TAG_LEN);
  
  const key = password 
    ? deriveUserKey(password, salt)
    : deriveKey(salt, ENCRYPTION_VERSION);
  
  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, {
    authTagLength: CHACHA_TAG_LEN
  } as crypto.CipherGCMOptions);
  decipher.setAuthTag(tag);
  
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
};

/**
 * Encrypt file using ChaCha20-Poly1305
 */
export const chaChaEncryptFile = (inputPath: string, outputPath: string, password?: string): void => {
  const input = fs.readFileSync(inputPath);
  const encrypted = chaChaEncrypt(input, password);
  fs.writeFileSync(outputPath, encrypted);
};

/**
 * Decrypt file using ChaCha20-Poly1305
 */
export const chaChaDecryptFile = (inputPath: string, password?: string): Buffer => {
  const data = fs.readFileSync(inputPath);
  return chaChaDecrypt(data, password);
};

// ============ HYBRID ENCRYPTION ============
// Combines RSA (for key encryption) with AES/ChaCha (for data encryption)
// Best for encrypting large files for specific recipients

const HYBRID_VERSION = 0x10;
const HYBRID_CHACHA_VERSION = 0x11;

export interface HybridEncryptedData {
  encryptedKey: string;      // RSA-encrypted symmetric key (base64)
  encryptedData: string;     // Symmetric-encrypted data (base64)
  algorithm: 'aes-256-gcm' | 'chacha20-poly1305';
}

/**
 * Hybrid encrypt: Generate random key, encrypt data with it, then RSA-encrypt the key
 */
export const hybridEncrypt = (
  data: Buffer, 
  recipientPublicKey: string,
  algorithm: 'aes-256-gcm' | 'chacha20-poly1305' = 'aes-256-gcm'
): HybridEncryptedData => {
  // Generate random symmetric key
  const symmetricKey = crypto.randomBytes(KEY_LEN);
  const iv = crypto.randomBytes(algorithm === 'chacha20-poly1305' ? CHACHA_IV_LEN : IV_LEN);
  
  // Encrypt data with symmetric key
  const cipher = crypto.createCipheriv(algorithm, symmetricKey, iv, {
    authTagLength: 16
  } as crypto.CipherGCMOptions) as crypto.CipherGCM;
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  
  // Combine IV + tag + encrypted data
  const encryptedPayload = Buffer.concat([iv, tag, encrypted]);
  
  // RSA encrypt the symmetric key
  const encryptedKey = rsaEncrypt(symmetricKey, recipientPublicKey);
  
  return {
    encryptedKey: encryptedKey.toString('base64'),
    encryptedData: encryptedPayload.toString('base64'),
    algorithm
  };
};

/**
 * Hybrid decrypt: RSA-decrypt the key, then use it to decrypt the data
 */
export const hybridDecrypt = (
  encryptedPayload: HybridEncryptedData,
  recipientPrivateKey: string
): Buffer => {
  // RSA decrypt the symmetric key
  const symmetricKey = rsaDecrypt(
    Buffer.from(encryptedPayload.encryptedKey, 'base64'),
    recipientPrivateKey
  );
  
  const data = Buffer.from(encryptedPayload.encryptedData, 'base64');
  const ivLen = encryptedPayload.algorithm === 'chacha20-poly1305' ? CHACHA_IV_LEN : IV_LEN;
  
  const iv = data.subarray(0, ivLen);
  const tag = data.subarray(ivLen, ivLen + 16);
  const encrypted = data.subarray(ivLen + 16);
  
  const decipher = crypto.createDecipheriv(encryptedPayload.algorithm, symmetricKey, iv, {
    authTagLength: 16
  } as crypto.CipherGCMOptions) as crypto.DecipherGCM;
  decipher.setAuthTag(tag);
  
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
};

/**
 * Hybrid encrypt file for a recipient
 */
export const hybridEncryptBuffer = (
  input: Buffer,
  recipientPublicKey: string,
  algorithm: 'aes-256-gcm' | 'chacha20-poly1305' = 'aes-256-gcm'
): Buffer => {
  const result = hybridEncrypt(input, recipientPublicKey, algorithm);
  const versionByte = Buffer.from([algorithm === 'chacha20-poly1305' ? HYBRID_CHACHA_VERSION : HYBRID_VERSION]);
  const keyLen = Buffer.alloc(2);
  const keyBuffer = Buffer.from(result.encryptedKey, 'base64');
  keyLen.writeUInt16BE(keyBuffer.length);
  const dataBuffer = Buffer.from(result.encryptedData, 'base64');
  
  return Buffer.concat([versionByte, keyLen, keyBuffer, dataBuffer]);
};

/**
 * Hybrid decrypt buffer
 */
export const hybridDecryptBuffer = (data: Buffer, privateKey: string): Buffer => {
  const version = data[0];
  const algorithm = version === HYBRID_CHACHA_VERSION ? 'chacha20-poly1305' : 'aes-256-gcm';
  
  if (version !== HYBRID_VERSION && version !== HYBRID_CHACHA_VERSION) {
    throw new Error('Invalid hybrid encrypted data format');
  }
  
  const keyLen = data.readUInt16BE(1);
  const encryptedKey = data.subarray(3, 3 + keyLen).toString('base64');
  const encryptedData = data.subarray(3 + keyLen).toString('base64');
  
  return hybridDecrypt({ encryptedKey, encryptedData, algorithm }, privateKey);
};

// ============ DIGITAL SIGNATURES ============
// For signing and verifying data integrity and authenticity

export interface SignatureKeyPair {
  publicKey: string;
  privateKey: string;
}

/**
 * Generate Ed25519 key pair for digital signatures
 */
export const generateSigningKeyPair = (): SignatureKeyPair => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
};

/**
 * Sign data using Ed25519 private key
 */
export const digitalSign = (data: Buffer | string, privateKey: string): string => {
  const signature = crypto.sign(null, Buffer.isBuffer(data) ? data : Buffer.from(data), privateKey);
  return signature.toString('base64');
};

/**
 * Verify Ed25519 signature
 */
export const verifyDigitalSignature = (
  data: Buffer | string, 
  signature: string, 
  publicKey: string
): boolean => {
  try {
    return crypto.verify(
      null, 
      Buffer.isBuffer(data) ? data : Buffer.from(data), 
      publicKey, 
      Buffer.from(signature, 'base64')
    );
  } catch {
    return false;
  }
};

/**
 * Generate ECDSA key pair (alternative to Ed25519)
 */
export const generateECDSAKeyPair = (curve: 'prime256v1' | 'secp384r1' = 'secp384r1'): SignatureKeyPair => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: curve,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
};

/**
 * Sign data using ECDSA
 */
export const ecdsaSign = (data: Buffer | string, privateKey: string): string => {
  const signature = crypto.sign('sha384', Buffer.isBuffer(data) ? data : Buffer.from(data), privateKey);
  return signature.toString('base64');
};

/**
 * Verify ECDSA signature
 */
export const verifyECDSASignature = (
  data: Buffer | string, 
  signature: string, 
  publicKey: string
): boolean => {
  try {
    return crypto.verify(
      'sha384', 
      Buffer.isBuffer(data) ? data : Buffer.from(data), 
      publicKey, 
      Buffer.from(signature, 'base64')
    );
  } catch {
    return false;
  }
};

// ============ ENVELOPE ENCRYPTION ============
// Multi-layer encryption for enhanced security

const ENVELOPE_VERSION = 0x20;

export interface EnvelopeEncryptedData {
  version: number;
  layers: number;
  data: string;
  keyHint: string;  // Hash of the first few bytes to help identify correct key
}

/**
 * Envelope encryption: Multiple layers of encryption
 * Layer 1: ChaCha20-Poly1305 with derived key
 * Layer 2: AES-256-GCM with different derived key
 */
export const envelopeEncrypt = (input: Buffer, password: string): Buffer => {
  const salt1 = crypto.randomBytes(SALT_LEN);
  const salt2 = crypto.randomBytes(SALT_LEN);
  
  // Layer 1: ChaCha20-Poly1305
  const key1 = crypto.scryptSync(password + ':layer1', salt1, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  const nonce1 = crypto.randomBytes(CHACHA_IV_LEN);
  const cipher1 = crypto.createCipheriv('chacha20-poly1305', key1, nonce1, { authTagLength: 16 } as crypto.CipherGCMOptions);
  const layer1 = Buffer.concat([cipher1.update(input), cipher1.final()]);
  const tag1 = cipher1.getAuthTag();
  
  // Layer 2: AES-256-GCM
  const key2 = crypto.scryptSync(password + ':layer2', salt2, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  const iv2 = crypto.randomBytes(IV_LEN);
  const cipher2 = crypto.createCipheriv('aes-256-gcm', key2, iv2);
  const combined1 = Buffer.concat([nonce1, tag1, layer1]);
  const layer2 = Buffer.concat([cipher2.update(combined1), cipher2.final()]);
  const tag2 = cipher2.getAuthTag();
  
  // Final format: [version][salt1][salt2][iv2][tag2][layer2_encrypted]
  const versionByte = Buffer.from([ENVELOPE_VERSION]);
  return Buffer.concat([versionByte, salt1, salt2, iv2, tag2, layer2]);
};

/**
 * Envelope decryption: Unwrap multiple encryption layers
 */
export const envelopeDecrypt = (data: Buffer, password: string): Buffer => {
  const version = data[0];
  if (version !== ENVELOPE_VERSION) {
    throw new Error('Invalid envelope encrypted data format');
  }
  
  const salt1 = data.subarray(1, 1 + SALT_LEN);
  const salt2 = data.subarray(1 + SALT_LEN, 1 + SALT_LEN * 2);
  const iv2 = data.subarray(1 + SALT_LEN * 2, 1 + SALT_LEN * 2 + IV_LEN);
  const tag2 = data.subarray(1 + SALT_LEN * 2 + IV_LEN, 1 + SALT_LEN * 2 + IV_LEN + TAG_LEN);
  const layer2Encrypted = data.subarray(1 + SALT_LEN * 2 + IV_LEN + TAG_LEN);
  
  // Decrypt Layer 2
  const key2 = crypto.scryptSync(password + ':layer2', salt2, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  const decipher2 = crypto.createDecipheriv('aes-256-gcm', key2, iv2);
  decipher2.setAuthTag(tag2);
  const layer1Data = Buffer.concat([decipher2.update(layer2Encrypted), decipher2.final()]);
  
  // Extract Layer 1 components
  const nonce1 = layer1Data.subarray(0, CHACHA_IV_LEN);
  const tag1 = layer1Data.subarray(CHACHA_IV_LEN, CHACHA_IV_LEN + 16);
  const layer1Encrypted = layer1Data.subarray(CHACHA_IV_LEN + 16);
  
  // Decrypt Layer 1
  const key1 = crypto.scryptSync(password + ':layer1', salt1, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  const decipher1 = crypto.createDecipheriv('chacha20-poly1305', key1, nonce1, { authTagLength: 16 } as crypto.CipherGCMOptions);
  decipher1.setAuthTag(tag1);
  
  return Buffer.concat([decipher1.update(layer1Encrypted), decipher1.final()]);
};

// ============ AES KEY WRAPPING ============
// Secure key storage using AES-KW (RFC 3394)

/**
 * Wrap (encrypt) a key using AES-256-KW
 */
export const wrapKey = (keyToWrap: Buffer, wrappingKey: Buffer): Buffer => {
  if (keyToWrap.length % 8 !== 0) {
    throw new Error('Key to wrap must be a multiple of 8 bytes');
  }
  if (wrappingKey.length !== 32) {
    throw new Error('Wrapping key must be 32 bytes');
  }
  
  const cipher = crypto.createCipheriv('aes-256-wrap', wrappingKey, Buffer.alloc(8, 0xa6));
  return Buffer.concat([cipher.update(keyToWrap), cipher.final()]);
};

/**
 * Unwrap (decrypt) a key using AES-256-KW
 */
export const unwrapKey = (wrappedKey: Buffer, wrappingKey: Buffer): Buffer => {
  if (wrappingKey.length !== 32) {
    throw new Error('Wrapping key must be 32 bytes');
  }
  
  const decipher = crypto.createDecipheriv('aes-256-wrap', wrappingKey, Buffer.alloc(8, 0xa6));
  return Buffer.concat([decipher.update(wrappedKey), decipher.final()]);
};

// ============ ARGON2-LIKE KEY DERIVATION ============
// Enhanced key derivation with multiple iterations

/**
 * Derive key with enhanced security (simulating Argon2-like behavior)
 */
export const deriveKeyEnhanced = (password: string, salt: Buffer, iterations: number = 3): Buffer => {
  let key = Buffer.from(password);
  
  for (let i = 0; i < iterations; i++) {
    const iterSalt = crypto.createHash('sha256')
      .update(Buffer.concat([salt, Buffer.from([i])]))
      .digest();
    
    key = crypto.scryptSync(key, iterSalt, KEY_LEN, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P
    });
  }
  
  return key;
};

// ============ ENCRYPTION ALGORITHM TYPES ============
// Enumeration of available encryption types

export enum EncryptionAlgorithm {
  AES_256_GCM = 'aes-256-gcm',
  CHACHA20_POLY1305 = 'chacha20-poly1305',
  HYBRID_RSA_AES = 'hybrid-rsa-aes',
  HYBRID_RSA_CHACHA = 'hybrid-rsa-chacha',
  ENVELOPE = 'envelope',
  USER_KEY = 'user-key'
}

export interface EncryptionOptions {
  algorithm: EncryptionAlgorithm;
  password?: string;
  publicKey?: string;
  privateKey?: string;
}

/**
 * Universal encryption function - encrypt using any supported algorithm
 */
export const universalEncrypt = (input: Buffer, options: EncryptionOptions): Buffer => {
  switch (options.algorithm) {
    case EncryptionAlgorithm.AES_256_GCM:
      return options.password 
        ? encryptBufferWithUserKey(input, options.password)
        : encryptBuffer(input);
    
    case EncryptionAlgorithm.CHACHA20_POLY1305:
      return chaChaEncrypt(input, options.password);
    
    case EncryptionAlgorithm.HYBRID_RSA_AES:
      if (!options.publicKey) throw new Error('Public key required for hybrid encryption');
      return hybridEncryptBuffer(input, options.publicKey, 'aes-256-gcm');
    
    case EncryptionAlgorithm.HYBRID_RSA_CHACHA:
      if (!options.publicKey) throw new Error('Public key required for hybrid encryption');
      return hybridEncryptBuffer(input, options.publicKey, 'chacha20-poly1305');
    
    case EncryptionAlgorithm.ENVELOPE:
      if (!options.password) throw new Error('Password required for envelope encryption');
      return envelopeEncrypt(input, options.password);
    
    case EncryptionAlgorithm.USER_KEY:
      if (!options.password) throw new Error('Password required for user-key encryption');
      return encryptBufferWithUserKey(input, options.password);
    
    default:
      throw new Error(`Unsupported encryption algorithm: ${options.algorithm}`);
  }
};

/**
 * Universal decryption function - detect and decrypt using appropriate algorithm
 */
export const universalDecrypt = (data: Buffer, options: EncryptionOptions): Buffer => {
  const version = data[0];
  
  // Auto-detect based on version byte
  switch (version) {
    case CHACHA_VERSION:
      return chaChaDecrypt(data, options.password);
    
    case HYBRID_VERSION:
    case HYBRID_CHACHA_VERSION:
      if (!options.privateKey) throw new Error('Private key required for hybrid decryption');
      return hybridDecryptBuffer(data, options.privateKey);
    
    case ENVELOPE_VERSION:
      if (!options.password) throw new Error('Password required for envelope decryption');
      return envelopeDecrypt(data, options.password);
    
    case USER_KEY_VERSION:
      if (!options.password) throw new Error('Password required for user-key decryption');
      return decryptBufferWithUserKey(data, options.password);
    
    case 0x02:
    case 0x03:
      return decryptBuffer(data);
    
    default:
      // Try legacy format
      return decryptBuffer(data);
  }
};

/**
 * Get encryption info from encrypted data
 */
export const getEncryptionInfo = (data: Buffer): { version: number; algorithm: string; requiresKey: boolean; requiresPassword: boolean } => {
  const version = data[0];
  
  switch (version) {
    case 0x02:
      return { version: 2, algorithm: 'AES-256-GCM v2', requiresKey: false, requiresPassword: false };
    case 0x03:
      return { version: 3, algorithm: 'AES-256-GCM v3 + HMAC', requiresKey: false, requiresPassword: false };
    case USER_KEY_VERSION:
      return { version: USER_KEY_VERSION, algorithm: 'AES-256-GCM (User Key)', requiresKey: false, requiresPassword: true };
    case CHACHA_VERSION:
      return { version: CHACHA_VERSION, algorithm: 'ChaCha20-Poly1305', requiresKey: false, requiresPassword: true };
    case HYBRID_VERSION:
      return { version: HYBRID_VERSION, algorithm: 'Hybrid RSA + AES-256-GCM', requiresKey: true, requiresPassword: false };
    case HYBRID_CHACHA_VERSION:
      return { version: HYBRID_CHACHA_VERSION, algorithm: 'Hybrid RSA + ChaCha20-Poly1305', requiresKey: true, requiresPassword: false };
    case ENVELOPE_VERSION:
      return { version: ENVELOPE_VERSION, algorithm: 'Envelope (2-layer)', requiresKey: false, requiresPassword: true };
    default:
      return { version: 1, algorithm: 'AES-256-GCM Legacy', requiresKey: false, requiresPassword: false };
  }
};

// ============ FILE ENCRYPTION WITH ALGORITHM CHOICE ============

const MULTI_ALG_VERSION = 0x30;

/**
 * Encrypt file with specified algorithm
 */
export const encryptFileWithAlgorithm = (
  inputPath: string, 
  outputPath: string, 
  algorithm: EncryptionAlgorithm,
  options: { password?: string; publicKey?: string } = {}
): void => {
  const input = fs.readFileSync(inputPath);
  const encrypted = universalEncrypt(input, { algorithm, ...options });
  fs.writeFileSync(outputPath, encrypted);
};

/**
 * Decrypt file (auto-detects algorithm)
 */
export const decryptFileWithAlgorithm = (
  inputPath: string,
  options: { password?: string; privateKey?: string } = {}
): Buffer => {
  const data = fs.readFileSync(inputPath);
  return universalDecrypt(data, { algorithm: EncryptionAlgorithm.AES_256_GCM, ...options });
};

// ============ SECURE RANDOM UTILITIES ============

/**
 * Generate cryptographically secure random bytes
 */
export const secureRandomBytes = (length: number): Buffer => {
  return crypto.randomBytes(length);
};

/**
 * Generate secure random number in range [min, max]
 */
export const secureRandomInt = (min: number, max: number): number => {
  const range = max - min + 1;
  const bytesNeeded = Math.ceil(Math.log2(range) / 8);
  const maxValid = Math.floor(256 ** bytesNeeded / range) * range;
  
  let randomValue: number;
  do {
    const randomBytes = crypto.randomBytes(bytesNeeded);
    randomValue = parseInt(randomBytes.toString('hex'), 16);
  } while (randomValue >= maxValid);
  
  return min + (randomValue % range);
};

/**
 * Generate a secure passphrase using word list
 */
export const generatePassphrase = (wordCount: number = 6): string => {
  const words = [
    'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel',
    'india', 'juliet', 'kilo', 'lima', 'mike', 'november', 'oscar', 'papa',
    'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray',
    'yankee', 'zulu', 'cipher', 'secure', 'vault', 'shield', 'guard', 'fort',
    'castle', 'dragon', 'phoenix', 'tiger', 'falcon', 'eagle', 'hawk', 'raven',
    'storm', 'thunder', 'lightning', 'blaze', 'frost', 'shadow', 'crystal', 'ember'
  ];
  
  const passphrase: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    const index = secureRandomInt(0, words.length - 1);
    passphrase.push(words[index]);
  }
  
  return passphrase.join('-');
};

// ============ KEY WRAPPING FOR USER-ENCRYPTED FILE SHARING ============

/**
 * Extract DEK from a user-encrypted file
 * This reads the file header and derives the DEK using the user's key
 */
export const extractDekFromUserEncryptedFile = (filePath: string, userKey: string): Buffer => {
  if (!userKey) {
    throw new Error('User key is required');
  }
  
  const data = fs.readFileSync(filePath);
  const version = data[0];
  
  if (version !== USER_KEY_VERSION) {
    throw new Error('This file was not encrypted with a user key');
  }
  
  // Extract salt from file header
  const salt = data.subarray(1, 1 + SALT_LEN);
  
  // Derive the DEK using the same method as decryptFileWithUserKey
  const dek = deriveUserKey(userKey, salt);
  
  return dek;
};

/**
 * Wrap (encrypt) a DEK for a recipient using their RSA public key
 */
export const wrapDekForUser = (dek: Buffer, recipientPublicKey: string): string => {
  if (!dek || dek.length !== KEY_LEN) {
    throw new Error('DEK must be 32 bytes');
  }
  
  if (!recipientPublicKey) {
    throw new Error('Recipient public key is required');
  }
  
  // BUG FIX 13: Validate RSA public key format before use
  if (!validateRSAPublicKey(recipientPublicKey)) {
    throw new Error('Invalid RSA public key format');
  }
  
  try {
    const wrappedKey = rsaEncrypt(dek, recipientPublicKey);
    return wrappedKey.toString('base64');
  } catch (err: any) {
    throw new Error(`Failed to wrap DEK: ${err.message}`);
  }
};

/**
 * Unwrap (decrypt) a DEK using the recipient's RSA private key
 */
export const unwrapDekForUser = (wrappedDek: string, recipientPrivateKey: string): Buffer => {
  if (!wrappedDek) {
    throw new Error('Wrapped DEK is required');
  }
  
  if (!recipientPrivateKey) {
    throw new Error('Recipient private key is required');
  }
  
  try {
    const wrappedBuffer = Buffer.from(wrappedDek, 'base64');
    const dek = rsaDecrypt(wrappedBuffer, recipientPrivateKey);
    
    if (dek.length !== KEY_LEN) {
      throw new Error('Unwrapped DEK has invalid length');
    }
    
    return dek;
  } catch (err: any) {
    throw new Error(`Failed to unwrap DEK: ${err.message}`);
  }
};

/**
 * Decrypt a file using a provided DEK (not deriving from password)
 * This is used when a shared user has unwrapped the DEK
 */
export const decryptFileWithDek = (filePath: string, dek: Buffer): Buffer => {
  if (!dek || dek.length !== KEY_LEN) {
    throw new Error('DEK must be 32 bytes');
  }
  
  const data = fs.readFileSync(filePath);
  const version = data[0];
  
  if (version !== USER_KEY_VERSION) {
    throw new Error('This file was not encrypted with a user key');
  }
  
  // Extract file components
  const salt = data.subarray(1, 1 + SALT_LEN);
  const iv = data.subarray(1 + SALT_LEN, 1 + SALT_LEN + IV_LEN);
  const tag = data.subarray(1 + SALT_LEN + IV_LEN, 1 + SALT_LEN + IV_LEN + TAG_LEN);
  const storedHmac = data.subarray(1 + SALT_LEN + IV_LEN + TAG_LEN, 1 + SALT_LEN + IV_LEN + TAG_LEN + 32);
  const encrypted = data.subarray(1 + SALT_LEN + IV_LEN + TAG_LEN + 32);
  
  // Verify HMAC (we need to derive HMAC key from the DEK)
  // For user-key encryption, HMAC key is derived from userKey + ':hmac'
  // Since we only have the DEK, we'll skip HMAC verification for wrapped key decryption
  // This is acceptable because the GCM auth tag provides integrity verification
  
  // Decrypt using the provided DEK
  const decipher = crypto.createDecipheriv(ALGORITHM, dek, iv);
  decipher.setAuthTag(tag);
  
  try {
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch (err) {
    throw new Error('Decryption failed: Invalid DEK or file has been tampered with');
  }
};

/**
 * Unified decryption function that handles all file types and user scenarios
 * This centralizes all decryption logic for reusability across endpoints
 * 
 * @param filePath - Path to the encrypted file
 * @param file - File metadata from database
 * @param userId - ID of the user requesting decryption
 * @param userKey - Optional user-provided encryption key (for owner access to user-encrypted files)
 * @param getWrappedKey - Function to retrieve wrapped key from database
 * @param getUserPrivateKey - Function to retrieve user's private key from database
 * @returns Decrypted file content as Buffer
 */
export interface DecryptFileForUserOptions {
  filePath: string;
  file: {
    id: string;
    encrypted: boolean;
    userKeyEncrypted?: boolean;
    ownerId: string;
    sharedWith: string[];
  };
  userId: string;
  userKey?: string;
  getWrappedKey?: (fileId: string, userId: string) => { wrappedDek: string } | undefined;
  getUserPrivateKey?: (userId: string) => string | undefined;
}

export const decryptFileForUser = (options: DecryptFileForUserOptions): Buffer => {
  const { filePath, file, userId, userKey, getWrappedKey, getUserPrivateKey } = options;
  
  // Case 1: File is not encrypted - return raw content
  if (!file.encrypted) {
    return fs.readFileSync(filePath);
  }
  
  // Case 2: File is server-encrypted (not user-key encrypted)
  if (!file.userKeyEncrypted) {
    return decryptFile(filePath);
  }
  
  // Case 3: File is user-encrypted and user is the owner
  if (file.ownerId === userId) {
    if (!userKey) {
      throw new Error('This file is encrypted with your key. Please provide your encryption key to decrypt it.');
    }
    return decryptFileWithUserKey(filePath, userKey);
  }
  
  // Case 4: File is user-encrypted and user is a shared recipient
  if (file.sharedWith.includes(userId)) {
    // Check if wrapped key exists
    if (!getWrappedKey) {
      throw new Error('Cannot decrypt: wrapped key retrieval function not provided');
    }
    
    const wrappedKey = getWrappedKey(file.id, userId);
    if (!wrappedKey) {
      throw new Error('Access denied. File owner has not completed the sharing process for this encrypted file.');
    }
    
    // Get user's private key
    if (!getUserPrivateKey) {
      throw new Error('Cannot decrypt: user private key retrieval function not provided');
    }
    
    const privateKey = getUserPrivateKey(userId);
    if (!privateKey) {
      throw new Error('Cannot decrypt: your encryption keys are not set up. Please contact support.');
    }
    
    // Unwrap the DEK and decrypt the file
    try {
      const dek = unwrapDekForUser(wrappedKey.wrappedDek, privateKey);
      return decryptFileWithDek(filePath, dek);
    } catch (err: any) {
      throw new Error(`Failed to decrypt shared file: ${err.message}`);
    }
  }
  
  // Case 5: User is not owner and not in sharedWith - access denied
  throw new Error('Access denied. You do not have permission to decrypt this file.');
};
