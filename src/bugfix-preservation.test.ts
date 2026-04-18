/**
 * Preservation Property Tests for Secure File Sharing Decryption
 * 
 * **Validates: Requirements 3.1, 3.2, 3.3, 3.4**
 * 
 * These tests MUST PASS on unfixed code - they confirm baseline behavior to preserve.
 * They verify that server-encrypted files, unencrypted files, and owner access to
 * user-encrypted files continue to work correctly after the fix.
 * 
 * IMPORTANT: Follow observation-first methodology
 * - These tests observe behavior on UNFIXED code for non-buggy inputs
 * - They capture the current working behavior that must be preserved
 * - Property-based testing generates many test cases for stronger guarantees
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { db } from './db';
import { Role, User, FileRecord, FileStatus, Session } from './types';
import { encryptFile, encryptFileWithUserKey, decryptFileWithUserKey } from './crypto';
import { v4 as uuid } from 'uuid';
import fs from 'fs';
import path from 'path';
import express, { Express } from 'express';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { config } from './config';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import routes from './routes';
import { errorHandler, securityHeaders, requestLogger, corsOptions } from './middleware';
import * as fc from 'fast-check';

describe('Preservation Properties: Server-Encrypted and Unencrypted File Sharing', () => {
  let app: Express;
  let testUsers: Map<string, { user: User; session: Session; token: string }>;
  let testFiles: FileRecord[];

  beforeAll(async () => {
    // Setup Express app with all middleware (matching app.ts)
    app = express();
    app.use(securityHeaders);
    app.use(requestLogger);
    app.use(cors(corsOptions));
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    app.use('/api', routes);
    app.use(errorHandler);

    testUsers = new Map();
    testFiles = [];
  });

  beforeEach(() => {
    // Clear test data before each test
    testUsers.clear();
    testFiles = [];
  });

  afterAll(() => {
    // Cleanup all test files
    for (const file of testFiles) {
      const filePath = path.join(config.uploadDir, file.storedName);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }

    // Cleanup sessions
    for (const [, userData] of testUsers) {
      try {
        db.deleteSession(userData.session.id);
      } catch (e) {
        // Ignore cleanup errors
      }
    }
  });

  /**
   * Helper function to create a test user with session and token
   */
  async function createTestUser(username: string, role: Role = Role.EDITOR): Promise<{ user: User; session: Session; token: string }> {
    const user: User = {
      id: uuid(),
      username,
      email: `${username}@test.com`,
      password: await bcrypt.hash('password123', 12),
      role,
      createdAt: new Date(),
      twoFactorEnabled: false,
      storageQuota: 1024 * 1024 * 100, // 100MB
      storageUsed: 0,
      failedLoginAttempts: 0,
      encryptionKeyVersion: 3,
      preferences: {
        emailNotifications: true,
        theme: 'dark',
        defaultEncrypt: true,
        autoLockMinutes: 30,
        showFileExtensions: true,
      },
    };

    db.createUser(user);

    const session: Session = {
      id: uuid(),
      userId: user.id,
      token: `test-token-${username}`,
      userAgent: 'test-agent',
      ipAddress: '127.0.0.1',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      lastActiveAt: new Date(),
    };

    db.createSession(session);

    const token = jwt.sign({ userId: user.id, role: user.role, sessionId: session.id }, config.jwtSecret, { expiresIn: '1h' });

    const userData = { user, session, token };
    testUsers.set(username, userData);
    return userData;
  }

  /**
   * Helper function to create a server-encrypted file
   */
  function createServerEncryptedFile(ownerId: string, sharedWith: string[] = []): FileRecord {
    const originalContent = `Server-encrypted content ${uuid()}`;
    const originalPath = path.join(config.uploadDir, `test-original-${uuid()}.txt`);
    const encryptedPath = path.join(config.uploadDir, `${uuid()}.enc`);

    fs.writeFileSync(originalPath, originalContent);
    encryptFile(originalPath, encryptedPath);
    fs.unlinkSync(originalPath);

    const file: FileRecord = {
      id: uuid(),
      name: `server-encrypted-${uuid()}.txt`,
      storedName: path.basename(encryptedPath),
      size: fs.statSync(encryptedPath).size,
      mimeType: 'text/plain',
      ownerId,
      encrypted: true,
      userKeyEncrypted: false, // Server-encrypted
      checksum: 'test-checksum',
      encryptionVersion: 3,
      createdAt: new Date(),
      status: FileStatus.ACTIVE,
      tags: [],
      version: 1,
      favoriteOf: [],
      sharedWith,
      downloadCount: 0,
    };

    db.createFile(file);
    testFiles.push(file);

    return file;
  }

  /**
   * Helper function to create an unencrypted file
   */
  function createUnencryptedFile(ownerId: string, sharedWith: string[] = []): FileRecord {
    const content = `Unencrypted content ${uuid()}`;
    const filePath = path.join(config.uploadDir, `${uuid()}.txt`);

    fs.writeFileSync(filePath, content);

    const file: FileRecord = {
      id: uuid(),
      name: `unencrypted-${uuid()}.txt`,
      storedName: path.basename(filePath),
      size: fs.statSync(filePath).size,
      mimeType: 'text/plain',
      ownerId,
      encrypted: false,
      userKeyEncrypted: false,
      checksum: 'test-checksum',
      encryptionVersion: 3,
      createdAt: new Date(),
      status: FileStatus.ACTIVE,
      tags: [],
      version: 1,
      favoriteOf: [],
      sharedWith,
      downloadCount: 0,
    };

    db.createFile(file);
    testFiles.push(file);

    return file;
  }

  /**
   * Helper function to create a user-encrypted file
   */
  function createUserEncryptedFile(ownerId: string, userKey: string, sharedWith: string[] = []): FileRecord {
    const originalContent = `User-encrypted content ${uuid()}`;
    const originalPath = path.join(config.uploadDir, `test-original-${uuid()}.txt`);
    const encryptedPath = path.join(config.uploadDir, `${uuid()}.enc`);

    fs.writeFileSync(originalPath, originalContent);
    encryptFileWithUserKey(originalPath, encryptedPath, userKey);
    fs.unlinkSync(originalPath);

    const file: FileRecord = {
      id: uuid(),
      name: `user-encrypted-${uuid()}.txt`,
      storedName: path.basename(encryptedPath),
      size: fs.statSync(encryptedPath).size,
      mimeType: 'text/plain',
      ownerId,
      encrypted: true,
      userKeyEncrypted: true, // User-encrypted
      checksum: 'test-checksum',
      encryptionVersion: 4,
      createdAt: new Date(),
      status: FileStatus.ACTIVE,
      tags: [],
      version: 1,
      favoriteOf: [],
      sharedWith,
      downloadCount: 0,
    };

    db.createFile(file);
    testFiles.push(file);

    return file;
  }

  describe('Property 2.1: Server-Encrypted File Sharing - Owner Access', () => {
    it('should allow file owner to decrypt their own server-encrypted files', async () => {
      /**
       * Property: For all server-encrypted files, the owner can decrypt and access the content.
       * 
       * This test MUST PASS on unfixed code - it confirms baseline behavior.
       * 
       * NOTE: Current code does NOT check sharedWith array, so we test owner access only.
       */

      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 0, max: 3 }), // Number of users in sharedWith (not actually checked by current code)
          async (numSharedUsers) => {
            // Create owner
            const owner = await createTestUser(`owner-${uuid().substring(0, 8)}`);

            // Create shared users (for database state, even though not checked)
            const sharedUserIds = await Promise.all(
              Array.from({ length: numSharedUsers }, async (_, i) => {
                const u = await createTestUser(`shared-${uuid().substring(0, 8)}-${i}`);
                return u.user.id;
              })
            );

            // Create server-encrypted file
            const file = createServerEncryptedFile(owner.user.id, sharedUserIds);

            // Owner should be able to download the decrypted file
            const response = await request(app)
              .get(`/api/files/${file.id}/download-decrypted`)
              .set('Authorization', `Bearer ${owner.token}`);

            // Assertions: owner can access their own file
            expect(response.status).toBe(200);
            expect(response.headers['x-file-decrypted']).toBe('true');
            expect(response.text).toBeTruthy();
            expect(response.text.length).toBeGreaterThan(0);
          }
        ),
        { numRuns: 5 } // Run 5 times with different configurations
      );
    });

    it('should use server master key for decryption of server-encrypted files', async () => {
      /**
       * Property: Server-encrypted files are decrypted using the server's master key,
       * not requiring any user-provided key.
       * 
       * This test MUST PASS on unfixed code.
       */

      const owner = await createTestUser(`owner-${uuid().substring(0, 8)}`);

      const file = createServerEncryptedFile(owner.user.id, []);

      // Owner downloads without providing any user key
      const response = await request(app)
        .get(`/api/files/${file.id}/download-decrypted`)
        .set('Authorization', `Bearer ${owner.token}`);

      expect(response.status).toBe(200);
      expect(response.headers['x-file-decrypted']).toBe('true');
      // No user key was provided, yet decryption succeeded
    });
  });

  describe('Property 2.2: Unencrypted File Access - Owner Access', () => {
    it('should allow file owner to access their own unencrypted files directly', async () => {
      /**
       * Property: For all unencrypted files, the owner can access the content directly.
       * 
       * This test MUST PASS on unfixed code.
       * 
       * NOTE: Current code does NOT check sharedWith array, so we test owner access only.
       */

      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 0, max: 3 }), // Number of users in sharedWith (not actually checked)
          async (numSharedUsers) => {
            // Create owner
            const owner = await createTestUser(`owner-${uuid().substring(0, 8)}`);

            // Create shared users (for database state)
            const sharedUserIds = await Promise.all(
              Array.from({ length: numSharedUsers }, async (_, i) => {
                const u = await createTestUser(`shared-${uuid().substring(0, 8)}-${i}`);
                return u.user.id;
              })
            );

            // Create unencrypted file
            const file = createUnencryptedFile(owner.user.id, sharedUserIds);

            // Owner should be able to download the file
            const response = await request(app)
              .get(`/api/files/${file.id}/download`)
              .set('Authorization', `Bearer ${owner.token}`);

            // Assertions: owner can access their own file
            expect(response.status).toBe(200);
            expect(response.text).toBeTruthy();
            expect(response.text.length).toBeGreaterThan(0);
          }
        ),
        { numRuns: 5 }
      );
    });

    it('should not perform decryption for unencrypted files', async () => {
      /**
       * Property: Unencrypted files are served directly without any decryption process.
       * 
       * This test MUST PASS on unfixed code.
       */

      const owner = await createTestUser(`owner-${uuid().substring(0, 8)}`);

      const file = createUnencryptedFile(owner.user.id, []);

      // Download should succeed and file should not be marked as decrypted
      const response = await request(app)
        .get(`/api/files/${file.id}/download`)
        .set('Authorization', `Bearer ${owner.token}`);

      expect(response.status).toBe(200);
      // For unencrypted files, the x-file-decrypted header should not be set or be 'false'
      expect(response.headers['x-file-decrypted']).not.toBe('true');
    });
  });

  describe('Property 2.3: Owner Access to User-Encrypted Files', () => {
    it('should allow owner to decrypt user-encrypted files when providing their key', async () => {
      /**
       * Property: File owners can decrypt their own user-encrypted files by providing their encryption key.
       * 
       * This test MUST PASS on both unfixed and fixed code - it confirms baseline behavior.
       * 
       * After the fix, owners can provide their key via query parameter to decrypt.
       */

      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 8, maxLength: 32 }), // User encryption key
          async (userKey) => {
            // Create owner
            const owner = await createTestUser(`owner-${uuid().substring(0, 8)}`);

            // Create user-encrypted file (not shared)
            const file = createUserEncryptedFile(owner.user.id, userKey, []);

            // Owner attempts to decrypt with their key (via query parameter)
            const response = await request(app)
              .get(`/api/files/${file.id}/download-decrypted`)
              .query({ userKey }) // Provide the user key
              .set('Authorization', `Bearer ${owner.token}`);

            // Owner should be able to decrypt with their key
            expect(response.status).toBe(200);
            expect(response.text).toBeTruthy();
            expect(response.text.length).toBeGreaterThan(0);
          }
        ),
        { numRuns: 5 }
      );
    });

    it('should require user key for owner to decrypt user-encrypted files', async () => {
      /**
       * Property: User-encrypted files require the owner to provide their encryption key.
       * 
       * This test MUST PASS on both unfixed and fixed code.
       */

      const owner = await createTestUser(`owner-${uuid().substring(0, 8)}`);
      const userKey = 'testKey123456';

      const file = createUserEncryptedFile(owner.user.id, userKey, []);

      // Without providing the key, owner should get an error
      const responseWithoutKey = await request(app)
        .get(`/api/files/${file.id}/download-decrypted`)
        .set('Authorization', `Bearer ${owner.token}`);

      // Should fail without key
      expect(responseWithoutKey.status).toBe(500);
      expect(responseWithoutKey.text).toContain('encryption key');
    });
  });

  describe('Property 2.4: File Access Control - Shared Users', () => {
    it('should allow shared users to access server-encrypted files', async () => {
      /**
       * Property: Shared users can access server-encrypted files.
       * 
       * This test verifies that the fix allows shared users to access files,
       * which is the intended behavior after the fix.
       */

      const owner = await createTestUser(`owner-${uuid().substring(0, 8)}`);
      const sharedUser = await createTestUser(`shared-${uuid().substring(0, 8)}`);

      // Create server-encrypted file with sharedUser in sharedWith
      const file = createServerEncryptedFile(owner.user.id, [sharedUser.user.id]);

      // Shared user should have access (after fix)
      const response = await request(app)
        .get(`/api/files/${file.id}/download-decrypted`)
        .set('Authorization', `Bearer ${sharedUser.token}`);

      // After fix: 200 success (shared users can access)
      expect(response.status).toBe(200);
      expect(response.text).toBeTruthy();
    });

    it('should deny access to non-shared users for server-encrypted files', async () => {
      /**
       * Property: Non-shared users cannot access files.
       * 
       * This test MUST PASS on both unfixed and fixed code.
       */

      const owner = await createTestUser(`owner-${uuid().substring(0, 8)}`);
      const otherUser = await createTestUser(`other-${uuid().substring(0, 8)}`);

      // Create server-encrypted file WITHOUT otherUser in sharedWith
      const file = createServerEncryptedFile(owner.user.id, []);

      // Other user should NOT have access
      const response = await request(app)
        .get(`/api/files/${file.id}/download-decrypted`)
        .set('Authorization', `Bearer ${otherUser.token}`);

      // Should be denied
      expect(response.status).toBe(403);
    });
  });
});
