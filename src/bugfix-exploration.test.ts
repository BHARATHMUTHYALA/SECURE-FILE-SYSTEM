/**
 * Bug Condition Exploration Test for Secure File Sharing Decryption
 * 
 * **Validates: Requirements 1.1, 1.2, 1.3, 2.1, 2.2, 2.3**
 * 
 * This test MUST FAIL on unfixed code - failure confirms the bug exists.
 * DO NOT attempt to fix the test or the code when it fails.
 * 
 * The test encodes the expected behavior - it will validate the fix when it passes after implementation.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { db } from './db';
import { Role, User, FileRecord, FileStatus, Session, WrappedKey } from './types';
import { encryptFileWithUserKey, generateRSAKeyPair, extractDekFromUserEncryptedFile, wrapDekForUser } from './crypto';
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

describe('Bug Condition Exploration: Shared User Cannot Decrypt User-Encrypted Files', () => {
  let app: Express;
  let userA: User;
  let userB: User;
  let sessionA: Session;
  let sessionB: Session;
  let tokenA: string;
  let tokenB: string;
  let testFile: FileRecord;
  let testFilePath: string;
  let encryptedFilePath: string;
  const userEncryptionKey = 'testKey123456';
  const originalContent = 'This is secret content that should be shared';

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

    // Create test users
    const keyPairA = generateRSAKeyPair(2048);
    const keyPairB = generateRSAKeyPair(2048);
    
    userA = {
      id: uuid(),
      username: 'alice',
      email: 'alice@test.com',
      password: await bcrypt.hash('password123', 12),
      role: Role.EDITOR,
      createdAt: new Date(),
      twoFactorEnabled: false,
      storageQuota: 1024 * 1024 * 100, // 100MB
      storageUsed: 0,
      failedLoginAttempts: 0,
      encryptionKeyVersion: 3,
      publicKey: keyPairA.publicKey,
      privateKey: keyPairA.privateKey,
      preferences: {
        emailNotifications: true,
        theme: 'dark',
        defaultEncrypt: true,
        autoLockMinutes: 30,
        showFileExtensions: true,
      },
    };

    userB = {
      id: uuid(),
      username: 'bob',
      email: 'bob@test.com',
      password: await bcrypt.hash('password123', 12),
      role: Role.EDITOR,
      createdAt: new Date(),
      twoFactorEnabled: false,
      storageQuota: 1024 * 1024 * 100,
      storageUsed: 0,
      failedLoginAttempts: 0,
      encryptionKeyVersion: 3,
      publicKey: keyPairB.publicKey,
      privateKey: keyPairB.privateKey,
      preferences: {
        emailNotifications: true,
        theme: 'dark',
        defaultEncrypt: true,
        autoLockMinutes: 30,
        showFileExtensions: true,
      },
    };

    db.createUser(userA);
    db.createUser(userB);

    // Create sessions for both users
    sessionA = {
      id: uuid(),
      userId: userA.id,
      token: 'test-token-a',
      userAgent: 'test-agent',
      ipAddress: '127.0.0.1',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      lastActiveAt: new Date(),
    };

    sessionB = {
      id: uuid(),
      userId: userB.id,
      token: 'test-token-b',
      userAgent: 'test-agent',
      ipAddress: '127.0.0.1',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      lastActiveAt: new Date(),
    };

    db.createSession(sessionA);
    db.createSession(sessionB);

    // Generate JWT tokens for both users
    tokenA = jwt.sign({ userId: userA.id, role: userA.role, sessionId: sessionA.id }, config.jwtSecret, { expiresIn: '1h' });
    tokenB = jwt.sign({ userId: userB.id, role: userB.role, sessionId: sessionB.id }, config.jwtSecret, { expiresIn: '1h' });

    // Create a test file with user-key encryption
    testFilePath = path.join(config.uploadDir, 'test-original.txt');
    encryptedFilePath = path.join(config.uploadDir, `${uuid()}.enc`);
    
    fs.writeFileSync(testFilePath, originalContent);
    encryptFileWithUserKey(testFilePath, encryptedFilePath, userEncryptionKey);

    // Create file record in database
    testFile = {
      id: uuid(),
      name: 'shared-secret.txt',
      storedName: path.basename(encryptedFilePath),
      size: fs.statSync(encryptedFilePath).size,
      mimeType: 'text/plain',
      ownerId: userA.id,
      encrypted: true,
      userKeyEncrypted: true, // This is the key flag
      checksum: 'test-checksum',
      encryptionVersion: 4,
      createdAt: new Date(),
      status: FileStatus.ACTIVE,
      tags: [],
      version: 1,
      favoriteOf: [],
      sharedWith: [userB.id], // File is shared with User B
      downloadCount: 0,
    };

    db.createFile(testFile);

    // Create wrapped key for User B (simulating the share-with-key endpoint)
    // Extract DEK from the file using owner's key
    const dek = extractDekFromUserEncryptedFile(encryptedFilePath, userEncryptionKey);
    
    // Wrap DEK for User B
    const wrappedDek = wrapDekForUser(dek, userB.publicKey!);
    
    // Store wrapped key in database
    const wrappedKey: WrappedKey = {
      id: uuid(),
      fileId: testFile.id,
      userId: userB.id,
      wrappedDek,
      algorithm: 'aes-256-gcm',
      createdAt: new Date(),
      createdBy: userA.id,
    };
    
    db.createWrappedKey(wrappedKey);

    // Clean up test file
    fs.unlinkSync(testFilePath);
  });

  afterAll(() => {
    // Cleanup
    if (fs.existsSync(encryptedFilePath)) {
      fs.unlinkSync(encryptedFilePath);
    }
    
    // Clean up database entries
    try {
      db.deleteSession(sessionA.id);
      db.deleteSession(sessionB.id);
    } catch (e) {
      // Ignore cleanup errors
    }
  });

  it('Property 1: Shared User Can Decrypt User-Encrypted Files', async () => {
    /**
     * EXPECTED BEHAVIOR (after fix):
     * - User B should be able to download the decrypted file
     * - Response status should be 200
     * - Response body should contain the original file content
     * - No error messages about "user-provided key"
     * 
     * CURRENT BEHAVIOR (unfixed code):
     * - User B receives 403 error (Access denied) because the endpoint doesn't check sharedWith
     * - OR User B receives 400 error if access control is fixed but user-key encryption is not handled
     * - Error message: "This file is encrypted with a user-provided key"
     * - Download fails
     * 
     * This test MUST FAIL on unfixed code to confirm the bug exists.
     * 
     * Note: The bug manifests in two ways:
     * 1. Access control doesn't check sharedWith array (403 error)
     * 2. User-key encrypted files are rejected even for shared users (400 error)
     */

    const response = await request(app)
      .get(`/api/files/${testFile.id}/download-decrypted`)
      .set('Authorization', `Bearer ${tokenB}`);

    // Expected behavior assertions (will fail on unfixed code)
    expect(response.status).toBe(200);
    expect(response.text).toBe(originalContent);
    expect(response.headers['x-file-decrypted']).toBe('true');
    
    // Verify no error about user-provided key or access denied
    expect(response.text).not.toContain('user-provided key');
    expect(response.text).not.toContain('Access denied');
  });

  it('Bug Condition: isBugCondition returns true for this scenario', () => {
    /**
     * Verify that the bug condition is correctly identified:
     * - file.userKeyEncrypted == true
     * - file.sharedWith.includes(userB.id)
     * - userB.id != file.ownerId
     * - action is 'download'
     * - No wrapped key exists for the user (in unfixed code)
     */

    expect(testFile.userKeyEncrypted).toBe(true);
    expect(testFile.sharedWith).toContain(userB.id);
    expect(userB.id).not.toBe(testFile.ownerId);
    expect(testFile.ownerId).toBe(userA.id);
  });
});
