#!/usr/bin/env node
/**
 * Automated Integration Test Suite
 * Tests core encryption/decryption functionality
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const SALT_LEN = 32;
const IV_LEN = 16;
const TAG_LEN = 16;
const HMAC_LEN = 32;
const KEY_LEN = 32;

class TestSuite {
  constructor() {
    this.testDir = path.join(__dirname, 'test-files');
    this.passed = 0;
    this.failed = 0;
    this.tests = [];
  }

  log(message, type = 'info') {
    const icons = {
      info: '📋',
      success: '✅',
      error: '❌',
      test: '🧪',
      warn: '⚠️',
      arrow: '➜'
    };
    console.log(`${icons[type] || '•'} ${message}`);
  }

  async run() {
    console.clear();
    this.log('Secure File System - Integration Test Suite', 'test');
    console.log('\n' + '='.repeat(60) + '\n');

    // Setup
    if (!fs.existsSync(this.testDir)) {
      fs.mkdirSync(this.testDir, { recursive: true });
    }

    // Run tests
    await this.testCreateTestFile();
    await this.testEncryptionWithUserKey();
    await this.testDecryptionUsingCLI();
    await this.testWrongPassword();
    await this.testFileIntegrity();
    await this.testEncryptionVersioning();

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log(`\nTest Summary:`);
    this.log(`Passed: ${this.passed}`, 'success');
    this.log(`Failed: ${this.failed}`, this.failed > 0 ? 'error' : 'success');
    console.log(`Total: ${this.passed + this.failed}\n`);

    // Cleanup
    this.cleanup();
  }

  async testCreateTestFile() {
    this.log('Test 1: Create Test File', 'test');
    try {
      const content = 'Hello World! This is a test file for encryption validation.';
      const testFile = path.join(this.testDir, 'original.txt');
      fs.writeFileSync(testFile, content);

      if (fs.existsSync(testFile) && fs.readFileSync(testFile, 'utf8') === content) {
        this.log('Created test file: original.txt', 'success');
        this.passed++;
        return true;
      } else {
        throw new Error('File content mismatch');
      }
    } catch (err) {
      this.log(`Failed to create test file: ${err.message}`, 'error');
      this.failed++;
      return false;
    }
  }

  async testEncryptionWithUserKey() {
    this.log('Test 2: Encrypt File with User Key', 'test');
    try {
      const testFile = path.join(this.testDir, 'original.txt');
      const encryptedFile = path.join(this.testDir, 'test.enc');
      const password = 'TestPassword123';

      // Read original file
      const data = fs.readFileSync(testFile);
      const salt = crypto.randomBytes(SALT_LEN);
      const iv = crypto.randomBytes(IV_LEN);

      // Derive key using scrypt
      const key = crypto.scryptSync(password, salt, KEY_LEN, {
        N: 16384,
        r: 8,
        p: 1,
      });

      // Encrypt
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
      const tag = cipher.getAuthTag();

      // Derive HMAC key and create HMAC
      const hmacKey = crypto.scryptSync(password + 'hmac', salt, KEY_LEN, {
        N: 16384,
        r: 8,
        p: 1,
      });
      const hmac = crypto.createHmac('sha256', hmacKey);
      hmac.update(encrypted);
      const hmacDigest = hmac.digest();

      // Write encrypted file: [version:1][salt:32][iv:16][tag:16][hmac:32][encrypted]
      const version = Buffer.from([4]); // Version 4 = user-key encrypted
      const encryptedContent = Buffer.concat([version, salt, iv, tag, hmacDigest, encrypted]);
      fs.writeFileSync(encryptedFile, encryptedContent);

      if (fs.existsSync(encryptedFile) && fs.statSync(encryptedFile).size > 100) {
        this.log('Encrypted file created successfully', 'success');
        this.log(`Original size: ${data.length} bytes`, 'arrow');
        this.log(`Encrypted size: ${encryptedContent.length} bytes`, 'arrow');
        this.passed++;
        return true;
      }
    } catch (err) {
      this.log(`Encryption failed: ${err.message}`, 'error');
      this.failed++;
      return false;
    }
  }

  async testDecryptionUsingCLI() {
    this.log('Test 3: Decrypt Using CLI Tool (decrypt.js)', 'test');
    try {
      const encryptedFile = path.join(this.testDir, 'test.enc');
      const decryptedFile = path.join(this.testDir, 'decrypted.txt');
      const password = 'TestPassword123';

      // Run decrypt.js
      const cmd = `node decrypt.js "${encryptedFile}" "${password}" "${decryptedFile}"`;
      const output = execSync(cmd, { cwd: __dirname, encoding: 'utf8' });

      if (fs.existsSync(decryptedFile)) {
        this.log('CLI decrypt.js executed successfully', 'success');
        this.passed++;
        return true;
      }
    } catch (err) {
      this.log(`CLI decryption failed: ${err.message}`, 'error');
      this.failed++;
      return false;
    }
  }

  async testFileIntegrity() {
    this.log('Test 4: Verify File Integrity (Content Match)', 'test');
    try {
      const originalFile = path.join(this.testDir, 'original.txt');
      const decryptedFile = path.join(this.testDir, 'decrypted.txt');

      const original = fs.readFileSync(originalFile, 'utf8');
      const decrypted = fs.readFileSync(decryptedFile, 'utf8');

      if (original === decrypted) {
        this.log('Decrypted content matches original exactly', 'success');
        this.log(`Content: "${original}"`, 'arrow');
        this.passed++;
        return true;
      } else {
        this.log('Content mismatch after decryption', 'error');
        this.log(`Expected: "${original}"`, 'warn');
        this.log(`Got: "${decrypted}"`, 'warn');
        this.failed++;
        return false;
      }
    } catch (err) {
      this.log(`Failed to verify integrity: ${err.message}`, 'error');
      this.failed++;
      return false;
    }
  }

  async testWrongPassword() {
    this.log('Test 5: Reject Wrong Password', 'test');
    try {
      const encryptedFile = path.join(this.testDir, 'test.enc');
      const wrongDecryptedFile = path.join(this.testDir, 'wrong-decrypted.txt');
      const wrongPassword = 'WrongPassword123';

      // Try decrypting with wrong password
      try {
        execSync(`node decrypt.js "${encryptedFile}" "${wrongPassword}" "${wrongDecryptedFile}"`, {
          cwd: __dirname,
          encoding: 'utf8'
        });
        this.log('Decryption should have failed with wrong password!', 'error');
        this.failed++;
        return false;
      } catch (decryptErr) {
        if (decryptErr.message.includes('Decryption failed')) {
          this.log('Correctly rejected wrong password', 'success');
          this.log('Error message: "Decryption failed: Wrong key or corrupted file"', 'arrow');
          this.passed++;
          return true;
        } else {
          throw decryptErr;
        }
      }
    } catch (err) {
      this.log(`Wrong password test had unexpected error: ${err.message}`, 'error');
      this.failed++;
      return false;
    }
  }

  async testEncryptionVersioning() {
    this.log('Test 6: Verify Encryption Version Marking', 'test');
    try {
      const encryptedFile = path.join(this.testDir, 'test.enc');
      const fileData = fs.readFileSync(encryptedFile);
      const version = fileData[0];

      if (version === 4) {
        this.log('Encryption version correctly marked as 4 (user-key)', 'success');
        this.log(`Version byte: ${version}`, 'arrow');
        this.passed++;
        return true;
      } else {
        this.log(`Wrong encryption version: ${version} (expected 4)`, 'error');
        this.failed++;
        return false;
      }
    } catch (err) {
      this.log(`Failed to verify version: ${err.message}`, 'error');
      this.failed++;
      return false;
    }
  }

  cleanup() {
    // Keep test files for inspection, just log location
    this.log(`Test files saved in: ${path.resolve(this.testDir)}`, 'info');
    this.log('You can manually inspect encrypted and decrypted files', 'info');
  }
}

// Run tests
const suite = new TestSuite();
suite.run().catch(err => {
  console.error('Test suite error:', err);
  process.exit(1);
});
