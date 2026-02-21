#!/usr/bin/env node
/**
 * Simple Validation Test
 * Tests encryption and decryption functionality step by step
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

console.log('\n' + '='.repeat(70));
console.log('Secure File System - Validation Test');
console.log('='.repeat(70) + '\n');

const testDir = path.join(__dirname, 'test-files');
const password = 'ValidateTest123!';
let passed = 0;
let failed = 0;

// Helper: log with icons
const log = (msg, status) => {
  const icons = { '✓': '✓ ', '✗': '✗ ', '→': '→ ', '⚙': '⚙ ' };
  console.log((icons[status] || '  ') + msg);
};

try {
  // 1. Create test directory and file
  console.log('STEP 1: Create test file');
  if (!fs.existsSync(testDir)) fs.mkdirSync(testDir, { recursive: true });
  
  const originalFile = path.join(testDir, '1-original.txt');
  const testContent = 'Validation Test: This is my secret document!';
  fs.writeFileSync(originalFile, testContent);
  log(`Created: ${testContent}`, '✓');
  passed++;

  // 2. Manually encrypt with user key
  console.log('\nSTEP 2: Encrypt file with user key');
  const encryptedFile = path.join(testDir, '2-encrypted.enc');
  const data = fs.readFileSync(originalFile);
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  
  const key = crypto.scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  
  const hmacKey = crypto.scryptSync(password + 'hmac', salt, 32, { N: 16384, r: 8, p: 1 });
  const hmac = crypto.createHmac('sha256', hmacKey);
  hmac.update(encrypted);
  const hmacDigest = hmac.digest();
  
  const version = Buffer.from([4]);
  const finalEncrypted = Buffer.concat([version, salt, iv, tag, hmacDigest, encrypted]);
  fs.writeFileSync(encryptedFile, finalEncrypted);
  log(`Encrypted file size: ${finalEncrypted.length} bytes`, '✓');
  log(`Original size: ${data.length} bytes`, '→');
  passed++;

  // 3. Decrypt using decrypt.js
  console.log('\nSTEP 3: Decrypt using decrypt.js');
  const decryptedFile = path.join(testDir, '3-decrypted.txt');
  const cmd = `node "${path.join(__dirname, 'decrypt.js')}" "${encryptedFile}" "${password}" "${decryptedFile}"`;
  const result = execSync(cmd, { encoding: 'utf8', shell: true });
  log('decrypt.js execution successful', '✓');
  log(`Output: ${result.split('\n')[0]}`, '→');
  passed++;

  // 4. Verify content matches
  console.log('\nSTEP 4: Verify decrypted content');
  const decryptedContent = fs.readFileSync(decryptedFile, 'utf8');
  if (decryptedContent === testContent) {
    log('Content matches original exactly!', '✓');
    log(`Decrypted: "${decryptedContent}"`, '→');
    passed++;
  } else {
    log('Content mismatch!', '✗');
    log(`Expected: "${testContent}"`, '→');
    log(`Got: "${decryptedContent}"`, '→');
    failed++;
  }

  // 5. Test wrong password
  console.log('\nSTEP 5: Test wrong password rejection');
  const wrongDecryptedFile = path.join(testDir, '4-wrong-decrypted.txt');
  try {
    execSync(`node "${path.join(__dirname, 'decrypt.js')}" "${encryptedFile}" "WrongPassword123" "${wrongDecryptedFile}"`, { encoding: 'utf8', shell: true });
    log('ERROR: Should have rejected wrong password!', '✗');
    failed++;
  } catch (err) {
    if (err.message.includes('Decryption failed')) {
      log('Correctly rejected wrong password', '✓');
      log('Error: "Decryption failed: Wrong key or corrupted file"', '→');
      passed++;
    } else {
      throw err;
    }
  }

  // 6. Verify encryption version
  console.log('\nSTEP 6: Verify encryption version');
  const fileData = fs.readFileSync(encryptedFile);
  const versionByte = fileData[0];
  if (versionByte === 4) {
    log(`Version byte is 4 (user-key encrypted)`, '✓');
    passed++;
  } else {
    log(`Wrong version: ${versionByte} (expected 4)`, '✗');
    failed++;
  }

  // Summary
  console.log('\n' + '='.repeat(70));
  console.log('SUMMARY');
  console.log('='.repeat(70));
  console.log(`✓ Passed: ${passed}`);
  console.log(`✗ Failed: ${failed}`);
  console.log(`Total:   ${passed + failed}`);
  
  if (failed === 0) {
    console.log('\n✓ ALL TESTS PASSED - Project is working correctly!\n');
  } else {
    console.log('\n✗ Some tests failed - see above for details\n');
  }

  console.log(`Test files saved in: ${testDir}`);
  console.log('You can inspect them manually if needed.\n');

} catch (err) {
  console.error('\nERROR during testing:', err.message);
  console.error(err.stack);
  process.exit(1);
}
