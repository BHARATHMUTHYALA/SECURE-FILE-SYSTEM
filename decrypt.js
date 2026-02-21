#!/usr/bin/env node
/**
 * Simple File Decryption Tool
 * Usage: node decrypt.js <encrypted_file.enc> <your_key> [output_file]
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Encryption parameters (must match the app)
const SALT_LEN = 32;
const IV_LEN = 16;
const TAG_LEN = 16;
const HMAC_LEN = 32;
const KEY_LEN = 32;

function decrypt(inputFile, key, outputFile) {
  // Read encrypted file
  const data = fs.readFileSync(inputFile);
  const version = data[0];
  
  console.log(`File version: ${version}`);
  
  if (version !== 4) {
    console.error('This file was not encrypted with a user key (version 4).');
    console.error('Only user-key encrypted files can be decrypted with this tool.');
    process.exit(1);
  }
  
  // Parse file format: [version:1][salt:32][iv:16][tag:16][hmac:32][data]
  let offset = 1;
  const salt = data.subarray(offset, offset + SALT_LEN); offset += SALT_LEN;
  const iv = data.subarray(offset, offset + IV_LEN); offset += IV_LEN;
  const tag = data.subarray(offset, offset + TAG_LEN); offset += TAG_LEN;
  const hmac = data.subarray(offset, offset + HMAC_LEN); offset += HMAC_LEN;
  const encrypted = data.subarray(offset);
  
  // Derive key using scrypt (same params as app)
  const derivedKey = crypto.scryptSync(key, salt, KEY_LEN, {
    N: 16384,
    r: 8,
    p: 1,
  });
  
  // Decrypt using AES-256-GCM
  const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
  decipher.setAuthTag(tag);
  
  try {
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    
    // Write output
    fs.writeFileSync(outputFile, decrypted);
    console.log(`✓ Decrypted successfully: ${outputFile}`);
    console.log(`  Size: ${decrypted.length} bytes`);
  } catch (err) {
    console.error('✗ Decryption failed: Wrong key or corrupted file');
    process.exit(1);
  }
}

// Main
const args = process.argv.slice(2);

if (args.length < 2) {
  console.log('');
  console.log('SecureFS File Decryption Tool');
  console.log('=============================');
  console.log('');
  console.log('Usage: node decrypt.js <encrypted_file> <key> [output_file]');
  console.log('');
  console.log('Examples:');
  console.log('  node decrypt.js myfile.enc MySecretKey123');
  console.log('  node decrypt.js myfile.enc MySecretKey123 decrypted.txt');
  console.log('');
  process.exit(1);
}

const inputFile = args[0];
const key = args[1];
const outputFile = args[2] || inputFile.replace('.enc', '_decrypted' + path.extname(inputFile.replace('.enc', '')) || '.bin');

if (!fs.existsSync(inputFile)) {
  console.error(`File not found: ${inputFile}`);
  process.exit(1);
}

decrypt(inputFile, key, outputFile);
