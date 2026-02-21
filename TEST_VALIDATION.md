# Project Validation Guide

Complete validation of the Secure File System functionality.

## Quick Start

### 1. Start the Server
```powershell
cd secure-file-system
npx ts-node src/app.ts
```

Server runs on: http://localhost:3000

### 2. Access the Web UI
Open browser to: **http://localhost:3000**
- Username: `admin`
- Password: `Admin123!`

---

## Validation Tests

### Test 1: Login & Authentication
**Steps:**
1. Open http://localhost:3000
2. Login with credentials above
3. Should see dashboard with file list

**Expected Result:** ✓ Dashboard loads successfully

---

### Test 2: Upload File WITHOUT User Key
**Steps:**
1. Click "Upload File" button
2. Select any file (txt, pdf, jpg, etc.)
3. Leave "Use my own encryption key" **unchecked**
4. Click Upload

**Expected Result:** ✓ File uploaded and encrypted with server key (Version 3)

---

### Test 3: Upload File WITH User Key (User-Provided Password)
**Steps:**
1. Click "Upload File" button
2. Select a test file
3. **Check** "Use my own encryption key"
4. Enter password: `MySecretKey123`
5. Verify key strength indicator shows green
6. Click Upload

**Expected Result:** ✓ File uploaded and encrypted with your password (Version 4)

---

### Test 4: Web-Based Decryption (User-Key Files Only)
**Prerequisites:** Have uploaded a file with user key (Test 3)

**Steps:**
1. Click "Decrypt File" button in UI
2. Upload the `.enc` file from step 3
3. Enter the same password: `MySecretKey123`
4. Click Decrypt

**Expected Result:** ✓ Decrypted file downloads automatically

---

### Test 5: Command-Line Decryption Tool
**Prerequisites:** Have uploaded a file with user key

**Steps:**
```powershell
# Navigate to project folder
cd secure-file-system

# Run decrypt.js script
node decrypt.js uploads/<filename>.enc "MySecretKey123" output.txt

# Or let it auto-name:
node decrypt.js uploads/<filename>.enc "MySecretKey123"
```

**Expected Result:** ✓ File decrypted successfully, message shows "✓ Decrypted successfully"

---

### Test 6: Wrong Password Validation
**Steps:**
1. Click "Decrypt File"
2. Upload a user-key encrypted file
3. Enter wrong password: `WrongPassword`
4. Click Decrypt

**Expected Result:** ✗ Error message: "Invalid encryption key - please verify you entered the correct key"

---

### Test 7: File Format Validation
**Steps:**
1. Try uploading a file with wrong MIME type (rename executable as .txt)
2. Upload malformed file

**Expected Result:** ✗ Rejected with error message about file type/content mismatch

---

### Test 8: Storage Quota
**Steps:**
1. For non-admin users, upload files until storage quota is exceeded
2. Try uploading another file

**Expected Result:** ✗ Error: "Storage quota exceeded"

---

## Full Integration Test (Automated)

Run the test script:
```powershell
cd secure-file-system
node test-validation.js
```

This will:
- Create a test file
- Upload with user key
- Decrypt using decrypt.js
- Verify content matches original
- Display results

---

## Manual End-to-End Test

### Scenario: Encrypt, Upload, Decrypt, Verify

**Step 1: Create a test file**
```powershell
cd secure-file-system
"This is my secret document" > secret.txt
```

**Step 2: Upload with user key via UI**
- Open http://localhost:3000
- Login as admin
- Upload `secret.txt`
- Check "Use my own encryption key"
- Enter password: `TestPassword123`
- Upload

**Step 3: Download encrypted file**
- In file list, right-click on uploaded file
- Select "Download" → saves as `.enc` file

**Step 4: Decrypt using CLI tool**
```powershell
node decrypt.js secret.txt.enc TestPassword123 decrypted.txt
cat decrypted.txt
```

**Step 5: Verify**
```powershell
Get-Content secret.txt
Get-Content decrypted.txt
# Contents should be identical
```

**Expected Result:** ✓ Both files contain "This is my secret document"

---

## Troubleshooting

### Server won't start
```powershell
# Kill existing node processes
Get-Process -Name "node" -ErrorAction SilentlyContinue | Stop-Process -Force
# Try again
npx ts-node src/app.ts
```

### Port 3000 already in use
```powershell
# Find process using port 3000
netstat -ano | findstr :3000
# Kill it by PID
taskkill /PID <PID> /F
```

### Decryption fails
- Verify the password is exactly correct (case-sensitive)
- Confirm file was uploaded WITH user key enabled
- Check file wasn't corrupted

### Compilation errors
```powershell
# Clear and rebuild
rm -r node_modules dist
npm install
npx tsc --noEmit
```

---

## What Should Work

✅ User registration and login
✅ File upload with encryption (both server-key and user-key)
✅ Encryption verification (AES-256-GCM + scrypt)
✅ Web-based decryption for user-key files
✅ CLI-based decryption using decrypt.js
✅ File integrity verification
✅ Storage quota enforcement
✅ File type validation
✅ Secure file deletion
✅ Activity logging

---

## What Won't Work (By Design)

❌ Decryption of server-key encrypted files (only server has key)
❌ External tools cannot decrypt unless password is provided
❌ Files cannot be recovered if user-key password is lost
