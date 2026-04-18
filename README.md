# 🔐 SecureFS - Enterprise-Grade Secure File Management System

A next-generation secure file management system with **zero-knowledge encryption**, **military-grade secure deletion**, and **user-controlled encryption keys**. Built with TypeScript, Express, and modern cryptography.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)

---

## 🌟 What Makes This Unique?

Unlike commercial alternatives (Dropbox, Google Drive, OneDrive), SecureFS offers **truly unique security features** that put YOU in control:

### 1. 🔒 **Zero-Knowledge Client-Side Encryption**
- **Files encrypted in your browser BEFORE upload**
- Server **never sees** your unencrypted data or password
- Open-source and verifiable (unlike proprietary alternatives)
- Uses Web Crypto API with AES-256-GCM + PBKDF2 (100,000 iterations)

**Why it matters**: Even if the server is compromised, your files remain encrypted. The server literally cannot decrypt them.

### 2. 🗑️ **DoD 5220.22-M Secure Deletion**
- **3-pass random data overwrite** + final zero-byte overwrite
- Files are **forensically unrecoverable** after deletion
- Meets military-grade data destruction standards

**Why it matters**: Most services (Dropbox, Google Drive) just "soft delete" files - they can be recovered for 30+ days. SecureFS makes deletion permanent.

### 3. 🔑 **User-Controlled Encryption Keys (BYOK)**
- **Bring Your Own Key** - encrypt files with YOUR password
- Server **never stores** your encryption key
- Full user control over encryption (rare in consumer apps)

**Why it matters**: You're not trusting the server with your encryption keys. Even the server admin cannot decrypt your files.

---

## 📋 Complete Feature List

### 🔐 Security & Encryption
- ✅ **Zero-Knowledge Encryption** - Client-side encryption in browser
- ✅ **User-Controlled Keys** - BYOK (Bring Your Own Key)
- ✅ **DoD Secure Deletion** - 3-pass overwrite (forensically unrecoverable)
- ✅ **AES-256-GCM Encryption** - Military-grade encryption
- ✅ **ChaCha20-Poly1305** - Modern authenticated encryption
- ✅ **RSA Key Wrapping** - Secure key exchange
- ✅ **HMAC Integrity Verification** - Tamper detection
- ✅ **Two-Factor Authentication (2FA)** - TOTP with QR codes and backup codes
- ✅ **Zero-Trust Architecture** - Session/IP/device-bound proof tokens
- ✅ **Failed Login Protection** - Account lockout after 5 failed attempts

### 📁 File Management
- ✅ **Drag & Drop Upload** - Modern file upload interface
- ✅ **File Versioning** - Track file history
- ✅ **Folder Organization** - Hierarchical folder structure
- ✅ **File Tagging** - Organize with custom tags
- ✅ **Favorites** - Mark important files
- ✅ **Trash/Restore** - Soft delete with recovery
- ✅ **Bulk Operations** - Select multiple files
- ✅ **File Preview** - View PDFs, images, text files
- ✅ **Search & Filter** - Find files quickly
- ✅ **Storage Quotas** - Per-user storage limits

### 👥 Collaboration & Sharing
- ✅ **Secure File Sharing** - Share with specific users
- ✅ **Share Links** - Password-protected public links
- ✅ **Expiring Links** - Time-limited access
- ✅ **Download Limits** - Control access count
- ✅ **Role-Based Access Control** - Admin, Editor, Viewer roles

### 📊 Advanced Features
- ✅ **Audit Logging** - Complete activity tracking
- ✅ **Security Dashboard** - Real-time security monitoring
- ✅ **Breach Detection** - Anomaly detection
- ✅ **Session Management** - View and terminate active sessions
- ✅ **Activity Feed** - Real-time user activity
- ✅ **Notifications** - Security alerts and updates
- ✅ **File Annotations** - Add notes to files
- ✅ **Bookmarks** - Quick access to important files

### 🎨 User Experience
- ✅ **Modern Dark UI** - Beautiful gradient-based design
- ✅ **Responsive Design** - Works on all devices
- ✅ **Grid/List Views** - Multiple viewing options
- ✅ **Real-time Updates** - Live activity feed
- ✅ **Toast Notifications** - User-friendly alerts
- ✅ **Keyboard Shortcuts** - Power user features

---

## 🆚 Comparison with Competitors

| Feature | SecureFS | Dropbox | Google Drive | Tresorit | Sync.com |
|---------|----------|---------|--------------|----------|----------|
| **Zero-Knowledge Encryption** | ✅ Open-source | ❌ | ❌ | ✅ Proprietary | ✅ Proprietary |
| **Client-Side Encryption** | ✅ Browser-based | ❌ | ❌ | ✅ Desktop app | ✅ Desktop app |
| **DoD Secure Deletion** | ✅ 3-pass overwrite | ❌ Soft delete | ❌ Soft delete | ❌ | ❌ |
| **User-Controlled Keys (BYOK)** | ✅ Consumer-level | ❌ | ❌ Enterprise only | ❌ | ❌ |
| **Open Source** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Self-Hostable** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Two-Factor Auth** | ✅ TOTP | ✅ | ✅ | ✅ | ✅ |
| **File Versioning** | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ and npm
- TypeScript 5.0+

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/secure-file-system.git
cd secure-file-system

# Install dependencies
npm install

# Build TypeScript
npm run build

# Start the server
npm start
```

The application will be available at `http://localhost:3000`

### Development Mode

```bash
# Run with auto-reload
npm run dev
```

---

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Security Keys (CHANGE THESE IN PRODUCTION!)
ENCRYPTION_KEY=your-32-character-encryption-key-here
JWT_SECRET=your-jwt-secret-key-here

# Storage Configuration
UPLOAD_DIR=./uploads
DATA_DIR=./data

# Rate Limiting
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=300000

# Storage Quotas (in bytes)
DEFAULT_STORAGE_QUOTA=524288000
```

### Generate Secure Keys

```bash
# Generate encryption key
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Generate JWT secret
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

---

## 📖 Usage Guide

### 1. Zero-Knowledge Encryption

**Upload with Zero-Knowledge Mode:**
1. Click "Upload File"
2. Select your file
3. ✅ Check "Zero-Knowledge Mode"
4. Enter encryption password (min 8 characters)
5. Confirm password
6. Click "Upload"

**Download Zero-Knowledge File:**
1. Click download on a zero-knowledge encrypted file
2. Enter your encryption password
3. File is decrypted in your browser
4. Download plaintext file

⚠️ **Important**: Remember your password! The server cannot recover it.

### 2. User-Controlled Encryption Keys

**Upload with Your Own Key:**
1. Click "Upload File"
2. Select your file
3. ✅ Check "Encrypt file"
4. ✅ Check "Use my own encryption key"
5. Enter your encryption key
6. Click "Upload"

**Download User-Key File:**
1. Go to "Decrypt File" page
2. Upload the encrypted `.enc` file
3. Enter your encryption key
4. Download decrypted file

### 3. Secure Deletion

**Permanently Delete a File:**
1. Select file
2. Click "Secure Delete" (trash icon with shield)
3. Confirm deletion
4. File is overwritten 3 times with random data
5. Final overwrite with zeros
6. File is forensically unrecoverable

### 4. Two-Factor Authentication

**Enable 2FA:**
1. Go to Settings → Security
2. Click "Enable 2FA"
3. Scan QR code with authenticator app (Google Authenticator, Authy)
4. Enter verification code
5. Save backup codes securely

---

## 🔐 Security Features Explained

### Zero-Knowledge Encryption Flow

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Browser   │         │   Server    │         │   Storage   │
└─────────────┘         └─────────────┘         └─────────────┘
      │                        │                        │
      │ 1. Select file         │                        │
      │ 2. Enter password      │                        │
      │ 3. Encrypt in browser  │                        │
      │    (AES-256-GCM)       │                        │
      │                        │                        │
      │ 4. Upload encrypted    │                        │
      │────────────────────────>                        │
      │                        │                        │
      │                        │ 5. Store encrypted     │
      │                        │────────────────────────>
      │                        │                        │
      │                        │ Server NEVER sees      │
      │                        │ plaintext or password  │
```

### DoD Secure Deletion Process

```
Original File → Pass 1 (Random) → Pass 2 (Random) → Pass 3 (Random) → Zero Pass → Delete
     ↓              ↓                  ↓                  ↓              ↓          ↓
  [Data]      [Random Bytes]    [Random Bytes]    [Random Bytes]    [0x00...]   [Gone]
```

---

## 🛠️ Technology Stack

### Backend
- **Runtime**: Node.js 18+
- **Framework**: Express.js
- **Language**: TypeScript
- **Authentication**: JWT + bcrypt
- **Encryption**: Node.js Crypto (AES-256-GCM, ChaCha20-Poly1305, RSA-OAEP)
- **2FA**: TOTP (Time-based One-Time Password)

### Frontend
- **HTML5** + **CSS3** (Modern gradient design)
- **Vanilla JavaScript** (No framework dependencies)
- **Web Crypto API** (Client-side encryption)
- **Font Awesome** (Icons)
- **PDF.js** (PDF preview)

### Security
- **Encryption**: AES-256-GCM, ChaCha20-Poly1305, RSA-4096
- **Key Derivation**: PBKDF2 (100,000 iterations), scrypt
- **Hashing**: SHA-256, HMAC-SHA256
- **Password Hashing**: bcrypt (12 rounds)

---

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePass123!",
  "totpCode": "123456"  // Optional, required if 2FA enabled
}
```

#### Enable 2FA
```http
POST /api/auth/2fa/setup
Authorization: Bearer <token>
```

### File Endpoints

#### Upload File (Standard)
```http
POST /api/files/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <binary>
encrypt: true
folderId: <optional>
tags: ["tag1", "tag2"]
```

#### Upload File (User Key)
```http
POST /api/files/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <binary>
encrypt: true
userEncryptionKey: "my-secret-key-123"
```

#### Upload File (Zero-Knowledge)
```http
POST /api/files/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <encrypted-blob>
clientSideEncrypted: true
encryptedMetadata: <base64-encrypted-metadata>
```

#### Download File
```http
GET /api/files/:id/download
Authorization: Bearer <token>
```

#### Secure Delete
```http
DELETE /api/files/:id/secure
Authorization: Bearer <token>
```

### Security Endpoints

#### Generate Zero-Trust Proof
```http
POST /api/security/zero-trust/proof
Authorization: Bearer <token>
Content-Type: application/json

{
  "purpose": "secure-share"
}
```

---

## 🧪 Testing

### Run Tests
```bash
npm test
```

### Test Zero-Knowledge Encryption
Open `test-zero-knowledge.html` in your browser to test client-side encryption.

### Test Crypto Functions
Open `test-crypto-functions.html` in your browser to test all cryptographic functions.

---

## 🚢 Deployment

### Deploy to Railway.app (Recommended)
```bash
# Push to GitHub
git push origin main

# Go to railway.app
# Sign up with GitHub
# Deploy from GitHub repo
# Done! ✅
```

See `DEPLOYMENT_GUIDE_RAILWAY.md` for detailed instructions.

### Deploy to Render.com
See `DEPLOYMENT_GUIDE_RENDER.md` for instructions.

### Deploy to Heroku
See `DEPLOYMENT_GUIDE_HEROKU.md` for instructions.

---

## 👥 User Roles & Permissions

| Role    | Upload | Download | Delete Own | Delete Any | Manage Users | View Audit Logs |
|---------|--------|----------|------------|------------|--------------|-----------------|
| Admin   | ✅     | ✅       | ✅         | ✅         | ✅           | ✅              |
| Editor  | ✅     | ✅       | ✅         | ❌         | ❌           | ❌              |
| Viewer  | ❌     | ✅       | ❌         | ❌         | ❌           | ❌              |

---

## 🔒 Security Best Practices

### For Users
1. ✅ Enable Two-Factor Authentication
2. ✅ Use strong, unique passwords (min 12 characters)
3. ✅ Use Zero-Knowledge Mode for sensitive files
4. ✅ Save backup codes in a secure location
5. ✅ Use Secure Delete for confidential files
6. ✅ Regularly review active sessions

### For Administrators
1. ✅ Change default encryption keys in production
2. ✅ Use HTTPS in production (required for Web Crypto API)
3. ✅ Set strong JWT secrets
4. ✅ Enable rate limiting
5. ✅ Regular security audits
6. ✅ Monitor audit logs
7. ✅ Keep dependencies updated

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 🙏 Acknowledgments

- Built with ❤️ using TypeScript and Express
- Cryptography powered by Node.js Crypto and Web Crypto API
- UI inspired by modern design principles
- Security standards based on NIST and DoD guidelines

---

## ⚠️ Disclaimer

This software is provided "as is" without warranty of any kind. While we implement industry-standard security practices, no system is 100% secure. Use at your own risk and always maintain backups of important data.

---

**Made with 🔐 by [Muthyala Bharath Sai]**
