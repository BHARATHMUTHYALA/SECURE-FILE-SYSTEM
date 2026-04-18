# Secure File Access System with Role-Based Permissions

A secure file management system with role-based access control (RBAC).

## Features

- **User Authentication**: JWT-based authentication with bcrypt password hashing
- **Zero-Trust Controls**: Session/IP/device-bound short-lived proof tokens for sensitive operations
- **Asymmetric Secure Sharing**: RSA-OAEP wrapped share secrets for recipient-specific secure access
- **Role-Based Access Control**: Admin, Editor, and Viewer roles
- **File Management**: Upload, download, view, and delete files
- **File Sharing**: Share files with specific users
- **Audit Logging**: Track all file access and modifications

## Roles & Permissions

| Role    | Read | Write | Delete | Manage Users |
|---------|------|-------|--------|--------------|
| Admin   | ✅   | ✅    | ✅     | ✅           |
| Editor  | ✅   | ✅    | ❌     | ❌           |
| Viewer  | ✅   | ❌    | ❌     | ❌           |

## Setup

```bash
cd secure-file-system
npm install
npm run dev
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login and get JWT token
- `GET /api/auth/profile` - Get current user profile

### Files
- `GET /api/files` - List accessible files
- `GET /api/files/my-files` - List own files
- `POST /api/files/upload` - Upload file (multipart/form-data)
- `GET /api/files/:id` - Get file details
- `GET /api/files/:id/download` - Download file
- `POST /api/files/:id/share` - Share file with users
- `POST /api/files/:id/share-secure` - Create secure asymmetric share link (requires zero-trust proof)
- `DELETE /api/files/:id` - Delete file

### Zero Trust & Secure Sharing
- `POST /api/security/zero-trust/proof` - Issue short-lived zero-trust proof for a purpose
- `POST /api/share/:token/key-package` - Retrieve RSA-wrapped share secret for recipient
- `POST /api/share/:token/download` - Download shared file (zero-trust proof required when enabled)

### Users (Admin only)
- `GET /api/users` - List all users
- `PATCH /api/users/:id/role` - Update user role
- `DELETE /api/users/:id` - Delete user

### Audit Logs (Admin only)
- `GET /api/audit` - Get audit logs

## Default Credentials

- **Email**: admin@example.com
- **Password**: admin123
