# Secure File Access System with Role-Based Permissions

A secure file management system with role-based access control (RBAC).

## Features

- **User Authentication**: JWT-based authentication with bcrypt password hashing
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
- `DELETE /api/files/:id` - Delete file

### Users (Admin only)
- `GET /api/users` - List all users
- `PATCH /api/users/:id/role` - Update user role
- `DELETE /api/users/:id` - Delete user

### Audit Logs (Admin only)
- `GET /api/audit` - Get audit logs

## Default Credentials

- **Email**: admin@example.com
- **Password**: admin123
