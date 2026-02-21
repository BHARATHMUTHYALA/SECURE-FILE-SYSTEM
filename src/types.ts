export enum Role {
  ADMIN = 'admin',
  EDITOR = 'editor',
  VIEWER = 'viewer',
}

export enum FileStatus {
  ACTIVE = 'active',
  TRASHED = 'trashed',
  DELETED = 'deleted',
}

export interface User {
  id: string;
  username: string;
  email: string;
  password: string;
  role: Role;
  createdAt: Date;
  // Security features
  twoFactorSecret?: string;
  twoFactorEnabled: boolean;
  storageQuota: number;
  storageUsed: number;
  avatar?: string;
  lastLoginAt?: Date;
  failedLoginAttempts: number;
  lockedUntil?: Date;
  preferences: UserPreferences;
  // Security enhancements
  passwordChangedAt?: Date;
  encryptionKeyVersion: number;
}

export interface UserPreferences {
  emailNotifications: boolean;
  theme: 'dark' | 'light';
  defaultEncrypt: boolean;
  autoLockMinutes: number;
  showFileExtensions: boolean;
}

export interface Session {
  id: string;
  userId: string;
  token: string;
  userAgent: string;
  ipAddress: string;
  createdAt: Date;
  expiresAt: Date;
  lastActiveAt: Date;
  deviceFingerprint?: string;
}

export interface FileRecord {
  id: string;
  name: string;
  storedName: string;
  size: number;
  mimeType: string;
  ownerId: string;
  encrypted: boolean;
  checksum: string;
  createdAt: Date;
  status: FileStatus;
  folderId?: string;
  tags: string[];
  categoryId?: string;
  description?: string;
  version: number;
  previousVersionId?: string;
  deletedAt?: Date;
  favoriteOf: string[];
  sharedWith: string[];
  downloadCount: number;
  lastAccessedAt?: Date;
  expiresAt?: Date;
  // Security enhancements
  encryptionVersion: number;
  integrityVerifiedAt?: Date;
  userKeyEncrypted?: boolean; // True if encrypted with user-provided key (key not stored on server)
}

export interface ShareLink {
  id: string;
  fileId: string;
  createdBy: string;
  accessToken: string;
  password?: string;
  expiresAt?: Date;
  maxDownloads?: number;
  downloadCount: number;
  allowedEmails?: string[];
  createdAt: Date;
  isActive: boolean;
}

export interface Folder {
  id: string;
  name: string;
  ownerId: string;
  parentId?: string;
  color?: string;
  icon?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface FileVersion {
  id: string;
  fileId: string;
  storedName: string;
  size: number;
  checksum: string;
  version: number;
  createdBy: string;
  createdAt: Date;
  comment?: string;
}

// ============ NEW FEATURES ============

// Categories - hierarchical organization
export interface Category {
  id: string;
  name: string;
  description?: string;
  color: string;
  icon: string;
  ownerId: string;
  parentId?: string;
  order: number;
  createdAt: Date;
  updatedAt: Date;
}

// File Annotations/Notes
export interface FileAnnotation {
  id: string;
  fileId: string;
  userId: string;
  title: string;
  content: string;
  color: string;
  pinned: boolean;
  createdAt: Date;
  updatedAt: Date;
}

// Bookmarks with labels
export interface Bookmark {
  id: string;
  fileId: string;
  userId: string;
  label: string;
  color: string;
  notes?: string;
  createdAt: Date;
}

// File Templates
export interface FileTemplate {
  id: string;
  name: string;
  description?: string;
  mimeType: string;
  storedName: string;
  size: number;
  category: string;
  ownerId: string;
  isPublic: boolean;
  usageCount: number;
  createdAt: Date;
  updatedAt: Date;
}

// Saved Search Filters
export interface SavedFilter {
  id: string;
  name: string;
  userId: string;
  filters: SearchFilters;
  isDefault: boolean;
  createdAt: Date;
}

export interface SearchFilters {
  query?: string;
  mimeTypes?: string[];
  tags?: string[];
  categoryId?: string;
  dateFrom?: string;
  dateTo?: string;
  sizeMin?: number;
  sizeMax?: number;
  encrypted?: boolean;
  hasAnnotations?: boolean;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

// Enhanced Tags with colors and descriptions
export interface Tag {
  id: string;
  name: string;
  color: string;
  description?: string;
  icon?: string;
  ownerId: string;
  createdAt: Date;
}

// Activity Feed
export interface ActivityFeed {
  id: string;
  userId: string;
  type: ActivityType;
  message: string;
  fileId?: string;
  metadata?: Record<string, unknown>;
  createdAt: Date;
}

export enum ActivityType {
  FILE_UPLOAD = 'file_upload',
  FILE_DOWNLOAD = 'file_download',
  FILE_DELETE = 'file_delete',
  FILE_EDIT = 'file_edit',
  FILE_MOVE = 'file_move',
  FOLDER_CREATE = 'folder_create',
  FOLDER_DELETE = 'folder_delete',
  ANNOTATION_ADD = 'annotation_add',
  BOOKMARK_ADD = 'bookmark_add',
  TAG_ADD = 'tag_add',
  CATEGORY_CREATE = 'category_create',
  TEMPLATE_CREATE = 'template_create',
  TEMPLATE_USE = 'template_use',
  SECURITY_EVENT = 'security_event',
  LOGIN = 'login',
  LOGOUT = 'logout',
}

// Quick Actions
export interface QuickAction {
  id: string;
  userId: string;
  name: string;
  icon: string;
  actionType: 'filter' | 'folder' | 'category' | 'template';
  targetId: string;
  order: number;
}

// Notifications
export interface Notification {
  id: string;
  userId: string;
  type: NotificationType;
  title: string;
  message: string;
  data?: Record<string, unknown>;
  read: boolean;
  createdAt: Date;
}

export enum NotificationType {
  FILE_UPLOADED = 'file_uploaded',
  FILE_DELETED = 'file_deleted',
  FILE_SHARED = 'file_shared',
  ANNOTATION_ADDED = 'annotation_added',
  STORAGE_WARNING = 'storage_warning',
  SECURITY_ALERT = 'security_alert',
  SYSTEM = 'system',
  INTEGRITY_CHECK = 'integrity_check',
}

export interface AuditLog {
  id: string;
  userId: string;
  action: string;
  target: string;
  details: string;
  ipAddress?: string;
  userAgent?: string;
  severity: 'info' | 'warning' | 'critical';
  timestamp: Date;
}

export interface RateLimitEntry {
  count: number;
  resetAt: Date;
}

// Security Event Log
export interface SecurityEvent {
  id: string;
  userId?: string;
  eventType: SecurityEventType;
  description: string;
  ipAddress: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
  timestamp: Date;
}

export enum SecurityEventType {
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILED = 'login_failed',
  LOGOUT = 'logout',
  PASSWORD_CHANGE = 'password_change',
  ACCOUNT_LOCKED = 'account_locked',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  FILE_INTEGRITY_FAIL = 'file_integrity_fail',
  UNAUTHORIZED_ACCESS = 'unauthorized_access',
  TWO_FACTOR_ENABLED = 'two_factor_enabled',
  ENCRYPTION_KEY_ROTATED = 'encryption_key_rotated',
}

declare global {
  namespace Express {
    interface Request {
      user?: { id: string; role: Role };
      sessionId?: string;
      clientIp?: string;
    }
  }
}
