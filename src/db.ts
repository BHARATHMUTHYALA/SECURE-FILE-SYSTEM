import { 
  User, FileRecord, AuditLog, Role, FileStatus, 
  Folder, FileVersion, Notification, NotificationType, Session, Tag, ActivityFeed, ActivityType,
  RateLimitEntry, Category, FileAnnotation, Bookmark, FileTemplate, SavedFilter, SecurityEvent, SecurityEventType, ShareLink
} from './types';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import { config } from './config';
import fs from 'fs';
import path from 'path';

const DB_FILE = path.join(__dirname, '..', 'data', 'database.json');

interface DBData {
  users: [string, User][];
  files: [string, FileRecord][];
  folders: [string, Folder][];
  versions: [string, FileVersion][];
  notifications: [string, Notification][];
  sessions: [string, Session][];
  tags: [string, Tag][];
  categories: [string, Category][];
  annotations: [string, FileAnnotation][];
  bookmarks: [string, Bookmark][];
  templates: [string, FileTemplate][];
  savedFilters: [string, SavedFilter][];
  shareLinks: [string, ShareLink][];
  securityEvents: SecurityEvent[];
  activities: ActivityFeed[];
  logs: AuditLog[];
}

class DB {
  users = new Map<string, User>();
  files = new Map<string, FileRecord>();
  folders = new Map<string, Folder>();
  versions = new Map<string, FileVersion>();
  notifications = new Map<string, Notification>();
  sessions = new Map<string, Session>();
  tags = new Map<string, Tag>();
  categories = new Map<string, Category>();
  annotations = new Map<string, FileAnnotation>();
  bookmarks = new Map<string, Bookmark>();
  templates = new Map<string, FileTemplate>();
  savedFilters = new Map<string, SavedFilter>();
  shareLinks = new Map<string, ShareLink>();
  securityEvents: SecurityEvent[] = [];
  activities: ActivityFeed[] = [];
  logs: AuditLog[] = [];
  rateLimits = new Map<string, RateLimitEntry>();

  constructor() {
    this.loadFromDisk();
    if (this.users.size === 0) {
      this.seedAdmin();
    }
    this.startCleanupJob();
  }

  private loadFromDisk() {
    try {
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf-8');
        const data: DBData = JSON.parse(raw, (key, value) => {
          // Convert date strings back to Date objects
          if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) {
            return new Date(value);
          }
          return value;
        });
        
        this.users = new Map(data.users || []);
        this.files = new Map(data.files || []);
        this.folders = new Map(data.folders || []);
        this.versions = new Map(data.versions || []);
        this.notifications = new Map(data.notifications || []);
        this.sessions = new Map(data.sessions || []);
        this.tags = new Map(data.tags || []);
        this.categories = new Map(data.categories || []);
        this.annotations = new Map(data.annotations || []);
        this.bookmarks = new Map(data.bookmarks || []);
        this.templates = new Map(data.templates || []);
        this.savedFilters = new Map(data.savedFilters || []);
        this.shareLinks = new Map(data.shareLinks || []);
        this.securityEvents = data.securityEvents || [];
        this.activities = data.activities || [];
        this.logs = data.logs || [];
        
        console.log('✓ Database loaded from disk');
      }
    } catch (err) {
      console.error('Failed to load database from disk:', err);
    }
  }

  private saveToDisk() {
    try {
      const dir = path.dirname(DB_FILE);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      const data: DBData = {
        users: [...this.users.entries()],
        files: [...this.files.entries()],
        folders: [...this.folders.entries()],
        versions: [...this.versions.entries()],
        notifications: [...this.notifications.entries()],
        sessions: [...this.sessions.entries()],
        tags: [...this.tags.entries()],
        categories: [...this.categories.entries()],
        annotations: [...this.annotations.entries()],
        bookmarks: [...this.bookmarks.entries()],
        templates: [...this.templates.entries()],
        savedFilters: [...this.savedFilters.entries()],
        shareLinks: [...this.shareLinks.entries()],
        securityEvents: this.securityEvents,
        activities: this.activities,
        logs: this.logs,
      };
      
      fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
    } catch (err) {
      console.error('Failed to save database to disk:', err);
    }
  }

  private seedAdmin() {
    const admin: User = {
      id: uuid(),
      username: 'admin',
      email: 'admin@example.com',
      password: bcrypt.hashSync('admin123', 12),
      role: Role.ADMIN,
      createdAt: new Date(),
      twoFactorEnabled: false,
      storageQuota: config.defaultStorageQuota * 10, // Admin gets 10x quota
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
    this.users.set(admin.id, admin);
    
    // Create default categories
    const defaultCategories = [
      { name: 'Documents', icon: '📄', color: '#3b82f6' },
      { name: 'Images', icon: '🖼️', color: '#10b981' },
      { name: 'Videos', icon: '🎬', color: '#f59e0b' },
      { name: 'Audio', icon: '🎵', color: '#8b5cf6' },
      { name: 'Archives', icon: '📦', color: '#6b7280' },
      { name: 'Other', icon: '📁', color: '#ec4899' },
    ];
    
    defaultCategories.forEach((cat, idx) => {
      const category: Category = {
        id: uuid(),
        name: cat.name,
        icon: cat.icon,
        color: cat.color,
        ownerId: admin.id,
        order: idx,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      this.categories.set(category.id, category);
    });
    
    this.saveToDisk();
    console.log('✓ Admin seeded (admin@example.com / admin123)');
  }

  private startCleanupJob() {
    // Clean up expired items every hour
    setInterval(() => {
      this.cleanupExpiredItems();
    }, 60 * 60 * 1000);
  }

  private cleanupExpiredItems() {
    const now = new Date();
    let changed = false;
    
    // Clean expired sessions
    for (const [id, session] of this.sessions) {
      if (session.expiresAt < now) {
        this.sessions.delete(id);
        changed = true;
      }
    }
    
    // Clean old trash items
    const trashRetention = config.trashRetentionDays * 24 * 60 * 60 * 1000;
    for (const [id, file] of this.files) {
      if (file.status === FileStatus.TRASHED && file.deletedAt) {
        if (now.getTime() - file.deletedAt.getTime() > trashRetention) {
          file.status = FileStatus.DELETED;
          changed = true;
        }
      }
      // Clean files with expiration dates
      if (file.expiresAt && file.expiresAt < now && file.status === FileStatus.ACTIVE) {
        file.status = FileStatus.TRASHED;
        file.deletedAt = now;
        changed = true;
      }
    }
    
    // Clean old security events (keep last 30 days)
    const securityRetention = 30 * 24 * 60 * 60 * 1000;
    this.securityEvents = this.securityEvents.filter(
      e => now.getTime() - e.timestamp.getTime() < securityRetention
    );
    
    if (changed) {
      this.saveToDisk();
    }
  }

  // ============ USERS ============
  findUserByEmail = (email: string) => [...this.users.values()].find(u => u.email === email);
  findUserById = (id: string) => this.users.get(id);
  findUserByUsername = (username: string) => [...this.users.values()].find(u => u.username.toLowerCase() === username.toLowerCase());
  createUser = (user: User) => { this.users.set(user.id, user); this.saveToDisk(); return user; };
  getAllUsers = () => [...this.users.values()];
  updateUser = (id: string, data: Partial<User>) => {
    const user = this.users.get(id);
    if (user) { this.users.set(id, { ...user, ...data }); this.saveToDisk(); }
    return this.users.get(id);
  };
  deleteUser = (id: string) => { const result = this.users.delete(id); this.saveToDisk(); return result; };
  
  updateStorageUsed = (userId: string, delta: number) => {
    const user = this.users.get(userId);
    if (user) {
      user.storageUsed = Math.max(0, user.storageUsed + delta);
      this.users.set(userId, user);
      this.saveToDisk();
    }
  };

  // ============ FILES ============
  createFile = (file: FileRecord) => { 
    this.files.set(file.id, file); 
    this.updateStorageUsed(file.ownerId, file.size);
    this.saveToDisk();
    return file; 
  };
  findFileById = (id: string) => this.files.get(id);
  getFilesByUser = (userId: string, includeTrash = false) => 
    [...this.files.values()].filter(f => 
      f.ownerId === userId &&
      (includeTrash ? f.status !== FileStatus.DELETED : f.status === FileStatus.ACTIVE)
    );
  getAllFiles = (includeTrash = false) => 
    [...this.files.values()].filter(f => 
      includeTrash ? f.status !== FileStatus.DELETED : f.status === FileStatus.ACTIVE
    );
  getFilesByFolder = (folderId: string | undefined, userId: string) =>
    [...this.files.values()].filter(f => 
      f.folderId === folderId && 
      f.status === FileStatus.ACTIVE &&
      f.ownerId === userId
    );
  getFilesByTag = (tag: string, userId: string) =>
    [...this.files.values()].filter(f => 
      f.tags.includes(tag) && 
      f.status === FileStatus.ACTIVE &&
      f.ownerId === userId
    );
  getFilesByCategory = (categoryId: string, userId: string) =>
    [...this.files.values()].filter(f =>
      f.categoryId === categoryId &&
      f.status === FileStatus.ACTIVE &&
      f.ownerId === userId
    );
  getFavorites = (userId: string) =>
    [...this.files.values()].filter(f => 
      f.favoriteOf.includes(userId) && f.status === FileStatus.ACTIVE
    );
  getTrashedFiles = (userId: string) =>
    [...this.files.values()].filter(f => 
      f.status === FileStatus.TRASHED && f.ownerId === userId
    );
  searchFiles = (userId: string, query: string, filters?: {
    tags?: string[];
    categoryId?: string;
    mimeTypes?: string[];
    dateFrom?: Date;
    dateTo?: Date;
    sizeMin?: number;
    sizeMax?: number;
    encrypted?: boolean;
  }) => {
    let files = [...this.files.values()].filter(f => 
      f.ownerId === userId && f.status === FileStatus.ACTIVE
    );
    
    // Text search
    if (query) {
      const term = query.toLowerCase();
      files = files.filter(f =>
        f.name.toLowerCase().includes(term) ||
        f.tags.some(t => t.toLowerCase().includes(term)) ||
        f.description?.toLowerCase().includes(term)
      );
    }
    
    // Apply filters
    if (filters) {
      if (filters.tags?.length) {
        files = files.filter(f => filters.tags!.some(t => f.tags.includes(t)));
      }
      if (filters.categoryId) {
        files = files.filter(f => f.categoryId === filters.categoryId);
      }
      if (filters.mimeTypes?.length) {
        files = files.filter(f => filters.mimeTypes!.some(m => f.mimeType.startsWith(m)));
      }
      if (filters.dateFrom) {
        files = files.filter(f => f.createdAt >= filters.dateFrom!);
      }
      if (filters.dateTo) {
        files = files.filter(f => f.createdAt <= filters.dateTo!);
      }
      if (filters.sizeMin !== undefined) {
        files = files.filter(f => f.size >= filters.sizeMin!);
      }
      if (filters.sizeMax !== undefined) {
        files = files.filter(f => f.size <= filters.sizeMax!);
      }
      if (filters.encrypted !== undefined) {
        files = files.filter(f => f.encrypted === filters.encrypted);
      }
    }
    
    return files;
  };
  updateFile = (id: string, data: Partial<FileRecord>) => {
    const file = this.files.get(id);
    if (file) { this.files.set(id, { ...file, ...data }); this.saveToDisk(); }
    return this.files.get(id);
  };
  deleteFile = (id: string) => {
    const file = this.files.get(id);
    if (file) {
      this.updateStorageUsed(file.ownerId, -file.size);
      // Clean up related data
      this.deleteAnnotationsByFile(id);
      this.deleteBookmarksByFile(id);
    }
    const result = this.files.delete(id);
    this.saveToDisk();
    return result;
  };
  trashFile = (id: string) => {
    const file = this.files.get(id);
    if (file) {
      file.status = FileStatus.TRASHED;
      file.deletedAt = new Date();
      this.files.set(id, file);
      this.saveToDisk();
      return true;
    }
    return false;
  };
  restoreFile = (id: string) => {
    const file = this.files.get(id);
    if (file && file.status === FileStatus.TRASHED) {
      file.status = FileStatus.ACTIVE;
      file.deletedAt = undefined;
      this.files.set(id, file);
      this.saveToDisk();
      return true;
    }
    return false;
  };

  // ============ FOLDERS ============
  createFolder = (folder: Folder) => { this.folders.set(folder.id, folder); this.saveToDisk(); return folder; };
  findFolderById = (id: string) => this.folders.get(id);
  getFoldersByUser = (userId: string, parentId?: string) =>
    [...this.folders.values()].filter(f => f.ownerId === userId && f.parentId === parentId);
  getAllFoldersByUser = (userId: string) =>
    [...this.folders.values()].filter(f => f.ownerId === userId);
  updateFolder = (id: string, data: Partial<Folder>) => {
    const folder = this.folders.get(id);
    if (folder) { this.folders.set(id, { ...folder, ...data, updatedAt: new Date() }); this.saveToDisk(); }
    return this.folders.get(id);
  };
  deleteFolder = (id: string) => { const result = this.folders.delete(id); this.saveToDisk(); return result; };

  // ============ VERSIONS ============
  createVersion = (version: FileVersion) => { this.versions.set(version.id, version); this.saveToDisk(); return version; };
  getVersionsByFile = (fileId: string) => 
    [...this.versions.values()]
      .filter(v => v.fileId === fileId)
      .sort((a, b) => b.version - a.version);
  findVersionById = (id: string) => this.versions.get(id);
  deleteVersion = (id: string) => { const result = this.versions.delete(id); this.saveToDisk(); return result; };
  deleteVersionsByFile = (fileId: string) => {
    for (const [id, version] of this.versions) {
      if (version.fileId === fileId) this.versions.delete(id);
    }
    this.saveToDisk();
  };

  // ============ CATEGORIES ============
  createCategory = (data: Omit<Category, 'id' | 'createdAt' | 'updatedAt' | 'order'> & { order?: number }) => {
    const category: Category = {
      ...data,
      id: uuid(),
      order: data.order ?? [...this.categories.values()].filter(c => c.ownerId === data.ownerId).length,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.categories.set(category.id, category); 
    this.saveToDisk(); 
    return category; 
  };
  findCategoryById = (id: string) => this.categories.get(id);
  getCategoriesByUser = (userId: string) => 
    [...this.categories.values()]
      .filter(c => c.ownerId === userId)
      .sort((a, b) => a.order - b.order);
  findCategoryByName = (name: string, userId: string) =>
    [...this.categories.values()].find(c => c.name.toLowerCase() === name.toLowerCase() && c.ownerId === userId);
  updateCategory = (id: string, data: Partial<Category>) => {
    const category = this.categories.get(id);
    if (category) { 
      this.categories.set(id, { ...category, ...data, updatedAt: new Date() }); 
      this.saveToDisk(); 
    }
    return this.categories.get(id);
  };
  deleteCategory = (id: string) => { 
    // Remove category from all files
    for (const [fileId, file] of this.files) {
      if (file.categoryId === id) {
        file.categoryId = undefined;
      }
    }
    const result = this.categories.delete(id); 
    this.saveToDisk(); 
    return result; 
  };
  getCategoryFileCount = (categoryId: string, userId: string) =>
    [...this.files.values()].filter(f => f.categoryId === categoryId && f.ownerId === userId && f.status === FileStatus.ACTIVE).length;

  // ============ ANNOTATIONS ============
  createAnnotation = (data: Omit<FileAnnotation, 'id' | 'createdAt' | 'updatedAt' | 'pinned'> & { pinned?: boolean }) => {
    const annotation: FileAnnotation = {
      ...data,
      id: uuid(),
      pinned: data.pinned ?? false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.annotations.set(annotation.id, annotation); 
    this.saveToDisk(); 
    return annotation; 
  };
  findAnnotationById = (id: string) => this.annotations.get(id);
  getAnnotationsByFile = (fileId: string) => 
    [...this.annotations.values()]
      .filter(a => a.fileId === fileId)
      .sort((a, b) => {
        if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
        return b.createdAt.getTime() - a.createdAt.getTime();
      });
  getAnnotationsByUser = (userId: string) =>
    [...this.annotations.values()].filter(a => a.userId === userId);
  updateAnnotation = (id: string, data: Partial<FileAnnotation>) => {
    const annotation = this.annotations.get(id);
    if (annotation) { 
      this.annotations.set(id, { ...annotation, ...data, updatedAt: new Date() }); 
      this.saveToDisk(); 
    }
    return this.annotations.get(id);
  };
  deleteAnnotation = (id: string) => { const result = this.annotations.delete(id); this.saveToDisk(); return result; };
  deleteAnnotationsByFile = (fileId: string) => {
    for (const [id, annotation] of this.annotations) {
      if (annotation.fileId === fileId) this.annotations.delete(id);
    }
    this.saveToDisk();
  };
  getFilesWithAnnotations = (userId: string) => {
    const fileIds = new Set([...this.annotations.values()].filter(a => a.userId === userId).map(a => a.fileId));
    return [...this.files.values()].filter(f => fileIds.has(f.id) && f.status === FileStatus.ACTIVE);
  };

  // ============ BOOKMARKS ============
  createBookmark = (data: Omit<Bookmark, 'id' | 'createdAt' | 'label'> & { label?: string }) => {
    const bookmark: Bookmark = {
      ...data,
      id: uuid(),
      label: data.label ?? 'Bookmark',
      createdAt: new Date(),
    };
    this.bookmarks.set(bookmark.id, bookmark); 
    this.saveToDisk(); 
    return bookmark; 
  };
  findBookmarkById = (id: string) => this.bookmarks.get(id);
  getBookmarksByUser = (userId: string) =>
    [...this.bookmarks.values()]
      .filter(b => b.userId === userId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  getBookmarksByFile = (fileId: string) =>
    [...this.bookmarks.values()].filter(b => b.fileId === fileId);
  findUserBookmarkForFile = (userId: string, fileId: string) =>
    [...this.bookmarks.values()].find(b => b.userId === userId && b.fileId === fileId);
  updateBookmark = (id: string, data: Partial<Bookmark>) => {
    const bookmark = this.bookmarks.get(id);
    if (bookmark) { this.bookmarks.set(id, { ...bookmark, ...data }); this.saveToDisk(); }
    return this.bookmarks.get(id);
  };
  deleteBookmark = (id: string) => { const result = this.bookmarks.delete(id); this.saveToDisk(); return result; };
  deleteBookmarksByFile = (fileId: string) => {
    for (const [id, bookmark] of this.bookmarks) {
      if (bookmark.fileId === fileId) this.bookmarks.delete(id);
    }
    this.saveToDisk();
  };

  // ============ TEMPLATES ============
  createTemplate = (data: Omit<FileTemplate, 'id' | 'createdAt' | 'updatedAt' | 'usageCount' | 'isPublic' | 'storedName' | 'size'> & { isPublic?: boolean; content: string }) => {
    // Store the content in a template file
    const storedName = `template_${uuid()}.json`;
    const contentBuffer = Buffer.from(data.content, 'utf-8');
    const storedPath = path.join(config.uploadDir, 'templates', storedName);
    
    // Ensure templates directory exists
    const templatesDir = path.join(config.uploadDir, 'templates');
    if (!fs.existsSync(templatesDir)) {
      fs.mkdirSync(templatesDir, { recursive: true });
    }
    fs.writeFileSync(storedPath, contentBuffer);
    
    const template: FileTemplate = {
      id: uuid(),
      name: data.name,
      description: data.description,
      mimeType: data.mimeType,
      storedName,
      size: contentBuffer.length,
      category: data.category,
      ownerId: data.ownerId,
      isPublic: data.isPublic ?? false,
      usageCount: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.templates.set(template.id, template); 
    this.saveToDisk(); 
    return template; 
  };
  
  getTemplateContent = (template: FileTemplate): string | null => {
    const storedPath = path.join(config.uploadDir, 'templates', template.storedName);
    if (!fs.existsSync(storedPath)) return null;
    return fs.readFileSync(storedPath, 'utf-8');
  };
  findTemplateById = (id: string) => this.templates.get(id);
  getTemplatesByUser = (userId: string) =>
    [...this.templates.values()].filter(t => t.ownerId === userId || t.isPublic);
  getPublicTemplates = () =>
    [...this.templates.values()].filter(t => t.isPublic);
  getTemplatesByCategory = (category: string) =>
    [...this.templates.values()].filter(t => t.category === category && t.isPublic);
  updateTemplate = (id: string, data: Partial<FileTemplate>) => {
    const template = this.templates.get(id);
    if (template) { this.templates.set(id, { ...template, ...data, updatedAt: new Date() }); this.saveToDisk(); }
    return this.templates.get(id);
  };
  deleteTemplate = (id: string) => { const result = this.templates.delete(id); this.saveToDisk(); return result; };
  incrementTemplateUsage = (id: string) => {
    const template = this.templates.get(id);
    if (template) {
      template.usageCount++;
      this.templates.set(id, template);
      this.saveToDisk();
    }
  };

  // ============ SAVED FILTERS ============
  createSavedFilter = (data: Omit<SavedFilter, 'id' | 'createdAt' | 'isDefault'> & { isDefault?: boolean }) => {
    const filter: SavedFilter = {
      ...data,
      id: uuid(),
      isDefault: data.isDefault ?? false,
      createdAt: new Date(),
    };
    this.savedFilters.set(filter.id, filter); 
    this.saveToDisk(); 
    return filter; 
  };
  findSavedFilterById = (id: string) => this.savedFilters.get(id);
  getSavedFiltersByUser = (userId: string) =>
    [...this.savedFilters.values()].filter(f => f.userId === userId);
  getDefaultFilter = (userId: string) =>
    [...this.savedFilters.values()].find(f => f.userId === userId && f.isDefault);
  updateSavedFilter = (id: string, data: Partial<SavedFilter>) => {
    const filter = this.savedFilters.get(id);
    if (filter) { this.savedFilters.set(id, { ...filter, ...data }); this.saveToDisk(); }
    return this.savedFilters.get(id);
  };
  deleteSavedFilter = (id: string) => { const result = this.savedFilters.delete(id); this.saveToDisk(); return result; };
  setDefaultFilter = (userId: string, filterId: string) => {
    // Clear existing default
    for (const [id, filter] of this.savedFilters) {
      if (filter.userId === userId && filter.isDefault) {
        filter.isDefault = false;
      }
    }
    // Set new default
    const filter = this.savedFilters.get(filterId);
    if (filter && filter.userId === userId) {
      filter.isDefault = true;
      this.saveToDisk();
    }
  };

  // ============ SHARE LINKS ============
  createShareLink = (link: ShareLink) => { 
    this.shareLinks.set(link.id, link); 
    this.saveToDisk(); 
    return link; 
  };
  findShareLinkById = (id: string) => this.shareLinks.get(id);
  findShareLinkByToken = (token: string) => 
    [...this.shareLinks.values()].find(l => l.accessToken === token);
  getShareLinksByFile = (fileId: string) => 
    [...this.shareLinks.values()].filter(l => l.fileId === fileId);
  getShareLinksByUser = (userId: string) =>
    [...this.shareLinks.values()].filter(l => l.createdBy === userId);
  updateShareLink = (id: string, data: Partial<ShareLink>) => {
    const link = this.shareLinks.get(id);
    if (link) { 
      this.shareLinks.set(id, { ...link, ...data }); 
      this.saveToDisk(); 
    }
    return this.shareLinks.get(id);
  };
  deleteShareLink = (id: string) => { 
    const result = this.shareLinks.delete(id); 
    this.saveToDisk(); 
    return result; 
  };
  deleteShareLinksByFile = (fileId: string) => {
    for (const [id, link] of this.shareLinks) {
      if (link.fileId === fileId) this.shareLinks.delete(id);
    }
    this.saveToDisk();
  };

  // ============ SECURITY EVENTS ============
  logSecurityEvent = (event: Omit<SecurityEvent, 'id' | 'timestamp'>) => {
    const fullEvent: SecurityEvent = {
      ...event,
      id: uuid(),
      timestamp: new Date(),
    };
    this.securityEvents.push(fullEvent);
    // Keep only last 10000 events
    if (this.securityEvents.length > 10000) {
      this.securityEvents = this.securityEvents.slice(-10000);
    }
    this.saveToDisk();
    return fullEvent;
  };
  getSecurityEvents = (limit = 100) =>
    [...this.securityEvents].reverse().slice(0, limit);
  getSecurityEventsByUser = (userId: string, limit = 50) =>
    [...this.securityEvents].filter(e => e.userId === userId).reverse().slice(0, limit);
  getSecurityEventsByType = (eventType: SecurityEventType, limit = 50) =>
    [...this.securityEvents].filter(e => e.eventType === eventType).reverse().slice(0, limit);

  // ============ NOTIFICATIONS ============
  createNotification = (notification: Notification) => { 
    this.notifications.set(notification.id, notification); 
    this.saveToDisk();
    return notification; 
  };
  getNotificationsByUser = (userId: string, unreadOnly = false) =>
    [...this.notifications.values()]
      .filter(n => n.userId === userId && (!unreadOnly || !n.read))
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  getUnreadCount = (userId: string) =>
    [...this.notifications.values()].filter(n => n.userId === userId && !n.read).length;
  markNotificationRead = (id: string) => {
    const notification = this.notifications.get(id);
    if (notification) {
      notification.read = true;
      this.notifications.set(id, notification);
      this.saveToDisk();
    }
  };
  markAllNotificationsRead = (userId: string) => {
    for (const [id, notification] of this.notifications) {
      if (notification.userId === userId) {
        notification.read = true;
      }
    }
    this.saveToDisk();
  };
  deleteNotification = (id: string) => { const result = this.notifications.delete(id); this.saveToDisk(); return result; };

  // ============ SESSIONS ============
  createSession = (session: Session) => { 
    // Enforce max sessions per user
    const userSessions = this.getSessionsByUser(session.userId);
    if (userSessions.length >= config.maxSessionsPerUser) {
      // Remove oldest session
      const oldest = userSessions.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())[0];
      this.sessions.delete(oldest.id);
    }
    this.sessions.set(session.id, session); 
    this.saveToDisk();
    return session; 
  };
  findSessionById = (id: string) => this.sessions.get(id);
  findSessionByToken = (token: string) => 
    [...this.sessions.values()].find(s => s.token === token && s.expiresAt > new Date());
  getSessionsByUser = (userId: string) =>
    [...this.sessions.values()].filter(s => s.userId === userId && s.expiresAt > new Date());
  updateSession = (id: string, data: Partial<Session>) => {
    const session = this.sessions.get(id);
    if (session) { this.sessions.set(id, { ...session, ...data }); this.saveToDisk(); }
    return this.sessions.get(id);
  };
  deleteSession = (id: string) => { const result = this.sessions.delete(id); this.saveToDisk(); return result; };
  deleteSessionsByUser = (userId: string) => {
    for (const [id, session] of this.sessions) {
      if (session.userId === userId) this.sessions.delete(id);
    }
    this.saveToDisk();
  };

  // ============ TAGS ============
  createTag = (tag: Tag) => { this.tags.set(tag.id, tag); this.saveToDisk(); return tag; };
  getTagsByUser = (userId: string) => 
    [...this.tags.values()].filter(t => t.ownerId === userId);
  findTagById = (id: string) => this.tags.get(id);
  findTagByName = (name: string, userId: string) =>
    [...this.tags.values()].find(t => t.name.toLowerCase() === name.toLowerCase() && t.ownerId === userId);
  updateTag = (id: string, data: Partial<Tag>) => {
    const tag = this.tags.get(id);
    if (tag) { this.tags.set(id, { ...tag, ...data }); this.saveToDisk(); }
    return this.tags.get(id);
  };
  deleteTag = (id: string) => { const result = this.tags.delete(id); this.saveToDisk(); return result; };

  // ============ ACTIVITY FEED ============
  addActivity = (activity: Omit<ActivityFeed, 'id' | 'createdAt'>) => {
    const full: ActivityFeed = {
      ...activity,
      id: uuid(),
      createdAt: new Date(),
    };
    this.activities.push(full);
    // Keep only last 1000 activities
    if (this.activities.length > 1000) {
      this.activities = this.activities.slice(-1000);
    }
    this.saveToDisk();
    return full;
  };
  getActivitiesByUser = (userId: string, limit = 20) =>
    [...this.activities]
      .filter(a => a.userId === userId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, limit);

  // ============ RATE LIMITING ============
  checkRateLimit = (key: string, maxRequests: number, windowMs: number): boolean => {
    const now = new Date();
    const entry = this.rateLimits.get(key);
    
    if (!entry || entry.resetAt < now) {
      this.rateLimits.set(key, { count: 1, resetAt: new Date(now.getTime() + windowMs) });
      return true;
    }
    
    if (entry.count >= maxRequests) {
      return false;
    }
    
    entry.count++;
    return true;
  };
  
  getRateLimitRemaining = (key: string, maxRequests: number): number => {
    const entry = this.rateLimits.get(key);
    if (!entry || entry.resetAt < new Date()) return maxRequests;
    return Math.max(0, maxRequests - entry.count);
  };

  // ============ AUDIT ============
  log = (userId: string, action: string, target: string, details = '', ipAddress?: string, userAgent?: string, severity: 'info' | 'warning' | 'critical' = 'info') => {
    this.logs.push({ 
      id: uuid(), 
      userId, 
      action, 
      target, 
      details, 
      ipAddress,
      userAgent,
      severity,
      timestamp: new Date() 
    });
    // Keep last 5000 logs
    if (this.logs.length > 5000) {
      this.logs = this.logs.slice(-5000);
    }
    this.saveToDisk();
  };
  getLogs = (limit = 100) => [...this.logs].reverse().slice(0, limit);
  getLogsByUser = (userId: string, limit = 20) => 
    [...this.logs].reverse().filter(l => l.userId === userId).slice(0, limit);
  getActivityLogs = (userId: string) => 
    [...this.logs].reverse().filter(l => l.userId === userId);
  getLogsByAction = (action: string, limit = 50) =>
    [...this.logs].reverse().filter(l => l.action === action).slice(0, limit);
  getLogsByDateRange = (start: Date, end: Date) =>
    [...this.logs].filter(l => l.timestamp >= start && l.timestamp <= end);
  getLogsBySeverity = (severity: 'info' | 'warning' | 'critical', limit = 50) =>
    [...this.logs].reverse().filter(l => l.severity === severity).slice(0, limit);

  // ============ NOTIFICATIONS HELPER ============
  notify = (userId: string, type: NotificationType, title: string, message: string, data?: Record<string, unknown>) => {
    return this.createNotification({
      id: uuid(),
      userId,
      type,
      title,
      message,
      data,
      read: false,
      createdAt: new Date(),
    });
  };

  // ============ STATS ============
  getSystemStats = () => {
    const files = [...this.files.values()];
    const users = [...this.users.values()];
    return {
      totalUsers: users.length,
      totalFiles: files.filter(f => f.status === FileStatus.ACTIVE).length,
      trashedFiles: files.filter(f => f.status === FileStatus.TRASHED).length,
      totalStorage: files.reduce((sum, f) => sum + f.size, 0),
      encryptedFiles: files.filter(f => f.encrypted && f.status === FileStatus.ACTIVE).length,
      totalDownloads: files.reduce((sum, f) => sum + f.downloadCount, 0),
      totalCategories: this.categories.size,
      totalTemplates: this.templates.size,
      totalAnnotations: this.annotations.size,
      totalBookmarks: this.bookmarks.size,
      activeSessions: [...this.sessions.values()].filter(s => s.expiresAt > new Date()).length,
      securityEventsToday: this.securityEvents.filter(e => {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        return e.timestamp >= today;
      }).length,
    };
  };

  // ============ DASHBOARD STATS ============
  getUserDashboardStats = (userId: string) => {
    const user = this.users.get(userId);
    const files = this.getFilesByUser(userId);
    const bookmarks = this.getBookmarksByUser(userId);
    const annotations = this.getAnnotationsByUser(userId);
    const recentActivity = this.getActivitiesByUser(userId, 10);
    
    return {
      totalFiles: files.length,
      encryptedFiles: files.filter(f => f.encrypted).length,
      totalSize: files.reduce((sum, f) => sum + f.size, 0),
      favoriteCount: this.getFavorites(userId).length,
      trashCount: this.getTrashedFiles(userId).length,
      bookmarkCount: bookmarks.length,
      annotationCount: annotations.length,
      storageUsed: user?.storageUsed || 0,
      storageQuota: user?.storageQuota || 0,
      storagePercent: user ? Math.round((user.storageUsed / user.storageQuota) * 100) : 0,
      recentActivity,
      unreadNotifications: this.getUnreadCount(userId),
    };
  };
}

export const db = new DB();
