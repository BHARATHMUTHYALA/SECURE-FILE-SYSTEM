/**
 * Global Rate Limiting System
 * Feature 2: IP-based rate limiting with per-endpoint limits
 */

import { Request, Response, NextFunction } from 'express';
import { getClientIp } from './middleware';

interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
}

interface RateLimitEntry {
  count: number;
  resetAt: Date;
  blocked: boolean;
  blockUntil?: Date;
}

class GlobalRateLimiter {
  private limits = new Map<string, RateLimitEntry>();
  private endpointConfigs: Map<string, RateLimitConfig> = new Map();
  private globalConfig: RateLimitConfig = {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 100, // 100 requests per minute globally
  };

  constructor() {
    // Define per-endpoint limits
    this.endpointConfigs.set('/api/auth/login', { windowMs: 15 * 60 * 1000, maxRequests: 5 }); // 5 per 15 min
    this.endpointConfigs.set('/api/auth/register', { windowMs: 60 * 60 * 1000, maxRequests: 3 }); // 3 per hour
    this.endpointConfigs.set('/api/files/upload', { windowMs: 60 * 1000, maxRequests: 10 }); // 10 per minute
    this.endpointConfigs.set('/api/decrypt-file', { windowMs: 60 * 60 * 1000, maxRequests: 5 }); // 5 per hour
    this.endpointConfigs.set('/api/files/:id/share-link', { windowMs: 60 * 1000, maxRequests: 20 }); // 20 per minute
    this.endpointConfigs.set('/api/files/download-multiple', { windowMs: 5 * 60 * 1000, maxRequests: 5 }); // 5 per 5 min
    
    // Cleanup old entries every 5 minutes
    setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  private cleanup() {
    const now = new Date();
    for (const [key, entry] of this.limits) {
      if (entry.resetAt < now && (!entry.blocked || (entry.blockUntil && entry.blockUntil < now))) {
        this.limits.delete(key);
      }
    }
  }

  private getKey(ip: string, endpoint: string): string {
    return `${ip}:${endpoint}`;
  }

  private getConfig(endpoint: string): RateLimitConfig {
    // Normalize endpoint (remove IDs)
    const normalized = endpoint.replace(/\/[0-9a-f-]{36}/gi, '/:id');
    return this.endpointConfigs.get(normalized) || this.globalConfig;
  }

  check(req: Request): { allowed: boolean; remaining: number; resetAt: Date; reason?: string } {
    const ip = getClientIp(req);
    const endpoint = req.path;
    const key = this.getKey(ip, endpoint);
    const config = this.getConfig(endpoint);
    const now = new Date();

    let entry = this.limits.get(key);

    // Check if IP is blocked
    if (entry?.blocked && entry.blockUntil && entry.blockUntil > now) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: entry.blockUntil,
        reason: 'IP temporarily blocked due to excessive requests',
      };
    }

    // Reset if window expired
    if (!entry || entry.resetAt < now) {
      entry = {
        count: 1,
        resetAt: new Date(now.getTime() + config.windowMs),
        blocked: false,
      };
      this.limits.set(key, entry);
      return {
        allowed: true,
        remaining: config.maxRequests - 1,
        resetAt: entry.resetAt,
      };
    }

    // Increment count
    entry.count++;

    // Check if limit exceeded
    if (entry.count > config.maxRequests) {
      // Block IP for 15 minutes after exceeding limit 3 times
      const blockKey = `${ip}:blocks`;
      let blockEntry = this.limits.get(blockKey);
      
      if (!blockEntry || blockEntry.resetAt < now) {
        blockEntry = {
          count: 1,
          resetAt: new Date(now.getTime() + 60 * 60 * 1000), // 1 hour window
          blocked: false,
        };
      } else {
        blockEntry.count++;
      }

      if (blockEntry.count >= 3) {
        entry.blocked = true;
        entry.blockUntil = new Date(now.getTime() + 15 * 60 * 1000); // Block for 15 minutes
        this.limits.set(blockKey, blockEntry);
        
        return {
          allowed: false,
          remaining: 0,
          resetAt: entry.blockUntil,
          reason: 'IP blocked due to repeated rate limit violations',
        };
      }

      this.limits.set(blockKey, blockEntry);

      return {
        allowed: false,
        remaining: 0,
        resetAt: entry.resetAt,
        reason: 'Rate limit exceeded',
      };
    }

    return {
      allowed: true,
      remaining: config.maxRequests - entry.count,
      resetAt: entry.resetAt,
    };
  }

  middleware() {
    return (req: Request, res: Response, next: NextFunction): void => {
      const result = this.check(req);

      // Set rate limit headers
      res.setHeader('X-RateLimit-Limit', result.remaining + (result.allowed ? 1 : 0));
      res.setHeader('X-RateLimit-Remaining', result.remaining);
      res.setHeader('X-RateLimit-Reset', result.resetAt.toISOString());

      if (!result.allowed) {
        res.setHeader('Retry-After', Math.ceil((result.resetAt.getTime() - Date.now()) / 1000));
        res.status(429).json({
          success: false,
          message: result.reason || 'Too many requests. Please try again later.',
          retryAfter: result.resetAt,
        });
        return;
      }

      next();
    };
  }

  // Get stats for monitoring
  getStats() {
    const now = new Date();
    const active = Array.from(this.limits.entries()).filter(([_, entry]) => entry.resetAt > now);
    const blocked = active.filter(([_, entry]) => entry.blocked);

    return {
      totalEntries: this.limits.size,
      activeEntries: active.length,
      blockedIPs: blocked.length,
      blockedList: blocked.map(([key]) => key.split(':')[0]),
    };
  }

  // Manually unblock an IP
  unblock(ip: string) {
    for (const [key, entry] of this.limits) {
      if (key.startsWith(ip + ':')) {
        entry.blocked = false;
        entry.blockUntil = undefined;
      }
    }
  }
}

export const globalRateLimiter = new GlobalRateLimiter();
