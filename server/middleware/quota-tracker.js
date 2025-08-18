/**
 * Quota Tracker Middleware
 * PostgreSQL-based API usage tracking and rate limiting
 */

import { dbManager } from '../db-init.js';

class QuotaTracker {
  constructor() {
    this.limits = {
      // API call limits per hour per user
      facebook: { posts: 50, calls: 200 },
      instagram: { posts: 25, calls: 200 },
      linkedin: { posts: 20, calls: 100 },
      twitter: { posts: 300, calls: 500 },
      youtube: { posts: 6, calls: 10000 },
      
      // General limits
      video_generation: { calls: 5 },
      auto_posting: { calls: 20 }
    };
  }

  async trackUsage(userId, platform, operation = 'call') {
    try {
      const db = dbManager.getDatabase();
      const currentHour = new Date();
      currentHour.setMinutes(0, 0, 0);

      // Insert or update usage record
      await db.execute(`
        INSERT INTO quota_usage (user_id, platform, operation, hour_window, count, created_at)
        VALUES ($1, $2, $3, $4, 1, NOW())
        ON CONFLICT (user_id, platform, operation, hour_window)
        DO UPDATE SET count = quota_usage.count + 1, updated_at = NOW()
      `, [userId, platform, operation, currentHour]);

      console.log(`📊 Quota tracked: User ${userId}, ${platform}, ${operation}`);
    } catch (error) {
      console.error('❌ Quota tracking failed:', error);
      // Don't throw - allow operation to continue even if tracking fails
    }
  }

  async checkQuota(userId, platform, operation = 'call') {
    try {
      const db = dbManager.getDatabase();
      const currentHour = new Date();
      currentHour.setMinutes(0, 0, 0);

      // Get current usage
      const result = await db.execute(`
        SELECT count FROM quota_usage 
        WHERE user_id = $1 AND platform = $2 AND operation = $3 AND hour_window = $4
      `, [userId, platform, operation, currentHour]);

      const currentUsage = result.rows[0]?.count || 0;
      const limit = this.limits[platform]?.[operation] || this.limits[platform]?.calls || 100;

      const withinQuota = currentUsage < limit;
      const remaining = Math.max(0, limit - currentUsage);

      console.log(`🔍 Quota check: User ${userId}, ${platform}, ${operation} - ${currentUsage}/${limit} (${remaining} remaining)`);

      return {
        withinQuota,
        currentUsage,
        limit,
        remaining,
        resetTime: new Date(currentHour.getTime() + 60 * 60 * 1000) // Next hour
      };
    } catch (error) {
      console.error('❌ Quota check failed:', error);
      // Fail open - allow operation if quota check fails
      return { withinQuota: true, currentUsage: 0, limit: 100, remaining: 100 };
    }
  }

  middleware() {
    return async (req, res, next) => {
      // Only apply to authenticated users
      if (!req.userId) {
        return next();
      }

      // Determine platform and operation from route
      const platform = this.detectPlatform(req);
      const operation = this.detectOperation(req);

      if (!platform) {
        return next();
      }

      try {
        const quotaStatus = await this.checkQuota(req.userId, platform, operation);
        
        if (!quotaStatus.withinQuota) {
          return res.status(429).json({
            error: 'Quota exceeded',
            message: `${platform} ${operation} limit exceeded. ${quotaStatus.currentUsage}/${quotaStatus.limit} used.`,
            quotaStatus,
            retryAfter: Math.ceil((quotaStatus.resetTime - new Date()) / 1000)
          });
        }

        // Track the usage for this request
        await this.trackUsage(req.userId, platform, operation);

        // Add quota info to response headers
        res.set({
          'X-RateLimit-Limit': quotaStatus.limit,
          'X-RateLimit-Remaining': quotaStatus.remaining - 1, // -1 for current request
          'X-RateLimit-Reset': Math.ceil(quotaStatus.resetTime.getTime() / 1000)
        });

        next();
      } catch (error) {
        console.error('❌ Quota middleware error:', error);
        next(); // Continue on error
      }
    };
  }

  detectPlatform(req) {
    const path = req.path.toLowerCase();
    const body = req.body || {};

    if (path.includes('facebook') || body.platform === 'facebook') return 'facebook';
    if (path.includes('instagram') || body.platform === 'instagram') return 'instagram';
    if (path.includes('linkedin') || body.platform === 'linkedin') return 'linkedin';
    if (path.includes('twitter') || path.includes('/x/') || body.platform === 'twitter' || body.platform === 'x') return 'twitter';
    if (path.includes('youtube') || body.platform === 'youtube') return 'youtube';
    if (path.includes('video')) return 'video_generation';
    if (path.includes('auto-post')) return 'auto_posting';

    return null;
  }

  detectOperation(req) {
    const path = req.path.toLowerCase();
    
    if (path.includes('post') || path.includes('publish')) return 'posts';
    if (path.includes('video')) return 'calls';
    
    return 'calls';
  }

  async getUserQuotaStatus(userId) {
    try {
      const db = dbManager.getDatabase();
      const currentHour = new Date();
      currentHour.setMinutes(0, 0, 0);

      const result = await db.execute(`
        SELECT platform, operation, count 
        FROM quota_usage 
        WHERE user_id = $1 AND hour_window = $2
      `, [userId, currentHour]);

      const usage = {};
      result.rows.forEach(row => {
        if (!usage[row.platform]) usage[row.platform] = {};
        usage[row.platform][row.operation] = row.count;
      });

      const status = {};
      Object.keys(this.limits).forEach(platform => {
        status[platform] = {};
        Object.keys(this.limits[platform]).forEach(operation => {
          const limit = this.limits[platform][operation];
          const used = usage[platform]?.[operation] || 0;
          const remaining = Math.max(0, limit - used);
          const percentage = Math.round((used / limit) * 100);

          status[platform][operation] = {
            used,
            limit,
            remaining,
            percentage,
            withinQuota: used < limit
          };
        });
      });

      return status;
    } catch (error) {
      console.error('❌ Get quota status failed:', error);
      return {};
    }
  }
}

// Create singleton instance
export const quotaTracker = new QuotaTracker();

// SQL to create quota_usage table
export const createQuotaTable = `
CREATE TABLE IF NOT EXISTS quota_usage (
  id SERIAL PRIMARY KEY,
  user_id VARCHAR(50) NOT NULL,
  platform VARCHAR(50) NOT NULL,
  operation VARCHAR(50) NOT NULL,
  hour_window TIMESTAMP NOT NULL,
  count INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, platform, operation, hour_window)
);

CREATE INDEX IF NOT EXISTS idx_quota_usage_user_platform ON quota_usage(user_id, platform);
CREATE INDEX IF NOT EXISTS idx_quota_usage_hour_window ON quota_usage(hour_window);
`;