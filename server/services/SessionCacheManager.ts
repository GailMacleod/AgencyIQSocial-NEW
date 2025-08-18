/**
 * SESSION CACHE MANAGER - REDIS PERSISTENCE FIX
 * Addresses session drops mid-onboarding and pipeline data loss
 * Implements Redis backing with HTTPS/SameSite enforcement
 */

import session from 'express-session';

// Redis imports with fallback handling
let Redis: any = null;
let connectRedis: any = null;

try {
  Redis = await import('ioredis').then(m => m.default);
  connectRedis = await import('connect-redis').then(m => m.default);
} catch (error) {
  console.warn('⚠️ Redis packages not available, using PostgreSQL fallback only');
}

interface SessionCacheOptions {
  redisUrl?: string;
  sessionSecret: string;
  cookieDomain?: string;
  isProduction?: boolean;
}

export class SessionCacheManager {
  private redis: any = null;
  private redisStore: any = null;
  private sessionMiddleware: any = null;

  constructor(options: SessionCacheOptions) {
    this.initializeRedis(options);
    this.createSessionMiddleware(options);
  }

  /**
   * Initialize Redis connection with fallback handling
   */
  private initializeRedis(options: SessionCacheOptions): void {
    try {
      // Try Redis connection if URL provided and Redis available
      if (options.redisUrl && Redis) {
        this.redis = new Redis(options.redisUrl, {
          retryDelayOnFailover: 100,
          maxRetriesPerRequest: 3,
          connectTimeout: 5000,
          lazyConnect: true
        });

        // Test connection
        this.redis.ping().then(() => {
          console.log('✅ Redis session cache connected successfully');
        }).catch((err: any) => {
          console.warn('⚠️ Redis connection failed, falling back to PostgreSQL:', err.message);
          this.redis = null;
        });
      } else if (!Redis) {
        console.warn('⚠️ Redis not available, using PostgreSQL session store only');
      }
    } catch (error) {
      console.warn('⚠️ Redis initialization failed:', error);
      this.redis = null;
    }
  }

  /**
   * Create session middleware with Redis or PostgreSQL fallback
   */
  private createSessionMiddleware(options: SessionCacheOptions): void {
    const sessionConfig: any = {
      secret: options.sessionSecret,
      resave: false,
      saveUninitialized: false,
      rolling: true, // Extend session on activity
      cookie: {
        maxAge: 30 * 60 * 1000, // 30 minutes
        httpOnly: false, // Allow frontend access
        secure: options.isProduction, // HTTPS in production
        sameSite: options.isProduction ? 'strict' : 'lax' // CSRF protection
      }
    };

    // Use Redis store if available, otherwise PostgreSQL
    if (this.redis && connectRedis) {
      try {
        const RedisStore = connectRedis(session);
        this.redisStore = new RedisStore({ client: this.redis });
        sessionConfig.store = this.redisStore;
        console.log('🔧 Session store: Redis (persistent)');
      } catch (error) {
        console.warn('⚠️ Redis store creation failed, using PostgreSQL:', error);
        this.setupPostgreSQLStore(sessionConfig);
      }
    } else {
      this.setupPostgreSQLStore(sessionConfig);
    }

    this.sessionMiddleware = session(sessionConfig);
  }

  /**
   * Setup PostgreSQL session store as fallback
   */
  private setupPostgreSQLStore(sessionConfig: any): void {
    try {
      const pgSession = (await import('connect-pg-simple')).default(session);
      sessionConfig.store = new pgSession({
        conString: process.env.DATABASE_URL,
        tableName: 'sessions',
        createTableIfMissing: false
      });
      console.log('🔧 Session store: PostgreSQL (fallback)');
    } catch (error) {
      console.error('❌ PostgreSQL session store setup failed:', error);
      // Continue without store - will use memory store
    }
  }

  /**
   * Get session middleware for Express app
   */
  getSessionMiddleware() {
    return this.sessionMiddleware;
  }

  /**
   * Enhanced session destroy with cleanup
   */
  async destroySession(sessionId: string): Promise<boolean> {
    try {
      if (this.redis) {
        // Redis session destruction
        await this.redis.del(`sess:${sessionId}`);
        console.log(`✅ Redis session destroyed: ${sessionId}`);
      } else if (this.redisStore) {
        // PostgreSQL session destruction
        return new Promise((resolve) => {
          this.redisStore.destroy(sessionId, (err: any) => {
            if (err) {
              console.error('❌ PostgreSQL session destruction failed:', err);
              resolve(false);
            } else {
              console.log(`✅ PostgreSQL session destroyed: ${sessionId}`);
              resolve(true);
            }
          });
        });
      }
      return true;
    } catch (error) {
      console.error('❌ Session destruction failed:', error);
      return false;
    }
  }

  /**
   * Cache JTBD pipeline data to prevent loss during Brand Purpose waterfall
   */
  async cachePipelineData(userId: number, pipelineData: any): Promise<boolean> {
    try {
      const cacheKey = `pipeline:${userId}`;
      const dataWithTimestamp = {
        ...pipelineData,
        cachedAt: new Date().toISOString(),
        ttl: 2 * 60 * 60 // 2 hours
      };

      if (this.redis) {
        await this.redis.setex(cacheKey, 2 * 60 * 60, JSON.stringify(dataWithTimestamp));
        console.log(`✅ Pipeline data cached for user ${userId}`);
      } else {
        // Fallback to global memory cache (less reliable but better than nothing)
        global.pipelineCache = global.pipelineCache || {};
        global.pipelineCache[cacheKey] = dataWithTimestamp;
        console.log(`⚠️ Pipeline data cached in memory for user ${userId}`);
      }
      return true;
    } catch (error) {
      console.error('❌ Pipeline data caching failed:', error);
      return false;
    }
  }

  /**
   * Retrieve cached pipeline data
   */
  async getCachedPipelineData(userId: number): Promise<any> {
    try {
      const cacheKey = `pipeline:${userId}`;

      if (this.redis) {
        const cached = await this.redis.get(cacheKey);
        if (cached) {
          const data = JSON.parse(cached);
          console.log(`✅ Pipeline data retrieved from Redis for user ${userId}`);
          return data;
        }
      } else {
        // Check global memory cache
        const cached = global.pipelineCache?.[cacheKey];
        if (cached) {
          // Check TTL
          const cachedTime = new Date(cached.cachedAt).getTime();
          const now = Date.now();
          if (now - cachedTime < cached.ttl * 1000) {
            console.log(`✅ Pipeline data retrieved from memory for user ${userId}`);
            return cached;
          } else {
            // Expired, remove from cache
            delete global.pipelineCache[cacheKey];
          }
        }
      }

      console.log(`ℹ️ No cached pipeline data found for user ${userId}`);
      return null;
    } catch (error) {
      console.error('❌ Pipeline data retrieval failed:', error);
      return null;
    }
  }

  /**
   * Clear pipeline cache after successful completion
   */
  async clearPipelineCache(userId: number): Promise<boolean> {
    try {
      const cacheKey = `pipeline:${userId}`;

      if (this.redis) {
        await this.redis.del(cacheKey);
        console.log(`✅ Pipeline cache cleared for user ${userId}`);
      } else {
        if (global.pipelineCache?.[cacheKey]) {
          delete global.pipelineCache[cacheKey];
          console.log(`✅ Pipeline memory cache cleared for user ${userId}`);
        }
      }
      return true;
    } catch (error) {
      console.error('❌ Pipeline cache clearing failed:', error);
      return false;
    }
  }

  /**
   * Health check for Redis connection
   */
  async healthCheck(): Promise<{ redis: boolean; store: string }> {
    let redisHealthy = false;
    
    if (this.redis) {
      try {
        await this.redis.ping();
        redisHealthy = true;
      } catch (error) {
        console.warn('Redis health check failed:', error);
      }
    }

    return {
      redis: redisHealthy,
      store: this.redis ? 'Redis' : 'PostgreSQL'
    };
  }
}

export default SessionCacheManager;