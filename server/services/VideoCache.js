/**
 * Redis-based Video Caching Service for VEO 3.0 responses
 * Implements CDN-style caching with speed optimization
 */

import Redis from 'ioredis';

class VideoCache {
  constructor() {
    this.redis = null;
    this.fallbackCache = new Map(); // In-memory fallback
    this.maxFallbackSize = 10; // Reduced memory footprint
    this.initRedis();
    // Memory cleanup every 15 minutes
    this.cleanupInterval = setInterval(() => this.cleanupMemory(), 15 * 60 * 1000);
  }

  async initRedis() {
    try {
      this.redis = new Redis({
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD,
        retryDelayOnFailover: 100,
        lazyConnect: true,
        maxRetriesPerRequest: 1,
        connectTimeout: 2000,
        commandTimeout: 2000,
        enableOfflineQueue: false,
        maxRetriesPerRequest: null
      });

      // Suppress Redis connection error events
      this.redis.on('error', () => {
        // Silently handle Redis errors - fallback to memory cache
        this.redis = null;
      });

      await this.redis.connect();
      console.log('✅ Redis connected for VEO 3.0 video caching');
    } catch (error) {
      console.log('📦 Using in-memory cache (Redis unavailable)');
      this.redis = null;
    }
  }

  /**
   * Memory-efficient video caching
   * @param {string} promptHash - Hash of video prompt for caching key
   * @param {Object} videoData - VEO 3.0 response data
   * @param {number} ttl - Time to live in seconds (reduced to 6 hours)
   */
  async cacheVideo(promptHash, videoData, ttl = 6 * 60 * 60) {
    const cacheKey = `veo3:video:${promptHash}`;
    const cacheData = {
      ...videoData,
      cachedAt: Date.now(),
      ttl: ttl
    };

    try {
      if (this.redis) {
        await this.redis.setex(cacheKey, ttl, JSON.stringify(cacheData));
        console.log(`📦 VEO 3.0 video cached with Redis: ${cacheKey}`);
      } else {
        // Memory-conscious fallback cache
        if (this.fallbackCache.size >= this.maxFallbackSize) {
          // Remove oldest entry to prevent memory bloat
          const firstKey = this.fallbackCache.keys().next().value;
          this.fallbackCache.delete(firstKey);
        }
        this.fallbackCache.set(cacheKey, {
          data: { videoUrl: cacheData.videoUrl, videoId: cacheData.videoId },
          expiry: Date.now() + (ttl * 1000)
        });
        console.log(`📦 Video cached in memory (${this.fallbackCache.size}/${this.maxFallbackSize})`);
      }
    } catch (error) {
      console.error('❌ Video caching error:', error.message);
    }
  }

  /**
   * Retrieve cached video with CDN-style speed optimization
   * @param {string} promptHash - Hash of video prompt
   * @returns {Object|null} - Cached video data or null
   */
  async getCachedVideo(promptHash) {
    const cacheKey = `veo3:video:${promptHash}`;

    try {
      if (this.redis) {
        const cached = await this.redis.get(cacheKey);
        if (cached) {
          const videoData = JSON.parse(cached);
          console.log(`⚡ Redis cache hit for VEO 3.0 video: ${cacheKey}`);
          return videoData;
        }
      } else {
        // Check memory cache
        const cached = this.fallbackCache.get(cacheKey);
        if (cached && cached.expiry > Date.now()) {
          console.log(`⚡ Memory cache hit for VEO 3.0 video: ${cacheKey}`);
          return cached.data;
        } else if (cached) {
          // Expired - remove from memory
          this.fallbackCache.delete(cacheKey);
        }
      }

      console.log(`❌ Cache miss for VEO 3.0 video: ${cacheKey}`);
      return null;
    } catch (error) {
      console.error('❌ Video cache retrieval error:', error.message);
      return null;
    }
  }

  /**
   * Generate cache key hash from prompt and config
   * @param {string} prompt - Video generation prompt
   * @param {Object} config - Generation configuration
   * @returns {string} - Hash for caching
   */
  async generateCacheKey(prompt, config) {
    const crypto = await import('crypto');
    const cacheInput = `${prompt}-${JSON.stringify(config)}`;
    return crypto.createHash('md5').update(cacheInput).digest('hex');
  }

  /**
   * Clear expired cache entries (cleanup)
   */
  async clearExpiredCache() {
    if (!this.redis) {
      // Clean memory cache
      const now = Date.now();
      for (const [key, value] of this.fallbackCache.entries()) {
        if (value.expiry <= now) {
          this.fallbackCache.delete(key);
        }
      }
      console.log('🧹 Memory cache cleanup completed');
      return;
    }

    try {
      const keys = await this.redis.keys('veo3:video:*');
      const pipeline = this.redis.pipeline();
      
      for (const key of keys) {
        const ttl = await this.redis.ttl(key);
        if (ttl <= 0) {
          pipeline.del(key);
        }
      }
      
      await pipeline.exec();
      console.log(`🧹 Redis cache cleanup: ${keys.length} keys processed`);
    } catch (error) {
      console.error('❌ Cache cleanup error:', error.message);
    }
  }

  /**
   * Get cache statistics
   */
  async getCacheStats() {
    try {
      if (this.redis) {
        const keys = await this.redis.keys('veo3:video:*');
        const memory = await this.redis.memory('usage');
        return {
          type: 'Redis',
          totalKeys: keys.length,
          memoryUsage: memory,
          connected: true
        };
      } else {
        return {
          type: 'Memory',
          totalKeys: this.fallbackCache.size,
          memoryUsage: 'N/A',
          connected: false
        };
      }
    } catch (error) {
      return {
        type: 'Error',
        error: error.message,
        connected: false
      };
    }
  }
}

// Export singleton instance
export default new VideoCache();