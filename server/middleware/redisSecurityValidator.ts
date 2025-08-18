/**
 * CRITICAL: Redis Security Validator - 2025 CVE Protection
 * Addresses HIGH SEVERITY issue: Potential Redis vulns without version/patch checks
 * 
 * 2025 CVEs affecting Redis:
 * - Memory exhaustion vulnerabilities
 * - DoS attacks on unpatched versions
 * 
 * This middleware validates Redis version and falls back to PostgreSQL when needed
 */

import Redis from 'ioredis';

export class RedisSecurityValidator {
  private static instance: RedisSecurityValidator;
  private redisClient: Redis | null = null;
  private isValidated = false;
  private usePostgreSQLFallback = false;

  public static getInstance(): RedisSecurityValidator {
    if (!RedisSecurityValidator.instance) {
      RedisSecurityValidator.instance = new RedisSecurityValidator();
    }
    return RedisSecurityValidator.instance;
  }

  /**
   * CRITICAL: Check Redis version for known vulnerabilities
   * 2025 OWASP requirement - validate Redis version before use
   */
  public async validateRedisVersion(): Promise<{ isValid: boolean; shouldFallback: boolean; version?: string }> {
    try {
      if (!process.env.REDIS_URL && !process.env.REDIS_HOST) {
        console.log('🔄 [REDIS_SECURITY] No Redis configured, using PostgreSQL session storage');
        this.usePostgreSQLFallback = true;
        return { isValid: false, shouldFallback: true };
      }

      // Create Redis client for version check
      this.redisClient = new Redis({
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT || '6379'),
        maxRetriesPerRequest: 3,
        lazyConnect: true,
        connectTimeout: 5000,
        commandTimeout: 3000
      });

      // Get Redis server info
      const info = await this.redisClient.info('server');
      const versionMatch = info.match(/redis_version:(\d+\.\d+\.\d+)/);
      
      if (!versionMatch) {
        console.error('🚨 [REDIS_SECURITY] Cannot determine Redis version - using PostgreSQL fallback');
        this.usePostgreSQLFallback = true;
        return { isValid: false, shouldFallback: true };
      }

      const version = versionMatch[1];
      const [major, minor, patch] = version.split('.').map(Number);

      // Check for vulnerable versions (2025 security requirements)
      const isVulnerable = this.isVulnerableVersion(major, minor, patch);
      
      if (isVulnerable) {
        console.error(`🚨 [REDIS_SECURITY] Redis version ${version} has known vulnerabilities`);
        console.error('🚨 [REDIS_SECURITY] Update to Redis 7.4+ to fix CVE-2024-31449 and CVE-2025-21605');
        console.log('🔄 [REDIS_SECURITY] Falling back to PostgreSQL session storage for security');
        this.usePostgreSQLFallback = true;
        return { isValid: false, shouldFallback: true, version };
      }

      console.log(`✅ [REDIS_SECURITY] Redis version ${version} validated - secure for production use`);
      this.isValidated = true;
      return { isValid: true, shouldFallback: false, version };

    } catch (error: any) {
      console.error('🚨 [REDIS_SECURITY] Redis connection failed:', error.message);
      console.log('🔄 [REDIS_SECURITY] Using PostgreSQL fallback for session storage');
      this.usePostgreSQLFallback = true;
      return { isValid: false, shouldFallback: true };
    }
  }

  /**
   * Check if Redis version has known vulnerabilities
   */
  private isVulnerableVersion(major: number, minor: number, patch: number): boolean {
    // Vulnerable versions based on 2025 security research
    if (major < 7) return true; // All versions below 7.x are vulnerable
    if (major === 7 && minor < 4) return true; // 7.0-7.3 have memory exhaustion CVEs
    
    return false;
  }

  /**
   * Get secure Redis client or indicate fallback needed
   */
  public async getSecureRedisClient(): Promise<Redis | null> {
    if (!this.isValidated) {
      await this.validateRedisVersion();
    }
    
    if (this.usePostgreSQLFallback) {
      return null; // Signal to use PostgreSQL
    }
    
    return this.redisClient;
  }

  /**
   * Check if system should use PostgreSQL fallback
   */
  public shouldUsePostgreSQLFallback(): boolean {
    return this.usePostgreSQLFallback;
  }

  /**
   * Close Redis connection
   */
  public async disconnect(): Promise<void> {
    if (this.redisClient) {
      await this.redisClient.quit();
      this.redisClient = null;
    }
  }
}

/**
 * Express middleware to validate Redis security before session operations
 */
export const redisSecurityMiddleware = async (req: any, res: any, next: any): Promise<void> => {
  const validator = RedisSecurityValidator.getInstance();
  
  // Validate Redis version on first request
  if (!validator['isValidated']) {
    const validation = await validator.validateRedisVersion();
    
    if (validation.shouldFallback) {
      // Add header to indicate PostgreSQL fallback is active
      res.setHeader('X-Session-Storage', 'postgresql-fallback');
      
      if (validation.version) {
        res.setHeader('X-Redis-Version-Warning', `Vulnerable Redis ${validation.version} - using PostgreSQL`);
      }
    } else {
      res.setHeader('X-Session-Storage', 'redis-validated');
      res.setHeader('X-Redis-Version', validation.version || 'unknown');
    }
  }
  
  next();
};