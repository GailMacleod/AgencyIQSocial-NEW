// Enhanced Security Middleware with PostgreSQL Session Management
// Comprehensive security headers, rate limiting, and session handling

import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { Request, Response, NextFunction } from 'express';
import { db } from '../db';
import { quotaUsage } from '../../shared/schema';
import { eq, and, gte } from 'drizzle-orm';

// Enhanced security headers configuration
export const enhancedSecurityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"], // Vite dev needs unsafe-eval
      connectSrc: ["'self'", "https:", "wss:"],
      frameSrc: ["'self'", "https://www.facebook.com", "https://accounts.google.com"],
      frameAncestors: ["'self'"]
    },
  },
  crossOriginEmbedderPolicy: false, // Needed for Vite dev server
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// PostgreSQL-backed rate limiting
export const createPostgreSQLRateLimit = (options: {
  windowMs: number;
  max: number;
  platform?: string;
  operation?: string;
}) => {
  return rateLimit({
    windowMs: options.windowMs,
    max: options.max,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
      // Use session ID or IP as key
      const sessionId = (req as any).session?.id || req.ip;
      return `${sessionId}_${options.platform || 'api'}_${options.operation || 'request'}`;
    },
    store: {
      // Custom PostgreSQL store implementation
      async increment(key: string): Promise<{ totalHits: number; resetTime?: Date }> {
        try {
          const userId = key.split('_')[0];
          const platform = options.platform || 'api';
          const operation = options.operation || 'request';
          const hourWindow = new Date();
          hourWindow.setMinutes(0, 0, 0); // Round to current hour

          // Try to increment existing record
          const existing = await db.select()
            .from(quotaUsage)
            .where(and(
              eq(quotaUsage.userId, userId),
              eq(quotaUsage.platform, platform),
              eq(quotaUsage.operation, operation),
              eq(quotaUsage.hourWindow, hourWindow)
            ));

          if (existing.length > 0) {
            await db.update(quotaUsage)
              .set({ 
                count: existing[0].count + 1,
                updatedAt: new Date()
              })
              .where(eq(quotaUsage.id, existing[0].id));
            
            return { 
              totalHits: existing[0].count + 1,
              resetTime: new Date(hourWindow.getTime() + options.windowMs)
            };
          } else {
            // Create new record
            const [newRecord] = await db.insert(quotaUsage)
              .values({
                userId,
                platform,
                operation,
                hourWindow,
                count: 1
              })
              .returning();

            return { 
              totalHits: 1,
              resetTime: new Date(hourWindow.getTime() + options.windowMs)
            };
          }
        } catch (error) {
          console.error('Rate limit store error:', error);
          return { totalHits: 1 };
        }
      },

      async decrement(key: string): Promise<void> {
        // Optional: implement decrement if needed
      },

      async resetKey(key: string): Promise<void> {
        try {
          const userId = key.split('_')[0];
          const platform = options.platform || 'api';
          const operation = options.operation || 'request';
          
          await db.delete(quotaUsage)
            .where(and(
              eq(quotaUsage.userId, userId),
              eq(quotaUsage.platform, platform),
              eq(quotaUsage.operation, operation)
            ));
        } catch (error) {
          console.error('Rate limit reset error:', error);
        }
      }
    },
    message: {
      error: `Too many ${options.operation || 'requests'} from this IP, please try again later.`,
      retryAfter: Math.ceil(options.windowMs / 1000)
    }
  });
};

// Platform-specific rate limiters
export const apiRateLimit = createPostgreSQLRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per 15 minutes
  operation: 'api_request'
});

export const postingRateLimit = createPostgreSQLRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 posts per hour
  operation: 'social_post'
});

export const videoRateLimit = createPostgreSQLRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 video generations per hour
  operation: 'video_generation'
});

export const authRateLimit = createPostgreSQLRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 auth attempts per 15 minutes
  operation: 'authentication'
});

// Session validation middleware
export const validateSession = (req: Request, res: Response, next: NextFunction) => {
  const session = (req as any).session;
  
  if (!session) {
    return res.status(401).json({
      error: 'Session required',
      code: 'NO_SESSION'
    });
  }

  // Validate session format
  if (!session.id || !session.id.startsWith('aiq_')) {
    return res.status(401).json({
      error: 'Invalid session format',
      code: 'INVALID_SESSION'
    });
  }

  next();
};

// Enhanced CORS middleware with secure defaults
export const enhancedCORS = (req: Request, res: Response, next: NextFunction) => {
  const isProduction = process.env.NODE_ENV === 'production';
  const allowedOrigins = isProduction 
    ? ['https://app.theagencyiq.ai', 'https://theagencyiq.ai']
    : ['http://localhost:5000', 'http://localhost:3000'];

  const origin = req.headers.origin;
  if (!origin || allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin || allowedOrigins[0]);
  }

  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cookie');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Max-Age', '86400'); // 24 hours
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
};

// Database connection validation middleware
export const validateDatabaseConnection = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Quick database health check
    await db.execute('SELECT 1');
    next();
  } catch (error) {
    console.error('Database connection validation failed:', error);
    res.status(503).json({
      error: 'Database temporarily unavailable',
      code: 'DB_UNAVAILABLE',
      retryAfter: 60
    });
  }
};

// Quota enforcement middleware
export const enforceQuota = (platform: string, operation: string, limit: number) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).session;
      const userId = session?.userId || 'anonymous';
      
      const hourWindow = new Date();
      hourWindow.setMinutes(0, 0, 0);

      const usage = await db.select()
        .from(quotaUsage)
        .where(and(
          eq(quotaUsage.userId, userId),
          eq(quotaUsage.platform, platform),
          eq(quotaUsage.operation, operation),
          gte(quotaUsage.hourWindow, hourWindow)
        ));

      const currentUsage = usage.reduce((sum, record) => sum + record.count, 0);
      
      if (currentUsage >= limit) {
        return res.status(429).json({
          error: `${operation} quota exceeded for ${platform}`,
          code: 'QUOTA_EXCEEDED',
          limit,
          current: currentUsage,
          resetTime: new Date(hourWindow.getTime() + 60 * 60 * 1000)
        });
      }

      next();
    } catch (error) {
      console.error('Quota enforcement error:', error);
      next(); // Continue on error to avoid blocking
    }
  };
};

// Security event logging middleware
export const logSecurityEvent = (eventType: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const session = (req as any).session;
    console.log(`[SECURITY] ${eventType}`, {
      timestamp: new Date().toISOString(),
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      sessionId: session?.id,
      userId: session?.userId,
      path: req.path,
      method: req.method
    });
    next();
  };
};