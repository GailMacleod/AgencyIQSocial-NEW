/**
 * CRITICAL FIX: Production Rate Limiting
 * Implements express-rate-limit middleware to prevent API abuse
 * Addresses CEO's concerns about spammable endpoints and quota exhaustion
 */

import rateLimit from 'express-rate-limit';

/**
 * General API rate limiting for all endpoints
 */
export const generalApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs in production
  message: {
    error: 'Too many API requests from this IP, please try again later.',
    retryAfter: 15 * 60, // 15 minutes in seconds
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res) => {
    console.log(`⚠️ Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
    res.status(429).json({
      error: 'Too many requests',
      retryAfter: 15 * 60,
      message: 'Please wait 15 minutes before making more requests'
    });
  }
});

/**
 * Strict rate limiting for social media posting endpoints
 */
export const socialPostingLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // limit each IP to 20 posts per hour
  message: {
    error: 'Too many posting requests. Social media platforms have strict limits.',
    retryAfter: 60 * 60, // 1 hour in seconds
    code: 'SOCIAL_POSTING_RATE_LIMIT'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.log(`🚫 Social posting rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      error: 'Social posting rate limit exceeded',
      retryAfter: 60 * 60,
      message: 'Please wait 1 hour before posting again to prevent platform bans'
    });
  }
});

/**
 * Video generation rate limiting (resource intensive)
 */
export const videoGenerationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // limit each IP to 5 video generations per hour
  message: {
    error: 'Too many video generation requests. This is a resource-intensive operation.',
    retryAfter: 60 * 60, // 1 hour in seconds
    code: 'VIDEO_GENERATION_RATE_LIMIT'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.log(`🎥 Video generation rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      error: 'Video generation rate limit exceeded',
      retryAfter: 60 * 60,
      message: 'Please wait 1 hour before generating more videos'
    });
  }
});

/**
 * Authentication endpoint rate limiting (prevent brute force)
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth attempts per windowMs
  message: {
    error: 'Too many authentication attempts from this IP.',
    retryAfter: 15 * 60, // 15 minutes in seconds
    code: 'AUTH_RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.log(`🔐 Auth rate limit exceeded for IP: ${req.ip} on ${req.path}`);
    res.status(429).json({
      error: 'Too many authentication attempts',
      retryAfter: 15 * 60,
      message: 'Please wait 15 minutes before trying to authenticate again'
    });
  }
});

/**
 * Health check rate limiting (lighter limits)
 */
export const healthCheckLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // limit each IP to 10 health checks per minute
  message: {
    error: 'Too many health check requests.',
    retryAfter: 60, // 1 minute in seconds
    code: 'HEALTH_CHECK_RATE_LIMIT'
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Apply rate limiting middleware to Express app
 */
export function applyRateLimiting(app: any) {
  console.log('🚀 Applying production rate limiting...');
  
  // General API rate limiting
  app.use('/api', generalApiLimiter);
  
  // Specific endpoint rate limiting
  app.use('/api/enforce-auto-posting', socialPostingLimiter);
  app.use('/api/auto-post-schedule', socialPostingLimiter);
  app.use('/api/posts', socialPostingLimiter);
  
  // Video generation endpoints
  app.use('/api/video/generate', videoGenerationLimiter);
  app.use('/api/video/render', videoGenerationLimiter);
  
  // Authentication endpoints
  app.use('/auth', authLimiter);
  app.use('/api/auth', authLimiter);
  app.use('/api/login', authLimiter);
  app.use('/api/establish-session', authLimiter);
  
  // Health check endpoints
  app.use('/api/health', healthCheckLimiter);
  app.use('/health', healthCheckLimiter);
  
  console.log('✅ Production rate limiting configured:');
  console.log('   • General API: 100 req/15min');
  console.log('   • Social posting: 20 req/hour');
  console.log('   • Video generation: 5 req/hour');
  console.log('   • Authentication: 5 req/15min');
  console.log('   • Health checks: 10 req/minute');
}

/**
 * Rate limit bypass for development
 */
export function createDevelopmentRateLimiter() {
  return rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 1000, // Very high limit for development
    message: {
      error: 'Development rate limit exceeded (very high threshold)',
      code: 'DEV_RATE_LIMIT'
    },
    standardHeaders: true,
    legacyHeaders: false
  });
}