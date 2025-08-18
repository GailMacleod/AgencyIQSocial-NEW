import rateLimit from 'express-rate-limit';
import type { Request, Response, NextFunction } from 'express';

// General API rate limiter
export const apiRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req: Request, res: Response) => {
    console.log(`🚫 Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
    res.status(429).json({
      error: 'Too many requests from this IP, please try again later.',
      retryAfter: '15 minutes'
    });
  }
});

// Social media posting rate limiter (more restrictive)
export const socialPostingRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // Limit to 20 posts per hour
  message: {
    error: 'Social media posting rate limit exceeded. Please wait before posting again.',
    retryAfter: '1 hour'
  },
  handler: (req: Request, res: Response) => {
    console.log(`🚫 Social posting rate limit exceeded for user: ${req.session?.userId} on ${req.path}`);
    res.status(429).json({
      error: 'Social media posting rate limit exceeded. Please wait before posting again.',
      retryAfter: '1 hour',
      quotaExceeded: true
    });
  }
});

// Video generation rate limiter (most restrictive)
export const videoGenerationRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit to 5 video generations per hour
  message: {
    error: 'Video generation rate limit exceeded. Please wait before generating more videos.',
    retryAfter: '1 hour'
  },
  handler: (req: Request, res: Response) => {
    console.log(`🚫 Video generation rate limit exceeded for user: ${req.session?.userId} on ${req.path}`);
    res.status(429).json({
      error: 'Video generation rate limit exceeded. Please wait before generating more videos.',
      retryAfter: '1 hour',
      quotaExceeded: true
    });
  }
});

// Auth endpoints rate limiter (prevent brute force)
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 auth requests per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later.',
    retryAfter: '15 minutes'
  },
  handler: (req: Request, res: Response) => {
    console.log(`🚫 Auth rate limit exceeded for IP: ${req.ip} on ${req.path}`);
    res.status(429).json({
      error: 'Too many authentication attempts, please try again later.',
      retryAfter: '15 minutes'
    });
  }
});

// Custom middleware for checking if request should be rate limited
export const skipRateLimitForDevelopment = (req: Request, res: Response, next: NextFunction) => {
  // Skip rate limiting in development mode for easier testing
  if (process.env.NODE_ENV === 'development' && req.headers['x-skip-rate-limit'] === 'true') {
    return next();
  }
  
  // Apply rate limiting in production
  return apiRateLimit(req, res, next);
};