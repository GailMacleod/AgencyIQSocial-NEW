/**
 * VEO 3.0 Rate Limiting Middleware
 * Prevents cost spiraling through aggressive rate limiting
 */

const rateLimit = require('express-rate-limit');
const { VeoUsageTracker } = require('../services/VeoUsageTracker');

// Create VEO usage tracker instance
const veoTracker = new VeoUsageTracker();

// Aggressive VEO rate limiting - max 3 videos per hour per user
const veoRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each user to 3 VEO requests per hour
  keyGenerator: (req) => {
    // Use session userId for rate limiting
    return req.session?.userId || req.ip;
  },
  message: {
    error: 'VEO rate limit exceeded',
    message: 'Maximum 3 video generations per hour. Please wait before creating more videos.',
    resetTime: new Date(Date.now() + 60 * 60 * 1000)
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for non-VEO endpoints
    return !req.path.includes('/video') && !req.path.includes('/veo');
  }
});

// Cost validation middleware
const veoCostValidation = async (req, res, next) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required for VEO generation' });
    }

    // Check if user can generate video within cost limits
    const validation = await veoTracker.canGenerateVideo(userId, 8); // Assume 8s default
    
    if (!validation.canGenerate) {
      return res.status(429).json({
        error: 'VEO quota exceeded',
        message: 'Video generation quota exceeded. Upgrade plan or wait for quota reset.',
        usage: await veoTracker.getUsageStats(userId)
      });
    }

    // Add validation data to request for use in video generation
    req.veoValidation = validation;
    next();
  } catch (error) {
    console.error('VEO cost validation error:', error);
    return res.status(429).json({
      error: 'Usage limit exceeded',
      message: error.message
    });
  }
};

// Combined middleware for VEO endpoints
const veoProtection = [veoRateLimit, veoCostValidation];

module.exports = {
  veoRateLimit,
  veoCostValidation,
  veoProtection
};