import rateLimit from 'express-rate-limit';

/**
 * Specialized rate limiter for VEO 3.0 operation polling
 * Allows frequent polling (every 5 seconds) for video generation status
 */
export const veoPollingRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute window
  max: 20, // Allow 20 polling requests per minute (every 3 seconds average)
  message: {
    error: 'VEO 3.0 polling rate limit exceeded. Please wait before checking again.',
    retryAfter: 60,
    code: 'VEO_POLLING_RATE_LIMIT'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.log(`🔄 VEO 3.0: Polling rate limit exceeded for IP: ${req.ip} on ${req.path}`);
    res.status(429).json({
      error: 'VEO 3.0 polling rate limit exceeded',
      retryAfter: 60,
      message: 'Please wait 1 minute before polling again'
    });
  },
  // Remove keyGenerator to avoid IPv6 issues
});