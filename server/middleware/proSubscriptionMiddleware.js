import SubscriptionService from '../SubscriptionService.js';

/**
 * Middleware to enforce Professional plan subscription for video features
 * Returns 403 for non-pro users attempting video generation
 */
export const requireProSubscription = async (req, res, next) => {
  try {
    // Get user ID from session
    const userId = req.session?.userId || req.body?.userId || req.query?.userId;
    
    if (!userId) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'User session not found',
        code: 'AUTH_REQUIRED'
      });
    }

    // Validate pro subscription for video access
    const validation = await SubscriptionService.validateVideoGeneration(userId);
    
    if (!validation.allowed) {
      return res.status(403).json({
        error: validation.error,
        code: validation.code,
        currentPlan: validation.currentPlan,
        message: 'Professional plan subscription required for video generation',
        upgradeRequired: true
      });
    }

    // Add subscription details to request for downstream use
    req.subscriptionDetails = {
      plan: validation.plan,
      quota: validation.quota,
      userId: userId
    };

    console.log(`✅ Pro subscription validated for user ${userId}`);
    next();
    
  } catch (error) {
    console.error('Pro subscription middleware error:', error);
    return res.status(500).json({
      error: 'Subscription validation failed',
      message: 'Unable to verify subscription status',
      code: 'VALIDATION_ERROR'
    });
  }
};

/**
 * Middleware to check video access without blocking request
 * Adds subscription info to request object
 */
export const checkVideoAccess = async (req, res, next) => {
  try {
    const userId = req.session?.userId || req.body?.userId || req.query?.userId;
    
    if (userId) {
      const hasAccess = await SubscriptionService.hasVideoAccess(userId);
      const details = await SubscriptionService.getSubscriptionDetails(userId);
      
      req.videoAccess = {
        hasAccess,
        plan: details.plan,
        active: details.active,
        quota: details.videoQuota
      };
    } else {
      req.videoAccess = {
        hasAccess: false,
        plan: 'none',
        active: false,
        quota: 0
      };
    }
    
    next();
    
  } catch (error) {
    console.error('Video access check error:', error);
    req.videoAccess = {
      hasAccess: false,
      plan: 'none',
      active: false,
      quota: 0,
      error: error.message
    };
    next();
  }
};