import { db } from '../db.js';
import { users, platformConnections } from '@shared/schema';
import { eq } from 'drizzle-orm';

/**
 * Authentication middleware that validates session and loads user data from database
 */
const requireAuth = async (req, res, next) => {
  try {
    // Check if session exists and has userId
    if (!req.session || !req.session.userId) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required - no valid session',
        code: 'NO_SESSION'
      });
    }

    const userId = req.session.userId;
    console.log(`🔐 Auth middleware: Validating user ${userId}`);

    // Query user from database using Drizzle
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.id, userId));

    if (!user) {
      // Clear invalid session
      req.session.destroy();
      return res.status(401).json({
        success: false,
        message: 'User not found - invalid session',
        code: 'USER_NOT_FOUND'
      });
    }

    // Attach user data to request
    req.user = user;
    req.userId = user.id;

    console.log(`✅ Auth middleware: User ${user.email} (ID: ${user.id}) authenticated`);
    next();
  } catch (error) {
    console.error('❌ Auth middleware error:', error);
    res.status(500).json({
      success: false,
      message: 'Authentication check failed',
      code: 'AUTH_ERROR'
    });
  }
};

/**
 * OAuth scope validation middleware
 * Ensures user has required OAuth connections for platform operations
 */
const requireOAuthScope = (requiredPlatforms = []) => {
  return async (req, res, next) => {
    try {
      if (!req.userId) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required for OAuth scope check',
          code: 'NO_AUTH'
        });
      }

      // If no specific platforms required, just check if user has any active connections
      if (requiredPlatforms.length === 0) {
        const connections = await db
          .select()
          .from(platformConnections)
          .where(eq(platformConnections.userId, req.userId));

        if (connections.length === 0) {
          return res.status(403).json({
            success: false,
            message: 'No platform connections found - complete onboarding first',
            code: 'NO_CONNECTIONS'
          });
        }

        req.platformConnections = connections;
        return next();
      }

      // Check for specific platform requirements
      const connections = await db
        .select()
        .from(platformConnections)
        .where(eq(platformConnections.userId, req.userId));

      const activePlatforms = connections
        .filter(conn => conn.isActive)
        .map(conn => conn.platform);

      const missingPlatforms = requiredPlatforms.filter(
        platform => !activePlatforms.includes(platform)
      );

      if (missingPlatforms.length > 0) {
        return res.status(403).json({
          success: false,
          message: `Missing required platform connections: ${missingPlatforms.join(', ')}`,
          code: 'MISSING_PLATFORMS',
          required: requiredPlatforms,
          missing: missingPlatforms,
          available: activePlatforms
        });
      }

      req.platformConnections = connections;
      console.log(`✅ OAuth scope validated: User ${req.userId} has access to ${activePlatforms.join(', ')}`);
      next();
    } catch (error) {
      console.error('❌ OAuth scope validation error:', error);
      res.status(500).json({
        success: false,
        message: 'OAuth scope validation failed',
        code: 'SCOPE_CHECK_ERROR'
      });
    }
  };
};

/**
 * Optional authentication middleware - loads user if session exists but doesn't require it
 */
const optionalAuth = async (req, res, next) => {
  try {
    if (req.session && req.session.userId) {
      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, req.session.userId));

      if (user) {
        req.user = user;
        req.userId = user.id;
        console.log(`✅ Optional auth: User ${user.email} (ID: ${user.id}) loaded`);
      }
    }
    next();
  } catch (error) {
    console.error('❌ Optional auth error:', error);
    // Don't fail on optional auth errors
    next();
  }
};

/**
 * Subscription validation middleware
 * Ensures user has active subscription for premium features
 */
const requireActiveSubscription = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required for subscription check',
      code: 'NO_AUTH'
    });
  }

  // Check subscription status
  if (!req.user.subscriptionActive) {
    return res.status(403).json({
      success: false,
      message: 'Active subscription required',
      code: 'SUBSCRIPTION_REQUIRED',
      subscriptionPlan: req.user.subscriptionPlan,
      subscriptionActive: req.user.subscriptionActive
    });
  }

  // Check subscription expiry if applicable
  if (req.user.subscriptionEnd && new Date(req.user.subscriptionEnd) < new Date()) {
    return res.status(403).json({
      success: false,
      message: 'Subscription expired',
      code: 'SUBSCRIPTION_EXPIRED',
      subscriptionEnd: req.user.subscriptionEnd
    });
  }

  console.log(`✅ Subscription validated: User ${req.user.id} has active ${req.user.subscriptionPlan} plan`);
  next();
};

export {
  requireAuth,
  requireOAuthScope,
  optionalAuth,
  requireActiveSubscription
};