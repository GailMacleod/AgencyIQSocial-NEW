// Authentication Validation Middleware with Database Integration
// Comprehensive user validation and session management

import { Request, Response, NextFunction } from 'express';
import { db } from '../db';
import { users } from '../../shared/schema';
import { eq } from 'drizzle-orm';

// Extend Request type to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        email: string;
        userId: string;
        subscriptionPlan?: string;
        subscriptionActive?: boolean;
      };
    }
  }
}

// Require authentication middleware
export const requireAuth = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const session = (req as any).session;
    
    if (!session || !session.userId) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'NOT_AUTHENTICATED'
      });
    }

    // Get user from database
    const [user] = await db.select()
      .from(users)
      .where(eq(users.id, session.userId));

    if (!user) {
      return res.status(401).json({
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    // Attach user to request
    req.user = {
      id: user.id,
      email: user.email,
      userId: user.userId,
      subscriptionPlan: user.subscriptionPlan,
      subscriptionActive: user.subscriptionActive
    };

    next();
  } catch (error) {
    console.error('Authentication validation failed:', error);
    res.status(500).json({
      error: 'Authentication validation failed',
      code: 'AUTH_ERROR'
    });
  }
};

// Optional authentication middleware
export const optionalAuth = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const session = (req as any).session;
    
    if (session && session.userId) {
      const [user] = await db.select()
        .from(users)
        .where(eq(users.id, session.userId));

      if (user) {
        req.user = {
          id: user.id,
          email: user.email,
          userId: user.userId,
          subscriptionPlan: user.subscriptionPlan,
          subscriptionActive: user.subscriptionActive
        };
      }
    }

    next();
  } catch (error) {
    console.error('Optional authentication failed:', error);
    next(); // Continue without authentication
  }
};

// Require active subscription middleware
export const requireActiveSubscription = (req: Request, res: Response, next: NextFunction) => {
  if (!req.user) {
    return res.status(401).json({
      error: 'Authentication required',
      code: 'NOT_AUTHENTICATED'
    });
  }

  if (!req.user.subscriptionActive) {
    return res.status(403).json({
      error: 'Active subscription required',
      code: 'SUBSCRIPTION_REQUIRED',
      subscriptionPlan: req.user.subscriptionPlan
    });
  }

  next();
};

// Require specific subscription plan
export const requireSubscriptionPlan = (plans: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'NOT_AUTHENTICATED'
      });
    }

    if (!req.user.subscriptionPlan || !plans.includes(req.user.subscriptionPlan)) {
      return res.status(403).json({
        error: `Subscription plan required: ${plans.join(' or ')}`,
        code: 'INSUFFICIENT_PLAN',
        currentPlan: req.user.subscriptionPlan,
        requiredPlans: plans
      });
    }

    next();
  };
};