/**
 * QUOTA ENFORCEMENT MIDDLEWARE
 * Prevents resource abuse across all critical endpoints
 */

import type { Request, Response, NextFunction } from 'express';
import { QuotaManager } from '../services/QuotaManager';
import { storage } from '../storage';

interface QuotaRequest extends Request {
  session: {
    userId?: number;
    userEmail?: string;
  };
}

/**
 * Middleware to check API call quota before proceeding
 */
export const checkAPIQuota = async (req: QuotaRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res.status(401).json({ 
        message: "Authentication required",
        quotaError: true 
      });
    }

    // Get user subscription tier
    const user = await storage.getUser(userId);
    const subscriptionTier = user?.subscriptionPlan === 'free' ? 'free' : 
                           user?.subscriptionPlan === 'enterprise' ? 'enterprise' : 'professional';

    // Check if user can make API call
    const quotaCheck = await QuotaManager.canMakeApiCall(userId);
    
    if (!quotaCheck.allowed) {
      console.log(`🚫 API quota exceeded for user ${userId}: ${quotaCheck.reason}`);
      return res.status(429).json({
        message: quotaCheck.reason,
        quotaExceeded: true,
        upgradeRequired: subscriptionTier === 'free'
      });
    }

    // Record the API call
    await QuotaManager.incrementApiUsage(userId);
    console.log(`✅ API call recorded for user ${userId} (${subscriptionTier})`);
    
    next();
  } catch (error) {
    console.error('❌ Quota enforcement error:', error);
    // Don't block request on quota system failure, but log it
    next();
  }
};

/**
 * Middleware to check video generation quota
 */
export const checkVideoQuota = async (req: QuotaRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res.status(401).json({ 
        message: "Authentication required",
        quotaError: true 
      });
    }

    // Get user subscription tier
    const user = await storage.getUser(userId);
    const subscriptionTier = user?.subscriptionPlan || 'free';

    console.log(`🎬 Video quota check for user ${userId} with ${subscriptionTier} plan`);

    // Check quota for all users including professional (52 video limit)
    const quotaCheck = await QuotaManager.canGenerateVideo(userId);
    
    if (!quotaCheck.allowed) {
      console.log(`🎬 Video quota exceeded for user ${userId}: ${quotaCheck.reason}`);
      return res.status(429).json({
        message: quotaCheck.reason,
        quotaExceeded: true,
        upgradeRequired: subscriptionTier === 'free'
      });
    }

    // Record the video generation (done here to prevent bypass)
    await QuotaManager.incrementVideoUsage(userId);
    console.log(`🎬 Video generation recorded for user ${userId} (${subscriptionTier})`);
    
    next();
  } catch (error) {
    console.error('❌ Video quota enforcement error, allowing request:', error);
    // Don't block request on quota system failure, but log it
    next();
  }
};

/**
 * Middleware to check content generation quota
 */
export const checkContentQuota = async (req: QuotaRequest, res: Response, next: NextFunction) => {
  try {
    const userId = req.session?.userId;
    if (!userId) {
      return res.status(401).json({ 
        message: "Authentication required",
        quotaError: true 
      });
    }

    // Get user subscription tier
    const user = await storage.getUser(userId);
    const subscriptionTier = user?.subscriptionPlan === 'free' ? 'free' : 
                           user?.subscriptionPlan === 'enterprise' ? 'enterprise' : 'professional';

    // Check if user can generate content (using API call quota for content)
    const quotaCheck = await QuotaManager.canMakeApiCall(userId);
    
    if (!quotaCheck.allowed) {
      console.log(`📝 Content quota exceeded for user ${userId}: ${quotaCheck.reason}`);
      return res.status(429).json({
        message: quotaCheck.reason,
        quotaExceeded: true,
        upgradeRequired: subscriptionTier === 'free'
      });
    }

    // Content generation recording handled in specific endpoints
    // to allow for rollback on generation failure
    
    next();
  } catch (error) {
    console.error('❌ Content quota enforcement error:', error);
    // Don't block request on quota system failure, but log it
    next();
  }
};

/**
 * Get quota status for frontend display
 */
export const getQuotaStatus = async (userId: number) => {
  try {
    const user = await storage.getUser(userId);
    const subscriptionTier = user?.subscriptionPlan === 'free' ? 'free' : 
                           user?.subscriptionPlan === 'enterprise' ? 'enterprise' : 'professional';

    const quota = await QuotaManager.getQuotaStatus(userId);
    
    return {
      success: true,
      quota,
      subscription: {
        tier: subscriptionTier,
        limits: quota.quotaLimits
      }
    };
  } catch (error: any) {
    console.error('❌ Get quota status error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};