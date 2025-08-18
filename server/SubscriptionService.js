import { storage } from './storage.js';

export default class SubscriptionService {
  
  /**
   * Get subscription status and capabilities for a user
   * @param {number} userId - User ID
   * @returns {Promise<Object>} - Subscription details with capabilities
   */
  static async getSubscriptionDetails(userId) {
    try {
      const user = await storage.getUser(userId);
      
      if (!user) {
        return {
          plan: 'none',
          active: false,
          videoAccess: false,
          postsQuota: 0,
          videoQuota: 0,
          error: 'User not found'
        };
      }

      const plan = user.subscriptionPlan || 'none';
      const active = user.subscriptionActive || false;
      
      // Video access is ONLY for pro subscribers
      const videoAccess = plan === 'professional' && active;
      
      // Video quota: 1 video per post for PRO users only
      const videoQuota = videoAccess ? 1 : 0;
      
      // Posts quota based on plan (30-day period)
      let postsQuota = 0;
      switch (plan) {
        case 'starter':
          postsQuota = 10;
          break;
        case 'growth':
          postsQuota = 20;
          break;
        case 'professional':
          postsQuota = 30;
          break;
        default:
          postsQuota = 0;
      }

      return {
        plan,
        active,
        videoAccess,
        postsQuota,
        videoQuota,
        subscriptionStart: user.subscriptionStart,
        remainingPosts: user.remainingPosts || 0,
        totalPosts: user.totalPosts || 0
      };
      
    } catch (error) {
      console.error('SubscriptionService.getSubscriptionDetails error:', error);
      return {
        plan: 'none',
        active: false,
        videoAccess: false,
        postsQuota: 0,
        videoQuota: 0,
        error: error.message
      };
    }
  }

  /**
   * Check if user has access to video generation features
   * @param {number} userId - User ID
   * @returns {Promise<boolean>} - True if user can generate videos
   */
  static async hasVideoAccess(userId) {
    try {
      const details = await this.getSubscriptionDetails(userId);
      return details.videoAccess;
    } catch (error) {
      console.error('SubscriptionService.hasVideoAccess error:', error);
      return false;
    }
  }

  /**
   * Validate video generation request for pro subscribers only
   * @param {number} userId - User ID
   * @returns {Promise<Object>} - Validation result
   */
  static async validateVideoGeneration(userId) {
    try {
      const details = await this.getSubscriptionDetails(userId);
      
      if (!details.active) {
        return {
          allowed: false,
          error: 'Active subscription required for video generation',
          code: 'SUBSCRIPTION_INACTIVE'
        };
      }
      
      if (!details.videoAccess) {
        return {
          allowed: false,
          error: 'Video generation is only available for Professional plan subscribers',
          code: 'PRO_PLAN_REQUIRED',
          currentPlan: details.plan
        };
      }
      
      // Check video quota (1 video per post for pro users)
      if (details.videoQuota <= 0) {
        return {
          allowed: false,
          error: 'Video quota exceeded for current subscription',
          code: 'VIDEO_QUOTA_EXCEEDED'
        };
      }
      
      return {
        allowed: true,
        quota: details.videoQuota,
        plan: details.plan
      };
      
    } catch (error) {
      console.error('SubscriptionService.validateVideoGeneration error:', error);
      return {
        allowed: false,
        error: 'Video validation failed',
        code: 'VALIDATION_ERROR'
      };
    }
  }

  /**
   * Check if user has pro subscription
   * @param {number} userId - User ID
   * @returns {Promise<boolean>} - True if user has pro plan
   */
  static async isProSubscriber(userId) {
    try {
      const details = await this.getSubscriptionDetails(userId);
      return details.plan === 'professional' && details.active;
    } catch (error) {
      console.error('SubscriptionService.isProSubscriber error:', error);
      return false;
    }
  }
}