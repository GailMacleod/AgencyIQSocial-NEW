/**
 * POST VERIFICATION AND SUBSCRIPTION DEDUCTION SERVICE
 * Independent service for verifying successful posts and deducting from subscription quotas
 * Runs separately from main publishing flow to avoid interference
 */

import { storage } from './storage';
import { db } from './db';
import { posts, users } from '../shared/schema';
import { eq, and } from 'drizzle-orm';

interface PostVerificationResult {
  success: boolean;
  message: string;
  remainingPosts?: number;
  postVerified?: boolean;
  quotaDeducted?: boolean;
}

export class PostVerificationService {
  
  /**
   * Check if post was successfully published and deduct from subscription quota
   * This runs independently after successful posts
   */
  static async checkAndDeductPost(subscriptionId: string, postId: number): Promise<PostVerificationResult> {
    console.log(`📊 Starting post verification for post ${postId}, subscription ${subscriptionId}`);
    
    try {
      // 1. Verify the post exists and was successfully published
      const post = await this.verifyPostSuccess(postId);
      if (!post.verified) {
        return {
          success: false,
          message: post.error || 'Post verification failed',
          postVerified: false
        };
      }

      // 2. Get user and verify subscription
      const user = await this.getUserBySubscription(subscriptionId);
      if (!user.found) {
        return {
          success: false,
          message: user.error || 'User not found for subscription',
          postVerified: true,
          quotaDeducted: false
        };
      }

      // 3. Check if post has already been counted
      const alreadyCounted = await this.isPostAlreadyCounted(postId);
      if (alreadyCounted) {
        return {
          success: true,
          message: 'Post already counted in quota',
          remainingPosts: user.data.remainingPosts,
          postVerified: true,
          quotaDeducted: true
        };
      }

      // 4. Deduct from subscription quota
      const deductionResult = await this.deductFromQuota(user.data.id, postId);
      if (!deductionResult.success) {
        return {
          success: false,
          message: deductionResult.message,
          postVerified: true,
          quotaDeducted: false
        };
      }

      console.log(`✅ Post ${postId} verified and quota deducted. Remaining: ${deductionResult.remainingPosts}`);
      
      return {
        success: true,
        message: 'Post registered and deducted successfully',
        remainingPosts: deductionResult.remainingPosts,
        postVerified: true,
        quotaDeducted: true
      };

    } catch (error) {
      console.error('❌ Post verification service error:', error);
      return {
        success: false,
        message: 'Internal verification error',
        postVerified: false,
        quotaDeducted: false
      };
    }
  }

  /**
   * Verify that a post was successfully published
   */
  private static async verifyPostSuccess(postId: number): Promise<{ verified: boolean; error?: string }> {
    try {
      const [post] = await db
        .select()
        .from(posts)
        .where(eq(posts.id, postId));

      if (!post) {
        return { verified: false, error: 'Post not found' };
      }

      // Check if post has successful status
      if (post.status !== 'approved' && post.status !== 'published') {
        return { verified: false, error: `Post status is ${post.status}` };
      }

      // Verify post has publishedAt timestamp
      if (!post.publishedAt) {
        return { verified: false, error: 'Post missing published timestamp' };
      }

      // Check if post was published recently (within last 24 hours)
      const publishTime = new Date(post.publishedAt).getTime();
      const now = Date.now();
      const twentyFourHours = 24 * 60 * 60 * 1000;
      
      if (now - publishTime > twentyFourHours) {
        return { verified: false, error: 'Post too old for verification' };
      }

      return { verified: true };

    } catch (error) {
      console.error('Error verifying post success:', error);
      return { verified: false, error: 'Database error during verification' };
    }
  }

  /**
   * Get user by subscription ID or phone number
   */
  private static async getUserBySubscription(subscriptionId: string): Promise<{ found: boolean; data?: any; error?: string }> {
    try {
      // Try to find user by phone number (our primary identifier)
      let user = await storage.getUserByPhone(subscriptionId);
      
      // If not found by phone, try by email
      if (!user) {
        user = await storage.getUserByEmail(subscriptionId);
      }

      // If still not found, try by stripe customer ID
      if (!user) {
        const [userByStripe] = await db
          .select()
          .from(users)
          .where(eq(users.stripeCustomerId, subscriptionId));
        user = userByStripe;
      }

      if (!user) {
        return { found: false, error: 'User not found for subscription identifier' };
      }

      return { found: true, data: user };

    } catch (error) {
      console.error('Error getting user by subscription:', error);
      return { found: false, error: 'Database error during user lookup' };
    }
  }

  /**
   * Check if post has already been counted in quota
   */
  private static async isPostAlreadyCounted(postId: number): Promise<boolean> {
    try {
      const [post] = await db
        .select({ subscriptionCycle: posts.subscriptionCycle })
        .from(posts)
        .where(eq(posts.id, postId));

      // If post has subscriptionCycle set, it's already been counted
      return post && post.subscriptionCycle !== null;

    } catch (error) {
      console.error('Error checking if post already counted:', error);
      return false; // Assume not counted if we can't verify
    }
  }

  /**
   * Deduct post from user's subscription quota
   */
  private static async deductFromQuota(userId: number, postId: number): Promise<{ success: boolean; message: string; remainingPosts?: number }> {
    try {
      return await db.transaction(async (tx) => {
        // Get current user data
        const [user] = await tx
          .select()
          .from(users)
          .where(eq(users.id, userId));

        if (!user) {
          return { success: false, message: 'User not found during quota deduction' };
        }

        // Check if user has remaining posts
        const remainingPosts = user.remainingPosts || 0;
        if (remainingPosts <= 0) {
          return { success: false, message: 'No remaining posts in subscription' };
        }

        // Deduct one post from remaining quota
        const newRemainingPosts = remainingPosts - 1;
        
        // Update user's remaining posts
        await tx
          .update(users)
          .set({ 
            remainingPosts: newRemainingPosts,
            updatedAt: new Date()
          })
          .where(eq(users.id, userId));

        // Mark post as counted by setting subscription cycle
        const currentCycle = this.getCurrentSubscriptionCycle();
        await tx
          .update(posts)
          .set({ 
            subscriptionCycle: currentCycle
          })
          .where(eq(posts.id, postId));

        console.log(`📉 Quota deducted for user ${userId}. Remaining: ${newRemainingPosts}`);

        return {
          success: true,
          message: 'Quota deducted successfully',
          remainingPosts: newRemainingPosts
        };
      });

    } catch (error) {
      console.error('Error deducting from quota:', error);
      return { success: false, message: 'Database error during quota deduction' };
    }
  }

  /**
   * Get current subscription cycle identifier
   */
  private static getCurrentSubscriptionCycle(): string {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    return `${year}-${month}`;
  }

  /**
   * Verify post across multiple platforms (independent verification)
   */
  static async verifyPostAcrossPlatforms(postId: number, platforms: string[]): Promise<{ [platform: string]: boolean }> {
    const verificationResults: { [platform: string]: boolean } = {};
    
    for (const platform of platforms) {
      try {
        const verified = await this.verifyPlatformPost(postId, platform);
        verificationResults[platform] = verified;
      } catch (error) {
        console.error(`Error verifying ${platform} post:`, error);
        verificationResults[platform] = false;
      }
    }
    
    return verificationResults;
  }

  /**
   * Platform-specific post verification
   */
  private static async verifyPlatformPost(postId: number, platform: string): Promise<boolean> {
    try {
      const [post] = await db
        .select()
        .from(posts)
        .where(and(eq(posts.id, postId), eq(posts.platform, platform)));

      if (!post) return false;
      
      // Check for platform-specific success indicators
      const analytics = post.analytics as any;
      switch (platform) {
        case 'facebook':
          return post.status === 'published' && post.publishedAt !== null &&
                 analytics && typeof analytics === 'object' && 
                 Boolean(analytics.facebook_post_id);
        
        case 'linkedin':
          return post.status === 'published' && post.publishedAt !== null &&
                 analytics && typeof analytics === 'object' && 
                 Boolean(analytics.linkedin_post_id);
        
        case 'x':
          return post.status === 'published' && post.publishedAt !== null &&
                 analytics && typeof analytics === 'object' && 
                 Boolean(analytics.tweet_id);
        
        case 'instagram':
          return post.status === 'published' && post.publishedAt !== null &&
                 analytics && typeof analytics === 'object' && 
                 Boolean(analytics.instagram_media_id);
        
        case 'youtube':
          return post.status === 'published' && post.publishedAt !== null &&
                 analytics && typeof analytics === 'object' && 
                 Boolean(analytics.youtube_post_id);
        
        default:
          return post.status === 'published' && post.publishedAt !== null;
      }

    } catch (error) {
      console.error(`Platform verification error for ${platform}:`, error);
      return false;
    }
  }

  /**
   * Bulk verify and deduct multiple posts (for batch processing)
   */
  static async bulkVerifyAndDeduct(subscriptionId: string, postIds: number[]): Promise<{ [postId: number]: PostVerificationResult }> {
    const results: { [postId: number]: PostVerificationResult } = {};
    
    for (const postId of postIds) {
      try {
        results[postId] = await this.checkAndDeductPost(subscriptionId, postId);
        // Small delay between verifications to avoid overwhelming the database
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        console.error(`Bulk verification error for post ${postId}:`, error);
        results[postId] = {
          success: false,
          message: 'Bulk verification error',
          postVerified: false,
          quotaDeducted: false
        };
      }
    }
    
    return results;
  }
}