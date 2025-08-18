/**
 * Post Retry Service - Automatically retries failed posts when platforms reconnect
 */

import { storage } from './storage';

export interface FailedPost {
  id: number;
  userId: number;
  platform: string;
  content: string;
  failureReason: string;
  retryCount: number;
  lastAttempt: Date;
  scheduledFor: Date | null;
}

export class PostRetryService {
  private static readonly MAX_RETRY_ATTEMPTS = 3;
  private static readonly RETRY_DELAY_MINUTES = 5;

  /**
   * Mark a post as failed and queue for retry
   */
  static async markPostFailed(postId: number, failureReason: string): Promise<void> {
    try {
      await storage.updatePost(postId, {
        status: 'failed',
        errorLog: failureReason,
        publishedAt: null
      });

      console.log(`Post ${postId} marked as failed: ${failureReason}`);
      
      // Schedule retry if within retry limits
      await this.scheduleRetry(postId);
    } catch (error) {
      console.error('Error marking post as failed:', error);
    }
  }

  /**
   * Schedule a retry for a failed post
   */
  static async scheduleRetry(postId: number): Promise<void> {
    try {
      const posts = await storage.getPostsByUser(0); // Get all posts
      const post = posts.find(p => p.id === postId);
      
      if (!post) {
        console.error(`Post ${postId} not found for retry scheduling`);
        return;
      }

      const retryCount = (post.errorLog?.match(/Retry attempt/g) || []).length;
      
      if (retryCount >= this.MAX_RETRY_ATTEMPTS) {
        console.log(`Post ${postId} exceeded max retry attempts (${this.MAX_RETRY_ATTEMPTS})`);
        await storage.updatePost(postId, {
          status: 'permanently_failed',
          errorLog: `${post.errorLog}\nMax retry attempts exceeded`
        });
        return;
      }

      // Schedule retry in 5 minutes
      const retryTime = new Date(Date.now() + this.RETRY_DELAY_MINUTES * 60 * 1000);
      
      await storage.updatePost(postId, {
        status: 'pending_retry',
        scheduledFor: retryTime,
        errorLog: `${post.errorLog}\nRetry attempt ${retryCount + 1} scheduled for ${retryTime.toISOString()}`
      });

      console.log(`Post ${postId} scheduled for retry at ${retryTime.toISOString()}`);
    } catch (error) {
      console.error('Error scheduling post retry:', error);
    }
  }

  /**
   * Process all pending retry posts when a platform reconnects
   */
  static async processRetryPosts(userId: number, platform: string): Promise<void> {
    try {
      const posts = await storage.getPostsByUser(userId);
      const retryPosts = posts.filter(post => 
        post.platform === platform && 
        (post.status === 'failed' || post.status === 'pending_retry')
      );

      console.log(`Processing ${retryPosts.length} retry posts for ${platform} (user ${userId})`);

      for (const post of retryPosts) {
        await this.retryPost(post.id);
        // Add delay between retries to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    } catch (error) {
      console.error('Error processing retry posts:', error);
    }
  }

  /**
   * Retry a specific failed post
   */
  static async retryPost(postId: number): Promise<boolean> {
    try {
      console.log(`Retrying post ${postId}`);
      
      // Update status to pending for retry
      await storage.updatePost(postId, {
        status: 'pending',
        errorLog: null
      });

      // The existing approve-post endpoint will handle the actual posting
      return true;
    } catch (error) {
      console.error(`Error retrying post ${postId}:`, error);
      await this.markPostFailed(postId, `Retry failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Get all failed posts for a user
   */
  static async getFailedPosts(userId: number): Promise<FailedPost[]> {
    try {
      const posts = await storage.getPostsByUser(userId);
      return posts.filter(post => 
        post.status === 'failed' || 
        post.status === 'pending_retry' || 
        post.status === 'permanently_failed'
      ).map(post => ({
        id: post.id,
        userId: post.userId,
        platform: post.platform,
        content: post.content,
        failureReason: post.errorLog || 'Unknown error',
        retryCount: (post.errorLog?.match(/Retry attempt/g) || []).length,
        lastAttempt: post.publishedAt || post.createdAt || new Date(),
        scheduledFor: post.scheduledFor
      }));
    } catch (error) {
      console.error('Error getting failed posts:', error);
      return [];
    }
  }

  /**
   * Process scheduled retries (called by cron job)
   */
  static async processScheduledRetries(): Promise<void> {
    try {
      const allPosts = await storage.getPostsByUser(0); // Get all posts
      const now = new Date();
      
      const readyForRetry = allPosts.filter(post => 
        post.status === 'pending_retry' &&
        post.scheduledFor &&
        new Date(post.scheduledFor) <= now
      );

      console.log(`Processing ${readyForRetry.length} scheduled retry posts`);

      for (const post of readyForRetry) {
        await this.retryPost(post.id);
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    } catch (error) {
      console.error('Error processing scheduled retries:', error);
    }
  }

  /**
   * Auto-retry failed posts when platform connection is restored
   */
  static async onPlatformReconnected(userId: number, platform: string): Promise<void> {
    console.log(`Platform ${platform} reconnected for user ${userId} - processing failed posts`);
    await this.processRetryPosts(userId, platform);
  }
}