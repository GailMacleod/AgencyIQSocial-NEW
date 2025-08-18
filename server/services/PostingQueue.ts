/**
 * POSTING QUEUE SERVICE
 * Prevents burst posting that crashes accounts and handles API rate limits
 */

import { storage } from '../storage';
import { DirectPublishService } from './DirectPublishService';
import { TwitterAPI } from './TwitterAPI';
import { UnifiedOAuthService } from './UnifiedOAuthService';

interface QueuedPost {
  id: string;
  postId: number;
  platform: string;
  content: string;
  userId: number;
  scheduledTime: Date;
  retryCount: number;
  maxRetries: number;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  lastError?: string;
}

class PostingQueueService {
  private queue: QueuedPost[] = [];
  private processing = false;
  private readonly DELAY_BETWEEN_POSTS = 2000; // 2 second delay between posts
  private readonly MAX_CONCURRENT_POSTS = 3; // Max 3 posts across all subscriptions
  private readonly MAX_RETRIES = 3;
  private processingTimer: NodeJS.Timeout | null = null;

  constructor() {
    this.startQueueProcessor();
  }

  /**
   * Add post to queue with delay scheduling
   */
  async addToQueue(postId: number, platform: string, content: string, userId: number, delay = 0): Promise<string> {
    const queueId = `queue_${Date.now()}_${postId}_${platform}`;
    const scheduledTime = new Date(Date.now() + delay);

    const queuedPost: QueuedPost = {
      id: queueId,
      postId,
      platform,
      content,
      userId,
      scheduledTime,
      retryCount: 0,
      maxRetries: this.MAX_RETRIES,
      status: 'pending'
    };

    this.queue.push(queuedPost);
    console.log(`📋 Added to queue: Post ${postId} for ${platform} (scheduled: ${scheduledTime.toISOString()})`);
    
    return queueId;
  }

  /**
   * Add multiple posts with staggered delays
   */
  async addBatchToQueue(posts: Array<{postId: number, platform: string, content: string, userId: number}>): Promise<string[]> {
    const queueIds: string[] = [];
    
    for (let i = 0; i < posts.length; i++) {
      const delay = i * this.DELAY_BETWEEN_POSTS; // Stagger by 2 seconds each
      const queueId = await this.addToQueue(
        posts[i].postId,
        posts[i].platform,
        posts[i].content,
        posts[i].userId,
        delay
      );
      queueIds.push(queueId);
    }

    console.log(`📋 Batch queued: ${posts.length} posts with ${this.DELAY_BETWEEN_POSTS}ms delays`);
    return queueIds;
  }

  /**
   * Process queue with rate limiting and error handling
   */
  private async processQueue(): Promise<void> {
    if (this.processing) return;

    this.processing = true;
    const now = new Date();
    
    // Get pending posts that are ready to process
    const readyPosts = this.queue.filter(post => 
      post.status === 'pending' && 
      post.scheduledTime <= now
    );

    if (readyPosts.length === 0) {
      this.processing = false;
      return;
    }

    // Limit concurrent processing
    const postsToProcess = readyPosts.slice(0, this.MAX_CONCURRENT_POSTS);
    
    console.log(`🚀 Processing ${postsToProcess.length} posts from queue`);

    for (const queuedPost of postsToProcess) {
      await this.processPost(queuedPost);
    }

    this.processing = false;
  }

  /**
   * Process individual post with error handling and retries
   */
  private async processPost(queuedPost: QueuedPost): Promise<void> {
    queuedPost.status = 'processing';
    
    try {
      console.log(`📤 Publishing post ${queuedPost.postId} to ${queuedPost.platform} (attempt ${queuedPost.retryCount + 1})`);
      
      // Get post data from database
      const post = await storage.getPost(queuedPost.postId);
      if (!post) {
        throw new Error(`Post ${queuedPost.postId} not found in database`);
      }

      let publishResult;

      // Use platform-specific publishing with proper API integration
      if (queuedPost.platform === 'x' || queuedPost.platform === 'twitter') {
        // Use TwitterAPI for X/Twitter posting with OAuth 1.0a
        const twitterAPI = TwitterAPI.fromEnvironment();
        
        if (twitterAPI) {
          const tweetResult = await twitterAPI.postTweet(queuedPost.content);
          publishResult = {
            success: tweetResult.success,
            platformPostId: tweetResult.tweetId,
            error: tweetResult.error
          };
          
          if (tweetResult.rateLimited) {
            // Handle rate limiting with longer retry delay
            throw new Error('X API rate limited - will retry later');
          }
        } else {
          // Fallback to DirectPublishService if Twitter API not available
          const validConnections = await UnifiedOAuthService.validateAndRefreshTokens(queuedPost.userId);
          const connection = validConnections.find(c => c.platform === queuedPost.platform);
          
          if (!connection) {
            throw new Error(`No active connection found for ${queuedPost.platform}`);
          }
          
          publishResult = await DirectPublishService.publishSinglePost(post, connection);
        }
      } else {
        // Use DirectPublishService for other platforms
        // Get valid connection for the platform
        const validConnections = await UnifiedOAuthService.validateAndRefreshTokens(queuedPost.userId);
        const connection = validConnections.find(c => c.platform === queuedPost.platform);
        
        if (!connection) {
          throw new Error(`No active connection found for ${queuedPost.platform}`);
        }
        
        publishResult = await DirectPublishService.publishSinglePost(post, connection);
      }

      if (publishResult.success) {
        queuedPost.status = 'completed';
        console.log(`✅ Successfully published post ${queuedPost.postId} to ${queuedPost.platform}`);
        
        // Update post status in database
        await storage.updatePost(queuedPost.postId, {
          status: 'published',
          publishedAt: new Date()
        });
        
        // Remove from queue
        this.removeFromQueue(queuedPost.id);
        
      } else {
        throw new Error(publishResult.error || 'Publishing failed');
      }

    } catch (error: any) {
      console.error(`❌ Failed to publish post ${queuedPost.postId} to ${queuedPost.platform}:`, error.message);
      
      queuedPost.retryCount++;
      queuedPost.lastError = error.message;
      
      if (queuedPost.retryCount >= queuedPost.maxRetries) {
        // Max retries reached - mark as failed
        queuedPost.status = 'failed';
        console.log(`💥 Post ${queuedPost.postId} to ${queuedPost.platform} failed after ${queuedPost.maxRetries} retries`);
        
        // Update post status in database
        await storage.updatePost(queuedPost.postId, {
          status: 'failed',
          errorLog: error.message
        });
        
        // Log to admin dashboard (could be enhanced with database logging)
        this.logFailureToAdmin(queuedPost, error.message);
        
      } else {
        // Schedule retry with exponential backoff (longer delays for rate limited platforms)
        let retryDelay = Math.pow(2, queuedPost.retryCount) * 1000; // 2s, 4s, 8s
        
        // Longer delays for rate limited platforms like X
        if ((queuedPost.platform === 'x' || queuedPost.platform === 'twitter') && 
            error.message.includes('rate limit')) {
          retryDelay = Math.min(retryDelay * 5, 300000); // Up to 5 minutes for rate limits
        }
        
        queuedPost.scheduledTime = new Date(Date.now() + retryDelay);
        queuedPost.status = 'pending';
        
        console.log(`🔄 Retrying post ${queuedPost.postId} to ${queuedPost.platform} in ${retryDelay}ms (attempt ${queuedPost.retryCount + 1}/${queuedPost.maxRetries})`);
      }
    }
  }

  /**
   * Remove post from queue
   */
  private removeFromQueue(queueId: string): void {
    const index = this.queue.findIndex(post => post.id === queueId);
    if (index !== -1) {
      this.queue.splice(index, 1);
    }
  }

  /**
   * Start the queue processor timer
   */
  private startQueueProcessor(): void {
    // Process queue every 5 seconds
    this.processingTimer = setInterval(() => {
      this.processQueue().catch(error => {
        console.error('Queue processing error:', error);
      });
    }, 5000);
    
    console.log('📋 Posting queue processor started (5s intervals)');
  }

  /**
   * Stop the queue processor
   */
  public stopQueueProcessor(): void {
    if (this.processingTimer) {
      clearInterval(this.processingTimer);
      this.processingTimer = null;
      console.log('📋 Posting queue processor stopped');
    }
  }

  /**
   * Get queue status for admin monitoring
   */
  public getQueueStatus() {
    const statusCounts = {
      pending: 0,
      processing: 0,
      completed: 0,
      failed: 0
    };

    this.queue.forEach(post => {
      statusCounts[post.status]++;
    });

    return {
      totalInQueue: this.queue.length,
      statusCounts,
      isProcessing: this.processing,
      nextScheduled: this.queue
        .filter(p => p.status === 'pending')
        .sort((a, b) => a.scheduledTime.getTime() - b.scheduledTime.getTime())[0]?.scheduledTime
    };
  }

  /**
   * Get detailed queue contents for admin
   */
  public getQueueDetails() {
    return this.queue.map(post => ({
      id: post.id,
      postId: post.postId,
      platform: post.platform,
      userId: post.userId,
      status: post.status,
      scheduledTime: post.scheduledTime,
      retryCount: post.retryCount,
      maxRetries: post.maxRetries,
      lastError: post.lastError
    }));
  }

  /**
   * Clear failed posts from queue
   */
  public clearFailedPosts(): number {
    const failedCount = this.queue.filter(p => p.status === 'failed').length;
    this.queue = this.queue.filter(p => p.status !== 'failed');
    return failedCount;
  }

  /**
   * Log failure to admin dashboard
   */
  private logFailureToAdmin(queuedPost: QueuedPost, error: string): void {
    console.error(`📊 ADMIN LOG - Post Publishing Failure:
      Post ID: ${queuedPost.postId}
      Platform: ${queuedPost.platform}
      User ID: ${queuedPost.userId}
      Error: ${error}
      Retry Count: ${queuedPost.retryCount}
      Time: ${new Date().toISOString()}`);
  }

  /**
   * Emergency stop - clear all pending posts
   */
  public emergencyStop(): number {
    const clearedCount = this.queue.filter(p => p.status === 'pending').length;
    this.queue = this.queue.filter(p => p.status !== 'pending');
    this.processing = false;
    
    // Stop the queue processor
    this.stopQueueProcessor();
    
    console.log(`🚨 EMERGENCY STOP: Cleared ${clearedCount} pending posts from queue`);
    return clearedCount;
  }
}

// Export singleton instance
export const postingQueue = new PostingQueueService();