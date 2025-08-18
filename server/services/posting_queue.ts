import { db } from '../db';
import { postSchedule } from '../../shared/schema';
import { eq, and } from 'drizzle-orm';

interface QueuedPost {
  id: string;
  userId: number;
  platform: string;
  content: string;
  videoUrl?: string;
  videoData?: any;
  scheduledFor: Date;
  retries: number;
  maxRetries: number;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  metadata?: any;
}

export class PostingQueue {
  private static queue: QueuedPost[] = [];
  private static processing = false;
  private static maxConcurrent = 3;
  private static retryDelay = 5000; // 5 seconds base delay

  // Add video generation output to posting queue
  static async addVideoPost(
    userId: number, 
    postId: string, 
    videoData: any, 
    platform: string, 
    content: string,
    scheduledFor?: Date
  ): Promise<void> {
    try {
      console.log(`📋 Adding video post to queue: ${postId} for ${platform}`);
      
      const queueItem: QueuedPost = {
        id: postId,
        userId,
        platform,
        content,
        videoUrl: videoData.videoUrl,
        videoData,
        scheduledFor: scheduledFor || new Date(),
        retries: 0,
        maxRetries: 3,
        status: 'pending',
        metadata: {
          hasVideo: true,
          videoGenerated: true,
          queuedAt: new Date().toISOString(),
          generationId: videoData.videoId
        }
      };

      this.queue.push(queueItem);
      console.log(`✅ Video post queued: ${postId}, queue length: ${this.queue.length}`);

      // Start processing if not already running
      if (!this.processing) {
        this.startProcessing();
      }

      // Update database with queue status
      await this.updatePostStatus(postId, 'queued_for_posting');

    } catch (error) {
      console.error('❌ Failed to add video post to queue:', error);
    }
  }

  // Start queue processing with retries and delays
  private static async startProcessing(): Promise<void> {
    if (this.processing) return;
    
    this.processing = true;
    console.log('🚀 Starting posting queue processor...');

    while (this.queue.length > 0) {
      const currentBatch = this.queue.splice(0, this.maxConcurrent);
      
      // Process batch concurrently with 2-second stagger
      const promises = currentBatch.map((post, index) => 
        this.processPostWithDelay(post, index * 2000)
      );

      try {
        await Promise.all(promises);
      } catch (error) {
        console.error('❌ Batch processing error:', error);
      }

      // Brief pause between batches
      if (this.queue.length > 0) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    this.processing = false;
    console.log('✅ Queue processing completed');
  }

  // Process individual post with delay and retry logic
  private static async processPostWithDelay(post: QueuedPost, delay: number): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, delay));
    return this.processPost(post);
  }

  private static async processPost(post: QueuedPost): Promise<void> {
    console.log(`🔄 Processing post: ${post.id} on ${post.platform} (attempt ${post.retries + 1})`);
    
    try {
      post.status = 'processing';
      
      // Mock posting logic - replace with actual platform APIs
      const success = await this.publishToplatform(post);
      
      if (success) {
        post.status = 'completed';
        await this.updatePostStatus(post.id, 'published');
        console.log(`✅ Post published successfully: ${post.id}`);
      } else {
        throw new Error('Publishing failed');
      }

    } catch (error) {
      console.error(`❌ Post processing failed: ${post.id}`, error.message);
      
      post.retries += 1;
      if (post.retries < post.maxRetries) {
        // Exponential backoff retry
        const retryDelay = this.retryDelay * Math.pow(2, post.retries);
        console.log(`🔄 Retrying post ${post.id} in ${retryDelay}ms...`);
        
        setTimeout(() => {
          this.queue.unshift(post); // Add back to front of queue
          if (!this.processing) {
            this.startProcessing();
          }
        }, retryDelay);
      } else {
        post.status = 'failed';
        await this.updatePostStatus(post.id, 'failed');
        console.log(`❌ Post failed after ${post.maxRetries} retries: ${post.id}`);
      }
    }
  }

  // Mock platform publishing - replace with actual implementations
  private static async publishToplatform(post: QueuedPost): Promise<boolean> {
    console.log(`📤 Publishing to ${post.platform}:`, {
      content: post.content.substring(0, 50) + '...',
      hasVideo: !!post.videoUrl,
      videoUrl: post.videoUrl
    });

    // Simulate API call with 90% success rate
    await new Promise(resolve => setTimeout(resolve, 1000));
    return Math.random() > 0.1;
  }

  // Update post status in database
  private static async updatePostStatus(postId: string, status: string): Promise<void> {
    try {
      await db.update(postSchedule)
        .set({ 
          status,
          updatedAt: new Date()
        })
        .where(eq(postSchedule.id, postId));
      
      console.log(`📊 Post status updated: ${postId} -> ${status}`);
    } catch (error) {
      console.error('❌ Failed to update post status:', error);
    }
  }

  // Get queue status for monitoring
  static getQueueStatus(): any {
    return {
      queueLength: this.queue.length,
      processing: this.processing,
      pendingPosts: this.queue.filter(p => p.status === 'pending').length,
      failedPosts: this.queue.filter(p => p.status === 'failed').length,
      maxConcurrent: this.maxConcurrent
    };
  }

  // Emergency stop queue processing
  static stopProcessing(): void {
    this.processing = false;
    console.log('🛑 Queue processing stopped');
  }

  // Clear failed posts from queue
  static clearFailedPosts(): void {
    const before = this.queue.length;
    this.queue = this.queue.filter(p => p.status !== 'failed');
    const cleared = before - this.queue.length;
    console.log(`🧹 Cleared ${cleared} failed posts from queue`);
  }
}