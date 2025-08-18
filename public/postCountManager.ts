import { db } from './db';
import { posts } from '../shared/schema';
import { eq, and } from 'drizzle-orm';
import fs from 'fs';
import path from 'path';

interface PostCountState {
  userId: number;
  totalGenerated: number;
  approvedPosts: number;
  livePosts: number;
  subscriptionQuota: number;
  lastGenerationTime: string;
  cycleStart: string;
}

export class PostCountManager {
  private static readonly POSTS_DB_PATH = path.join(process.cwd(), 'posts-db.json');

  // Load current state from posts-db.json
  static loadState(userId: number): PostCountState | null {
    try {
      if (!fs.existsSync(this.POSTS_DB_PATH)) {
        return null;
      }
      
      const data = JSON.parse(fs.readFileSync(this.POSTS_DB_PATH, 'utf8'));
      return data[userId] || null;
    } catch (error) {
      console.error('Error loading post count state:', error);
      return null;
    }
  }

  // Save state to posts-db.json
  static saveState(userId: number, state: PostCountState): void {
    try {
      let data = {};
      if (fs.existsSync(this.POSTS_DB_PATH)) {
        data = JSON.parse(fs.readFileSync(this.POSTS_DB_PATH, 'utf8'));
      }
      
      data[userId] = state;
      fs.writeFileSync(this.POSTS_DB_PATH, JSON.stringify(data, null, 2));
    } catch (error) {
      console.error('Error saving post count state:', error);
    }
  }

  // Get accurate post counts from database
  static async getActualPostCounts(userId: number): Promise<{
    total: number;
    approved: number;
    live: number;
    scheduled: number;
  }> {
    try {
      const userPosts = await db.select().from(posts).where(eq(posts.userId, userId));
      
      const counts = {
        total: userPosts.length,
        approved: userPosts.filter(p => p.status === 'approved').length,
        live: userPosts.filter(p => p.status === 'approved' && p.publishedAt).length,
        scheduled: userPosts.filter(p => p.status === 'scheduled').length
      };

      console.log(`Actual post counts for user ${userId}:`, counts);
      return counts;
    } catch (error) {
      console.error('Error getting actual post counts:', error);
      return { total: 0, approved: 0, live: 0, scheduled: 0 };
    }
  }

  // Clear unapproved posts before generating new ones
  static async clearUnapprovedPosts(userId: number): Promise<number> {
    try {
      const deletedPosts = await db.delete(posts)
        .where(and(
          eq(posts.userId, userId),
          eq(posts.status, 'scheduled')
        ))
        .returning();

      console.log(`Cleared ${deletedPosts.length} unapproved posts for user ${userId}`);
      return deletedPosts.length;
    } catch (error) {
      console.error('Error clearing unapproved posts:', error);
      return 0;
    }
  }

  // DEPRECATED: Legacy calculation replaced by PostQuotaService
  // Use PostQuotaService.getQuotaStatus() instead
  static calculatePostsToGenerate(
    subscriptionQuota: number,
    currentApproved: number,
    currentScheduled: number
  ): number {
    console.warn('⚠️ DEPRECATED: calculatePostsToGenerate() - Use PostQuotaService.getQuotaStatus() instead');
    
    // Legacy fallback - should not be used
    const currentTotal = currentApproved + currentScheduled;
    const postsNeeded = subscriptionQuota - currentTotal;
    
    console.log(`⚠️ LEGACY Post generation calculation (deprecated):`, {
      subscriptionQuota,
      currentApproved,
      currentScheduled,
      currentTotal,
      postsNeeded: Math.max(0, postsNeeded)
    });

    return Math.max(0, postsNeeded);
  }

  // Validate post count integrity
  static async validatePostIntegrity(userId: number, subscriptionQuota: number): Promise<{
    isValid: boolean;
    actualCounts: any;
    expectedQuota: number;
    needsCorrection: boolean;
  }> {
    const actualCounts = await this.getActualPostCounts(userId);
    const isValid = actualCounts.total <= subscriptionQuota;
    const needsCorrection = actualCounts.total > subscriptionQuota;

    return {
      isValid,
      actualCounts,
      expectedQuota: subscriptionQuota,
      needsCorrection
    };
  }

  // Reset post counts to align with subscription quota
  static async resetPostCounts(userId: number, subscriptionQuota: number): Promise<void> {
    console.log(`Resetting post counts for user ${userId} to quota ${subscriptionQuota}`);
    
    // Clear all unapproved posts first
    await this.clearUnapprovedPosts(userId);
    
    // Get current approved posts
    const { approved } = await this.getActualPostCounts(userId);
    
    // Update state file
    const state: PostCountState = {
      userId,
      totalGenerated: approved,
      approvedPosts: approved,
      livePosts: approved, // Assuming all approved posts are live
      subscriptionQuota,
      lastGenerationTime: new Date().toISOString(),
      cycleStart: new Date().toISOString()
    };
    
    this.saveState(userId, state);
    console.log(`Post counts reset completed for user ${userId}`);
  }

  // Sync database with subscription quota
  static async syncWithQuota(userId: number, subscriptionQuota: number): Promise<{
    cleared: number;
    postsToGenerate: number;
    finalCounts: any;
  }> {
    console.log(`Syncing user ${userId} with subscription quota ${subscriptionQuota}`);
    
    // Clear unapproved posts to prevent doubling
    const cleared = await this.clearUnapprovedPosts(userId);
    
    // Get current state after clearing
    const currentCounts = await this.getActualPostCounts(userId);
    
    // Calculate how many new posts to generate
    const postsToGenerate = this.calculatePostsToGenerate(
      subscriptionQuota,
      currentCounts.approved,
      currentCounts.scheduled
    );

    return {
      cleared,
      postsToGenerate,
      finalCounts: currentCounts
    };
  }
}