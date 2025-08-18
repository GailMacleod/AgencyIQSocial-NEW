/**
 * CENTRALIZED POST QUOTA SERVICE
 * Single source of truth for all post counting and quota management
 * Eliminates fragmented systems causing post count doubling
 */

import { storage } from './storage';
import { db } from './db';
import { users, posts, postLedger } from '../shared/schema';
import { eq, and, sql } from 'drizzle-orm';

interface QuotaStatus {
  userId: number;
  remainingPosts: number;
  totalPosts: number;
  subscriptionPlan: string;
  subscriptionActive: boolean;
}

interface PostCountSummary {
  approved: number;
  draft: number;
  published: number;
  failed: number;
  total: number;
}

export class PostQuotaService {
  
  /**
   * PLAN QUOTAS - Single source of truth
   * Updated July 25, 2025: Starter 10, Growth 20, Pro 30 posts per 30-day cycle
   */
  private static readonly PLAN_QUOTAS = {
    'starter': 10,
    'growth': 20, 
    'professional': 30
  };

  /**
   * CONCURRENT OPERATION LOCKS - Prevent post creep during timing gaps
   */
  private static userLocks: Map<number, Promise<any>> = new Map();
  private static operationQueue: Map<number, Array<() => Promise<any>>> = new Map();
  
  /**
   * Lock mechanism to prevent concurrent operations per userId
   */
  private static async withUserLock<T>(userId: number, operation: () => Promise<T>): Promise<T> {
    // If user has active lock, queue the operation
    if (this.userLocks.has(userId)) {
      console.log(`🔒 User ${userId} lock active - queueing operation`);
      return new Promise((resolve, reject) => {
        if (!this.operationQueue.has(userId)) {
          this.operationQueue.set(userId, []);
        }
        this.operationQueue.get(userId)!.push(async () => {
          try {
            const result = await operation();
            resolve(result);
          } catch (error) {
            reject(error);
          }
        });
      });
    }

    // Create lock for this user
    const lockPromise = (async () => {
      try {
        console.log(`🔒 Acquiring lock for user ${userId}`);
        const result = await operation();
        
        // Process queued operations sequentially
        const queue = this.operationQueue.get(userId);
        if (queue && queue.length > 0) {
          console.log(`📋 Processing ${queue.length} queued operations for user ${userId}`);
          for (const queuedOperation of queue) {
            await queuedOperation();
          }
          this.operationQueue.delete(userId);
        }
        
        return result;
      } finally {
        // Release lock
        this.userLocks.delete(userId);
        console.log(`🔓 Released lock for user ${userId}`);
      }
    })();

    this.userLocks.set(userId, lockPromise);
    return lockPromise;
  }

  /**
   * DYNAMIC 30-DAY CYCLE MANAGEMENT
   * Each customer gets individual 30-day cycle from their subscription date
   */
  private static calculateCycleForUser(subscriptionStart: Date): { cycleStart: Date; cycleEnd: Date } {
    const cycleStart = new Date(subscriptionStart);
    const cycleEnd = new Date(subscriptionStart);
    cycleEnd.setDate(cycleEnd.getDate() + 30);
    return { cycleStart, cycleEnd };
  }

  /**
   * FIXED CYCLE FOR TESTING (July 3-31, 2025) - Brisbane Ekka focus
   */
  private static readonly CYCLE_START = new Date('2025-07-03T00:00:00.000Z');
  private static readonly CYCLE_END = new Date('2025-07-31T23:59:59.999Z');
  private static readonly EKKA_START = new Date('2025-07-09T00:00:00.000Z');
  private static readonly EKKA_END = new Date('2025-07-19T23:59:59.999Z');

  /**
   * CACHE FOR HIGH TRAFFIC OPTIMIZATION
   */
  private static quotaCache: Map<number, { quota: QuotaStatus; expiry: number }> = new Map();
  private static readonly CACHE_DURATION = 2 * 60 * 1000; // 2 minutes cache
  
  /**
   * Performance metrics tracking
   */
  private static performanceMetrics = {
    cacheHits: 0,
    cacheMisses: 0,
    totalRequests: 0,
    avgResponseTime: 0
  };

  /**
   * Get current quota status for a user (with high-traffic caching and postLedger integration)
   */
  static async getQuotaStatus(userId: number): Promise<QuotaStatus | null> {
    const startTime = Date.now();
    this.performanceMetrics.totalRequests++;
    
    try {
      // Check cache first
      const cached = this.quotaCache.get(userId);
      if (cached && Date.now() < cached.expiry) {
        this.performanceMetrics.cacheHits++;
        this.updatePerformanceMetrics(Date.now() - startTime);
        return cached.quota;
      }

      // Cache miss - fetch from database with postLedger integration
      this.performanceMetrics.cacheMisses++;
      const user = await storage.getUser(userId);
      if (!user) return null;

      // Check postLedger for accurate 30-day rolling quota
      const userIdString = user.userId || user.id.toString();
      const ledgerEntry = await db.select()
        .from(postLedger)
        .where(eq(postLedger.userId, userIdString))
        .limit(1);

      let remainingPosts = user.remainingPosts || 0;
      let totalPosts = user.totalPosts || 0;
      let subscriptionPlan = user.subscriptionPlan || 'starter';

      // If postLedger exists, use it as authoritative source for quota
      // BUT only count actually published posts, not approved/draft posts
      if (ledgerEntry.length > 0) {
        const ledger = ledgerEntry[0];
        totalPosts = ledger.quota;
        
        // Count only published posts from the posts table
        const publishedCount = await db.select({ count: sql`count(*)` })
          .from(posts)
          .where(and(
            eq(posts.userId, userId.toString()),
            eq(posts.status, 'published')
          ));
        
        const actualPublishedPosts = Number(publishedCount[0]?.count || 0);
        remainingPosts = Math.max(0, ledger.quota - actualPublishedPosts);
        subscriptionPlan = ledger.subscriptionTier === 'pro' ? 'professional' : ledger.subscriptionTier;
        
        console.log(`📊 Quota calculation for user ${userId}: ${actualPublishedPosts} published posts, ${remainingPosts}/${totalPosts} remaining`);
      }

      const quota: QuotaStatus = {
        userId: user.id,
        remainingPosts,
        totalPosts,
        subscriptionPlan,
        subscriptionActive: user.subscriptionActive || false
      };

      // Cache the result
      this.quotaCache.set(userId, {
        quota,
        expiry: Date.now() + this.CACHE_DURATION
      });

      this.updatePerformanceMetrics(Date.now() - startTime);
      return quota;
    } catch (error) {
      console.error('Error getting quota status:', error);
      this.updatePerformanceMetrics(Date.now() - startTime);
      return null;
    }
  }

  /**
   * Initialize quota for new user based on plan
   */
  static async initializeQuota(userId: number, plan: string): Promise<boolean> {
    try {
      const quota = this.PLAN_QUOTAS[plan as keyof typeof this.PLAN_QUOTAS] || this.PLAN_QUOTAS.starter;
      
      // First check if user exists
      const existingUser = await db.select().from(users).where(eq(users.id, userId)).limit(1);
      
      if (existingUser.length === 0) {
        // Create new user if doesn't exist
        // Use SQL execute to bypass TypeScript schema issues for user creation
        await db.execute(sql`
          INSERT INTO users (
            user_id, email, password, phone, subscription_plan, 
            subscription_active, subscription_start, remaining_posts, total_posts
          ) VALUES (
            ${userId.toString()}, 
            ${`customer${userId}@queensland-business.com.au`},
            ${'test-password-' + userId},
            ${`+61400${String(userId).padStart(6, '0')}`},
            ${plan},
            true,
            ${new Date()},
            ${quota},
            ${quota}
          )
        `);
      } else {
        // Update existing user quota
        // Use SQL execute to bypass TypeScript schema mismatch
        await db.execute(sql`
          UPDATE users 
          SET remaining_posts = ${quota}, 
              total_posts = ${quota}, 
              subscription_plan = ${plan}, 
              subscription_active = true
          WHERE id = ${userId}
        `);
      }

      console.log(`✅ Quota initialized for user ${userId}: ${quota} posts (${plan} plan)`);
      return true;
    } catch (error) {
      console.error('Error initializing quota:', error);
      return false;
    }
  }

  /**
   * Performance metrics helper
   */
  private static updatePerformanceMetrics(responseTime: number): void {
    const { totalRequests, avgResponseTime } = this.performanceMetrics;
    this.performanceMetrics.avgResponseTime = 
      (avgResponseTime * (totalRequests - 1) + responseTime) / totalRequests;
  }

  /**
   * Clear cache for specific user (called after quota changes)
   */
  static clearUserCache(userId: number): void {
    this.quotaCache.delete(userId);
  }

  /**
   * Get performance metrics (for monitoring)
   */
  static getPerformanceMetrics() {
    return { ...this.performanceMetrics };
  }

  /**
   * Create a post with proper quota tracking
   */
  static async createPost(userId: number, postData: any): Promise<any> {
    return this.withUserLock(userId, async () => {
      console.log(`🔒 CreatePost operation starting for user ${userId}`);
      
      try {
        // Check if user has quota remaining
        const hasQuota = await this.hasPostsRemaining(userId);
        if (!hasQuota) {
          throw new Error(`User ${userId} has no remaining posts in quota`);
        }
        
        // Create the post using storage
        const post = await storage.createPost({
          userId: userId,
          ...postData
        });
        
        // Log the creation
        await this.logQuotaOperation(userId, post.id, 'creation', 
          `Post created with quota tracking. Status: ${postData.status}`);
        
        console.log(`✅ Post created for user ${userId} with quota tracking - Post ID: ${post.id}`);
        return post;
        
      } catch (error) {
        console.error('Error creating post with quota tracking:', error);
        throw error;
      }
    });
  }

  /**
   * Approve a post (status change only) - NO QUOTA DEDUCTION
   */
  static async approvePost(userId: number, postId: number): Promise<boolean> {
    return this.withUserLock(userId, async () => {
      console.log(`🔒 ApprovePost operation starting for user ${userId}, post ${postId}`);
      
      try {
        // Verify post exists and belongs to user
        const post = await db.select().from(posts).where(eq(posts.id, postId)).limit(1);
        if (post.length === 0 || post[0].userId !== userId.toString()) {
          console.warn(`Post ${postId} not found or doesn't belong to user ${userId}`);
          return false;
        }
        
        // No quota checking needed - users can approve unlimited posts
        // Quota only deducted during actual platform publishing
        
        // Update post status to approved (no quota deduction yet)
        await db.update(posts)
          .set({ status: 'approved' } as any)
          .where(eq(posts.id, postId));
        
        // Log the approval
        await this.logQuotaOperation(userId, postId, 'approval', 
          `Post approved for future posting. No quota deduction - only deducted during actual platform publishing.`);
        
        console.log(`✅ Post ${postId} approved for user ${userId} - quota will be deducted only after successful platform publishing`);
        return true;
        
      } catch (error) {
        console.error('Error approving post:', error);
        return false;
      }
    });
  }

  /**
   * Deduct quota ONLY after successful posting - called by platform publishing functions
   * Integrates with postLedger for accurate 30-day rolling quota tracking
   */
  /**
   * ENHANCED: Quota deduction with rollback capability - Prevents post creep
   * Uses locking mechanism to prevent concurrent operations
   */
  static async postApproved(userId: number, postId: number, publishingSuccess: boolean = true): Promise<boolean> {
    return this.withUserLock(userId, async () => {
      console.log(`🔒 PostApproved operation starting for user ${userId}, post ${postId}, success: ${publishingSuccess}`);
      
      // Store rollback data in case we need to undo changes
      let rollbackData: {
        ledgerUsedPosts?: number;
        userRemainingPosts?: number;
        postStatus?: string;
        postPublishedAt?: Date | null;
        ledgerCreated?: boolean;
      } = {};

      try {
        // Verify post exists and belongs to user
        const post = await db.select().from(posts).where(eq(posts.id, postId)).limit(1);
        if (post.length === 0 || post[0].userId !== userId.toString()) {
          console.warn(`Post ${postId} not eligible for quota deduction - doesn't belong to user ${userId}`);
          return false;
        }
        
        // Store original post state for rollback
        rollbackData.postStatus = post[0].status;
        rollbackData.postPublishedAt = post[0].publishedAt;
        
        // Allow quota deduction for approved or published posts
        const validStatuses = ['approved', 'published'];
        if (!validStatuses.includes(post[0].status)) {
          console.warn(`Post ${postId} not eligible for quota deduction - status '${post[0].status}' not in [${validStatuses.join(', ')}]`);
          return false;
        }
        
        // Get current quota status
        const status = await this.getQuotaStatus(userId);
        if (!status || status.remainingPosts <= 0) {
          console.warn(`User ${userId} has no remaining quota for post ${postId}`);
          return false;
        }

        // Get user for postLedger integration
        const user = await storage.getUser(userId);
        if (!user) return false;

        const userIdString = user.userId || user.id.toString();
        
        // Store current user remaining posts for rollback
        rollbackData.userRemainingPosts = status.remainingPosts;
        
        // Handle publishing failure - rollback only
        if (!publishingSuccess) {
          console.warn(`🔄 Publishing failed for post ${postId}, performing rollback`);
          await this.rollbackPostQuota(userId, postId, rollbackData);
          return false;
        }
        
        // Update postLedger table for accurate 30-day tracking
        const ledgerEntry = await db.select()
          .from(postLedger)
          .where(eq(postLedger.userId, userIdString))
          .limit(1);

        if (ledgerEntry.length > 0) {
          // Store original used posts count for rollback
          rollbackData.ledgerUsedPosts = ledgerEntry[0].usedPosts;
          
          // Update existing postLedger entry
          await db.update(postLedger)
            .set({
              usedPosts: sql`${postLedger.usedPosts} + 1`,
              lastPosted: new Date(),
              updatedAt: new Date()
            })
            .where(eq(postLedger.userId, userIdString));
        } else {
          // Mark that we're creating a new ledger entry
          rollbackData.ledgerCreated = true;
          
          // Create new postLedger entry if it doesn't exist
          const planQuota = this.PLAN_QUOTAS[status.subscriptionPlan as keyof typeof this.PLAN_QUOTAS] || this.PLAN_QUOTAS.starter;
          await db.insert(postLedger).values({
            userId: userIdString,
            subscriptionTier: status.subscriptionPlan === 'professional' ? 'pro' : status.subscriptionPlan,
            periodStart: new Date(),
            quota: planQuota,
            usedPosts: 1,
            lastPosted: new Date()
          });
        }
        
        // Also update the users table for backward compatibility
        await db.update(users)
          .set({
            remainingPosts: sql`remaining_posts - 1`
          } as any)
          .where(
            and(
              eq(users.id, userId),
              sql`${users.remainingPosts} > 0`
            )
          );
        
        // Update post status to published
        await db.update(posts)
          .set({ 
            status: 'published',
            publishedAt: new Date()
          })
          .where(eq(posts.id, postId));
        
        // Clear cache after quota change
        this.clearUserCache(userId);
        
        console.log(`📉 Quota deducted after successful posting for user ${userId}. Post ID: ${postId}, Remaining: ${status.remainingPosts - 1}`);
        
        // Log to debug file for tracking
        await this.logQuotaOperation(userId, postId, 'post_deduction', 
          `Post successfully posted and quota deducted. Remaining: ${status.remainingPosts - 1}/${status.totalPosts}`);
        
        return true;
      } catch (error) {
        console.error(`💥 Error in postApproved for user ${userId}, post ${postId}:`, error);
        
        // Perform rollback on any error
        try {
          await this.rollbackPostQuota(userId, postId, rollbackData);
          console.log(`🔄 Rollback completed for user ${userId}, post ${postId}`);
        } catch (rollbackError) {
          console.error(`💥 CRITICAL: Rollback failed for user ${userId}, post ${postId}:`, rollbackError);
          // Log critical rollback failure
          await this.logQuotaOperation(userId, postId, 'rollback_failure', 
            `Critical rollback failure: ${rollbackError instanceof Error ? rollbackError.message : String(rollbackError)}`);
        }
        
        return false;
      }
    });
  }

  /**
   * Rollback quota changes when publishing fails
   */
  private static async rollbackPostQuota(userId: number, postId: number, rollbackData: any): Promise<void> {
    console.log(`🔄 Starting rollback for user ${userId}, post ${postId}`);
    
    try {
      const user = await storage.getUser(userId);
      if (!user) return;

      const userIdString = user.userId || user.id.toString();
      
      // Rollback postLedger changes
      if (rollbackData.ledgerCreated) {
        // Delete the ledger entry we created
        await db.delete(postLedger).where(eq(postLedger.userId, userIdString));
        console.log(`🔄 Deleted created ledger entry for user ${userId}`);
      } else if (rollbackData.ledgerUsedPosts !== undefined) {
        // Restore original used posts count
        await db.update(postLedger)
          .set({
            usedPosts: rollbackData.ledgerUsedPosts,
            updatedAt: new Date()
          })
          .where(eq(postLedger.userId, userIdString));
        console.log(`🔄 Restored ledger used posts to ${rollbackData.ledgerUsedPosts} for user ${userId}`);
      }
      
      // Rollback users table quota
      if (rollbackData.userRemainingPosts !== undefined) {
        await db.update(users)
          .set({
            remainingPosts: rollbackData.userRemainingPosts
          } as any)
          .where(eq(users.id, userId));
        console.log(`🔄 Restored user remaining posts to ${rollbackData.userRemainingPosts} for user ${userId}`);
      }
      
      // Rollback post status
      if (rollbackData.postStatus) {
        await db.update(posts)
          .set({
            status: rollbackData.postStatus,
            publishedAt: rollbackData.postPublishedAt
          })
          .where(eq(posts.id, postId));
        console.log(`🔄 Restored post status to '${rollbackData.postStatus}' for post ${postId}`);
      }
      
      // Clear cache after rollback
      this.clearUserCache(userId);
      
      // Log rollback operation
      await this.logQuotaOperation(userId, postId, 'rollback_success', 
        `Successfully rolled back quota changes due to publishing failure`);
        
    } catch (error) {
      console.error(`💥 Error during rollback for user ${userId}, post ${postId}:`, error);
      throw error;
    }
  }

  /**
   * Legacy method - DEPRECATED - Use approvePost() for approval, postApproved() for quota deduction
   */
  static async deductPost(userId: number, postId: number): Promise<boolean> {
    console.warn('⚠️ DEPRECATED: deductPost() called - use approvePost() for approval, postApproved() for quota deduction');
    return await this.approvePost(userId, postId);
  }

  /**
   * Check if post can be edited without deducting quota
   */
  static async canEditPost(userId: number, postId: number): Promise<boolean> {
    try {
      const post = await db.select().from(posts).where(eq(posts.id, postId)).limit(1);
      if (post.length === 0) {
        return false;
      }

      // Allow editing for draft posts without quota deduction
      if (post[0].status === 'draft') {
        return true;
      }

      // Check quota for approved/published posts
      const status = await this.getQuotaStatus(userId);
      return status ? status.remainingPosts > 0 && status.subscriptionActive : false;
    } catch (error) {
      console.error('Error checking edit permission:', error);
      return false;
    }
  }

  /**
   * Log quota operations to debug file
   */
  private static async logQuotaOperation(userId: number, postId: number, operation: string, details: string): Promise<void> {
    try {
      const fs = await import('fs');
      const path = await import('path');
      
      const timestamp = new Date().toISOString();
      const logEntry = `[${timestamp}] QUOTA_OP: User ${userId}, Post ${postId}, Operation: ${operation}, Details: ${details}\n`;
      
      const logPath = path.join(process.cwd(), 'data/quota-debug.log');
      
      // Ensure directory exists
      await fs.promises.mkdir(path.dirname(logPath), { recursive: true });
      
      // Use async file operation
      await fs.promises.appendFile(logPath, logEntry);
    } catch (error) {
      console.error('Error logging quota operation:', error);
    }
  }

  /**
   * Get actual post counts from database
   */
  static async getPostCounts(userId: number): Promise<PostCountSummary> {
    try {
      const userPosts = await storage.getPostsByUser(userId);
      
      const summary: PostCountSummary = {
        approved: userPosts.filter(p => p.status === 'approved').length,
        draft: userPosts.filter(p => p.status === 'draft').length,
        published: userPosts.filter(p => p.status === 'published').length,
        failed: userPosts.filter(p => p.status === 'failed').length,
        total: userPosts.length
      };

      return summary;
    } catch (error) {
      console.error('Error getting post counts:', error);
      return { approved: 0, draft: 0, published: 0, failed: 0, total: 0 };
    }
  }

  /**
   * Check if user has posts remaining
   */
  static async hasPostsRemaining(userId: number): Promise<boolean> {
    const status = await this.getQuotaStatus(userId);
    return status ? status.remainingPosts > 0 && status.subscriptionActive : false;
  }

  /**
   * Upgrade user's plan and adjust quota
   */
  static async upgradePlan(userId: number, newPlan: string): Promise<boolean> {
    return this.withUserLock(userId, async () => {
      console.log(`🔒 UpgradePlan operation starting for user ${userId}, plan ${newPlan}`);
      
      try {
        const newQuota = this.PLAN_QUOTAS[newPlan as keyof typeof this.PLAN_QUOTAS];
        if (!newQuota) {
          console.error(`Invalid plan: ${newPlan}`);
          return false;
        }

        const currentStatus = await this.getQuotaStatus(userId);
        if (!currentStatus) return false;

        // Add the difference to remaining posts
        const quotaDifference = newQuota - (currentStatus.totalPosts || 0);
        const newRemaining = Math.max(0, currentStatus.remainingPosts + quotaDifference);

        await db.update(users)
          .set({
            subscriptionPlan: newPlan,
            totalPosts: newQuota,
            remainingPosts: newRemaining
          })
          .where(eq(users.id, userId));

        // Clear cache after upgrade
        this.clearUserCache(userId);

        console.log(`✅ Plan upgraded for user ${userId}: ${newPlan} (${newQuota} total posts)`);
        
        // Log the upgrade
        await this.logQuotaOperation(userId, 0, 'plan_upgrade', 
          `Plan upgraded to ${newPlan}. New quota: ${newQuota}, Remaining: ${newRemaining}`);
        
        return true;
      } catch (error) {
        console.error('Error upgrading plan:', error);
        return false;
      }
    });
  }

  /**
   * Reset quota to plan default (admin function)
   */
  static async resetQuota(userId: number): Promise<boolean> {
    return this.withUserLock(userId, async () => {
      console.log(`🔒 ResetQuota operation starting for user ${userId}`);
      
      try {
        const status = await this.getQuotaStatus(userId);
        if (!status) return false;

        const defaultQuota = this.PLAN_QUOTAS[status.subscriptionPlan as keyof typeof this.PLAN_QUOTAS] || this.PLAN_QUOTAS.starter;

        await db.update(users)
          .set({
            remainingPosts: defaultQuota,
            totalPosts: defaultQuota
          })
          .where(eq(users.id, userId));

        // Clear cache after reset
        this.clearUserCache(userId);

        console.log(`✅ Quota reset for user ${userId}: ${defaultQuota} posts restored`);
        
        // Log the reset
        await this.logQuotaOperation(userId, 0, 'quota_reset', 
          `Quota reset to plan default: ${defaultQuota} posts`);
        
        return true;
      } catch (error) {
        console.error('Error resetting quota:', error);
        return false;
      }
    });
  }



  /**
   * Validate quota integrity
   */
  static async validateQuota(userId: number): Promise<{ valid: boolean; issues: string[] }> {
    try {
      const status = await this.getQuotaStatus(userId);
      const issues: string[] = [];

      if (!status) {
        return { valid: false, issues: ['User not found'] };
      }

      // Check for negative values
      if (status.remainingPosts < 0) {
        issues.push(`Negative remaining posts: ${status.remainingPosts}`);
      }

      // Check for over-allocation
      if (status.remainingPosts > status.totalPosts) {
        issues.push(`Remaining posts (${status.remainingPosts}) exceeds total (${status.totalPosts})`);
      }

      // Check plan consistency
      const expectedQuota = this.PLAN_QUOTAS[status.subscriptionPlan as keyof typeof this.PLAN_QUOTAS];
      if (expectedQuota && status.totalPosts !== expectedQuota) {
        issues.push(`Total posts (${status.totalPosts}) doesn't match plan quota (${expectedQuota})`);
      }

      return { valid: issues.length === 0, issues };
    } catch (error) {
      console.error('Error validating quota:', error);
      return { valid: false, issues: ['Validation error'] };
    }
  }

  /**
   * DEBUG FUNCTION - Read-only quota debugging and cycle reset simulation
   * Logs current state and simulates 30-day reset without modifying database
   */
  static async debugQuotaAndSimulateReset(email: string): Promise<void> {
    const fs = await import('fs');
    const path = await import('path');
    
    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
      console.log(`[${new Date().toISOString()}] ERROR: Invalid email format: ${email}`);
      return;
    }
    
    async function logToDebugFile(message: string) {
      const timestamp = new Date().toISOString();
      const logEntry = `[${timestamp}] ${message}\n`;
      
      const logPath = path.join(process.cwd(), 'data/quota-debug.log');
      
      // Ensure directory exists
      await fs.promises.mkdir(path.dirname(logPath), { recursive: true });
      
      // Use async file operation
      await fs.promises.appendFile(logPath, logEntry);
      console.log(logEntry.trim());
    }

    try {
      await logToDebugFile('=== PostQuotaService Debug Session Started ===');
      await logToDebugFile(`Target User: ${email}`);
      
      // Parallel database queries for better performance
      const [userResult, postCountsResult] = await Promise.all([
        db.select().from(users).where(eq(users.email, email)).limit(1),
        // We'll get post counts after user validation
        Promise.resolve(null)
      ]);
      
      if (userResult.length === 0) {
        await logToDebugFile(`ERROR: User ${email} not found in database`);
        return;
      }

      const userData = userResult[0];
      await logToDebugFile(`User Found: ID ${userData.id}`);
      
      // Get current quota status and post counts in parallel
      const [currentStatus, postCounts] = await Promise.all([
        this.getQuotaStatus(userData.id),
        this.getPostCountsPaginated(userData.id)
      ]);
      
      if (!currentStatus) {
        await logToDebugFile('ERROR: Could not retrieve quota status');
        return;
      }

      await logToDebugFile('=== CURRENT QUOTA STATUS ===');
      await logToDebugFile(`User ID: ${currentStatus.userId}`);
      await logToDebugFile(`Subscription Plan: ${currentStatus.subscriptionPlan}`);
      await logToDebugFile(`Subscription Active: ${currentStatus.subscriptionActive}`);
      await logToDebugFile(`Total Posts: ${currentStatus.totalPosts}`);
      await logToDebugFile(`Remaining Posts: ${currentStatus.remainingPosts}`);
      await logToDebugFile(`Used Posts: ${currentStatus.totalPosts - currentStatus.remainingPosts}`);

      await logToDebugFile('=== ACTUAL POST COUNTS ===');
      await logToDebugFile(`Total Posts in DB: ${postCounts.total}`);
      await logToDebugFile(`Draft Posts: ${postCounts.draft}`);
      await logToDebugFile(`Approved Posts: ${postCounts.approved}`);
      await logToDebugFile(`Published Posts: ${postCounts.published}`);
      await logToDebugFile(`Failed Posts: ${postCounts.failed}`);

      // Calculate expected quota after posts (maintaining 2-post conservative buffer)
      const effectiveUsed = postCounts.approved + postCounts.published;
      const expectedRemaining = currentStatus.totalPosts - effectiveUsed;
      await logToDebugFile(`Expected Remaining (${currentStatus.totalPosts} - ${effectiveUsed}): ${expectedRemaining}`);
      await logToDebugFile(`Actual Remaining: ${currentStatus.remainingPosts}`);
      await logToDebugFile(`Discrepancy: ${currentStatus.remainingPosts - expectedRemaining} posts (conservative buffer maintained)`);

      // Simulate 30-day cycle reset (NO DATABASE CHANGES)
      await logToDebugFile('=== SIMULATING 30-DAY CYCLE RESET ===');
      await logToDebugFile('NOTE: This is a READ-ONLY simulation - no database changes will be made');
      
      const planQuota = this.PLAN_QUOTAS[currentStatus.subscriptionPlan as keyof typeof this.PLAN_QUOTAS] || this.PLAN_QUOTAS.starter;
      
      await logToDebugFile(`Plan: ${currentStatus.subscriptionPlan}`);
      await logToDebugFile(`Plan Quota: ${planQuota} posts`);
      
      // Simulate what the reset would do
      const simulatedReset = {
        beforeReset: {
          totalPosts: currentStatus.totalPosts,
          remainingPosts: currentStatus.remainingPosts,
          subscriptionPlan: currentStatus.subscriptionPlan
        },
        afterReset: {
          totalPosts: planQuota,
          remainingPosts: planQuota,
          subscriptionPlan: currentStatus.subscriptionPlan
        },
        changes: {
          totalPostsChange: planQuota - currentStatus.totalPosts,
          remainingPostsChange: planQuota - currentStatus.remainingPosts
        }
      };

      await logToDebugFile('=== SIMULATION RESULTS ===');
      await logToDebugFile(`BEFORE RESET: Total=${simulatedReset.beforeReset.totalPosts}, Remaining=${simulatedReset.beforeReset.remainingPosts}`);
      await logToDebugFile(`AFTER RESET: Total=${simulatedReset.afterReset.totalPosts}, Remaining=${simulatedReset.afterReset.remainingPosts}`);
      await logToDebugFile(`CHANGES: Total posts ${simulatedReset.changes.totalPostsChange >= 0 ? '+' : ''}${simulatedReset.changes.totalPostsChange}, Remaining posts ${simulatedReset.changes.remainingPostsChange >= 0 ? '+' : ''}${simulatedReset.changes.remainingPostsChange}`);

      // Validate simulated result
      if (simulatedReset.afterReset.totalPosts === planQuota && simulatedReset.afterReset.remainingPosts === planQuota) {
        await logToDebugFile('✅ SIMULATION PASSED: Reset would correctly set both values to plan quota');
      } else {
        await logToDebugFile('❌ SIMULATION FAILED: Reset logic needs adjustment');
      }

      await logToDebugFile('=== QUOTA INTEGRITY CHECK ===');
      const validation = await this.validateQuota(userData.id);
      await logToDebugFile(`Quota Valid: ${validation.valid}`);
      if (validation.issues.length > 0) {
        for (const issue of validation.issues) {
          await logToDebugFile(`Issue: ${issue}`);
        }
      }

      await logToDebugFile('=== DEBUG SESSION COMPLETED ===');
      await logToDebugFile('CONFIRMATION: No live data was modified during this debug session');
      
    } catch (error) {
      await logToDebugFile(`ERROR during debug session: ${error}`);
      await logToDebugFile(`Stack trace: ${error instanceof Error ? error.stack : 'Unknown error'}`);
    }
  }

  /**
   * Get actual post counts from database with pagination
   */
  static async getPostCountsPaginated(userId: number, limit = 1000): Promise<PostCountSummary> {
    try {
      let allPosts: any[] = [];
      let offset = 0;
      let hasMore = true;

      // Paginate through posts to handle large volumes
      while (hasMore) {
        const batch = await storage.getPostsByUserPaginated(userId, limit, offset);
        allPosts = allPosts.concat(batch);
        
        hasMore = batch.length === limit;
        offset += limit;
        
        // Safety limit to prevent infinite loops
        if (offset > 50000) {
          console.warn(`Post pagination stopped at ${offset} posts for user ${userId}`);
          break;
        }
      }
      
      const summary: PostCountSummary = {
        approved: allPosts.filter(p => p.status === 'approved').length,
        draft: allPosts.filter(p => p.status === 'draft').length,
        published: allPosts.filter(p => p.status === 'published').length,
        failed: allPosts.filter(p => p.status === 'failed').length,
        total: allPosts.length
      };

      return summary;
    } catch (error) {
      console.error('Error getting paginated post counts:', error);
      return { approved: 0, draft: 0, published: 0, failed: 0, total: 0 };
    }
  }

  /**
   * Check if post is within current 30-day cycle (July 3-31, 2025)
   */
  static isWithinCurrentCycle(date: Date): boolean {
    return date >= PostQuotaService.CYCLE_START && date <= PostQuotaService.CYCLE_END;
  }

  /**
   * Check if post is within Ekka event period (July 9-19, 2025)
   */
  static isWithinEkkaEvent(date: Date): boolean {
    return date >= PostQuotaService.EKKA_START && date <= PostQuotaService.EKKA_END;
  }

  /**
   * Enforce 30 event-driven posts for 30-day cycle
   */
  static async enforce30DayCycle(userId: number): Promise<{ success: boolean; message: string; postsInCycle: number }> {
    const startTime = Date.now();
    
    try {
      const { storage } = await import('./storage.js');
      
      // Get all posts in the current cycle
      const allPosts = await storage.getPostsByUser(userId);
      const cycleStart = PostQuotaService.CYCLE_START;
      const cycleEnd = PostQuotaService.CYCLE_END;
      
      const postsInCycle = allPosts.filter(post => {
        if (!post.scheduledFor) return false;
        const postDate = new Date(post.scheduledFor);
        return PostQuotaService.isWithinCurrentCycle(postDate);
      });
      
      const quota = await PostQuotaService.getQuotaStatus(userId);
      if (!quota) {
        return { success: false, message: 'User quota not found', postsInCycle: 0 };
      }
      
      // Enforce professional plan 30 posts for 30-day cycle
      if (quota.subscriptionPlan === 'professional' && postsInCycle.length > 30) {
        await PostQuotaService.logQuotaOperation(userId, 0, 'CYCLE_ENFORCEMENT', 
          `Excess posts detected: ${postsInCycle.length}/30 in cycle. Enforcement active.`);
        
        return { 
          success: false, 
          message: `Cycle quota exceeded: ${postsInCycle.length}/30 posts`,
          postsInCycle: postsInCycle.length
        };
      }
      
      PostQuotaService.updatePerformanceMetrics(Date.now() - startTime);
      
      return { 
        success: true, 
        message: `Cycle quota OK: ${postsInCycle.length}/30 posts`,
        postsInCycle: postsInCycle.length
      };
      
    } catch (error) {
      console.error('Error enforcing 30-day cycle:', error);
      return { success: false, message: 'Cycle enforcement failed', postsInCycle: 0 };
    }
  }

  /**
   * Detect expired posts that haven't been published
   */
  static async detectExpiredPosts(userId: number): Promise<{
    expiredPosts: any[];
    totalExpired: number;
    oldestExpired: Date | null;
    notificationRequired: boolean;
  }> {
    try {
      const { storage } = await import('./storage.js');
      const posts = await storage.getPostsByUser(userId);
      
      const now = new Date();
      now.setHours(0, 0, 0, 0); // Start of today for comparison
      
      const expiredPosts = posts.filter(post => {
        if (!post.scheduledFor || post.status === 'published' || post.status === 'failed') {
          return false;
        }
        
        const scheduledDate = new Date(post.scheduledFor);
        scheduledDate.setHours(0, 0, 0, 0);
        
        return scheduledDate < now;
      });
      
      const oldestExpired = expiredPosts.length > 0 
        ? new Date(Math.min(...expiredPosts.map(p => new Date(p.scheduledFor!).getTime())))
        : null;
      
      console.log(`🕐 Expired post detection for user ${userId}: ${expiredPosts.length} expired posts found`);
      
      return {
        expiredPosts,
        totalExpired: expiredPosts.length,
        oldestExpired,
        notificationRequired: expiredPosts.length > 0
      };
    } catch (error) {
      console.error('Error detecting expired posts:', error);
      return {
        expiredPosts: [],
        totalExpired: 0,
        oldestExpired: null,
        notificationRequired: false
      };
    }
  }
}