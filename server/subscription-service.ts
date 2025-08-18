import { db } from './db';
import { users, subscriptionAnalytics, posts } from '@shared/schema';
import { eq, and, gte, lte, desc, sql } from 'drizzle-orm';

export interface SubscriptionPlan {
  name: string;
  postsPerMonth: number;
  freeBonus: number;
  price: number; // Monthly price in USD
}

export const SUBSCRIPTION_PLANS: Record<string, SubscriptionPlan> = {
  starter: {
    name: 'Starter',
    postsPerMonth: 10,
    freeBonus: 0,
    price: 19.99
  },
  growth: {
    name: 'Growth', 
    postsPerMonth: 20,
    freeBonus: 0,
    price: 41.99
  },
  professional: {
    name: 'Professional',
    postsPerMonth: 30,
    freeBonus: 0,
    price: 99.99
  }
};

export class SubscriptionService {
  
  // Get current subscription cycle for user
  static getCurrentCycle(subscriptionStart: Date): { cycleStart: Date; cycleEnd: Date; cycleName: string } {
    const now = new Date();
    const start = new Date(subscriptionStart);
    
    // Calculate months since subscription start
    const monthsDiff = (now.getFullYear() - start.getFullYear()) * 12 + (now.getMonth() - start.getMonth());
    
    // Current cycle start is subscription start + monthsDiff months
    const cycleStart = new Date(start.getFullYear(), start.getMonth() + monthsDiff, start.getDate());
    const cycleEnd = new Date(start.getFullYear(), start.getMonth() + monthsDiff + 1, start.getDate() - 1);
    
    // Ensure cycle end is not beyond current time for active cycles
    if (cycleEnd > now) {
      cycleEnd.setTime(now.getTime());
    }
    
    const cycleName = `${cycleStart.getFullYear()}-${String(cycleStart.getMonth() + 1).padStart(2, '0')}-${String(cycleStart.getDate()).padStart(2, '0')}`;
    
    return { cycleStart, cycleEnd, cycleName };
  }
  
  // Initialize subscription analytics for new cycle
  static async initializeSubscriptionCycle(userId: number, subscriptionPlan: string, subscriptionStart: Date) {
    const plan = SUBSCRIPTION_PLANS[subscriptionPlan];
    if (!plan) throw new Error('Invalid subscription plan');
    
    const { cycleStart, cycleEnd, cycleName } = this.getCurrentCycle(subscriptionStart);
    const totalAllowed = plan.postsPerMonth; // Strict plan enforcement: no free bonus
    
    // Check if analytics already exist for this cycle
    const [existing] = await db
      .select()
      .from(subscriptionAnalytics)
      .where(and(
        eq(subscriptionAnalytics.userId, userId),
        eq(subscriptionAnalytics.subscriptionCycle, cycleName)
      ));
    
    if (existing) return existing;
    
    // Create new cycle analytics
    const dataRetentionExpiry = new Date(cycleEnd);
    dataRetentionExpiry.setMonth(dataRetentionExpiry.getMonth() + 3); // 3 months retention
    
    const [analytics] = await db
      .insert(subscriptionAnalytics)
      .values({
        userId,
        subscriptionCycle: cycleName,
        subscriptionPlan,
        totalPostsAllowed: totalAllowed,
        cycleStartDate: cycleStart,
        cycleEndDate: cycleEnd,
        dataRetentionExpiry
      })
      .returning();
    
    return analytics;
  }
  
  // Get current subscription status and limits
  static async getSubscriptionStatus(userId: number) {
    const [user] = await db.select().from(users).where(eq(users.id, userId));
    if (!user || !user.subscriptionStart || !user.subscriptionPlan) {
      throw new Error('No active subscription found');
    }
    
    const { cycleName } = this.getCurrentCycle(user.subscriptionStart);
    
    // Get or create current cycle analytics
    let analytics = await this.initializeSubscriptionCycle(userId, user.subscriptionPlan, user.subscriptionStart);
    
    // Count actual posts used in current cycle
    const postsInCycle = await db
      .select()
      .from(posts)
      .where(and(
        eq(posts.userId, userId),
        eq(posts.subscriptionCycle, cycleName),
        eq(posts.status, 'published')
      ));
    
    const postsUsed = postsInCycle.length;
    const postsRemaining = analytics.totalPostsAllowed - postsUsed;
    
    return {
      ...analytics,
      postsUsed,
      postsRemaining,
      plan: SUBSCRIPTION_PLANS[user.subscriptionPlan],
      cycleInfo: this.getCurrentCycle(user.subscriptionStart)
    };
  }
  
  // Check if user can create more posts
  static async canCreatePost(userId: number): Promise<{ allowed: boolean; reason?: string }> {
    try {
      const status = await this.getSubscriptionStatus(userId);
      
      if (status.postsRemaining <= 0) {
        return {
          allowed: false,
          reason: `You've used all ${status.totalPostsAllowed} posts for this billing cycle. Upgrade your plan or wait for next cycle.`
        };
      }
      
      return { allowed: true };
    } catch (error) {
      return {
        allowed: false,
        reason: 'No active subscription found. Please subscribe to continue.'
      };
    }
  }
  
  // Track successful post publication
  static async trackSuccessfulPost(userId: number, postId: number, analytics: any) {
    const [user] = await db.select().from(users).where(eq(users.id, userId));
    if (!user || !user.subscriptionStart) return;
    
    const { cycleName } = this.getCurrentCycle(user.subscriptionStart);
    
    // Update post with subscription cycle
    await db
      .update(posts)
      .set({ 
        subscriptionCycle: cycleName,
        analytics: analytics
      })
      .where(eq(posts.id, postId));
    
    // Update subscription analytics
    const reach = analytics?.reach || 0;
    const engagement = analytics?.engagement || 0;
    const impressions = analytics?.impressions || 0;
    
    await db
      .update(subscriptionAnalytics)
      .set({
        successfulPosts: sql`${subscriptionAnalytics.successfulPosts} + 1`,
        totalReach: sql`${subscriptionAnalytics.totalReach} + ${reach}`,
        totalEngagement: sql`${subscriptionAnalytics.totalEngagement} + ${engagement}`,
        totalImpressions: sql`${subscriptionAnalytics.totalImpressions} + ${impressions}`
      })
      .where(and(
        eq(subscriptionAnalytics.userId, userId),
        eq(subscriptionAnalytics.subscriptionCycle, cycleName)
      ));
  }
  
  // Generate analytics report for download
  static async generateAnalyticsReport(userId: number, cycleId?: string) {
    let analytics;
    
    if (cycleId) {
      // Specific cycle
      [analytics] = await db
        .select()
        .from(subscriptionAnalytics)
        .where(and(
          eq(subscriptionAnalytics.userId, userId),
          eq(subscriptionAnalytics.subscriptionCycle, cycleId)
        ));
    } else {
      // Current cycle
      const [user] = await db.select().from(users).where(eq(users.id, userId));
      if (!user?.subscriptionStart) throw new Error('No subscription found');
      
      const { cycleName } = this.getCurrentCycle(user.subscriptionStart);
      [analytics] = await db
        .select()
        .from(subscriptionAnalytics)
        .where(and(
          eq(subscriptionAnalytics.userId, userId),
          eq(subscriptionAnalytics.subscriptionCycle, cycleName)
        ));
    }
    
    if (!analytics) throw new Error('Analytics not found for specified cycle');
    
    // Get detailed post data for the cycle
    const cyclePosts = await db
      .select()
      .from(posts)
      .where(and(
        eq(posts.userId, userId),
        eq(posts.subscriptionCycle, analytics.subscriptionCycle),
        eq(posts.status, 'published')
      ));
    
    return {
      cycle: analytics,
      posts: cyclePosts,
      summary: {
        totalPosts: cyclePosts.length,
        averageReach: (analytics.successfulPosts || 0) > 0 ? Math.round((analytics.totalReach || 0) / (analytics.successfulPosts || 1)) : 0,
        averageEngagement: (analytics.successfulPosts || 0) > 0 ? Math.round((analytics.totalEngagement || 0) / (analytics.successfulPosts || 1)) : 0,
        platformBreakdown: cyclePosts.reduce((acc, post) => {
          acc[post.platform] = (acc[post.platform] || 0) + 1;
          return acc;
        }, {} as Record<string, number>)
      }
    };
  }
  
  // Clean up expired analytics (older than 3 months)
  static async cleanupExpiredAnalytics() {
    const now = new Date();
    
    await db
      .delete(subscriptionAnalytics)
      .where(lte(subscriptionAnalytics.dataRetentionExpiry, now));
  }
  
  // Get available analytics for download (within 3 month retention)
  static async getAvailableAnalytics(userId: number) {
    const now = new Date();
    
    const availableAnalytics = await db
      .select()
      .from(subscriptionAnalytics)
      .where(and(
        eq(subscriptionAnalytics.userId, userId),
        gte(subscriptionAnalytics.dataRetentionExpiry, now)
      ))
      .orderBy(desc(subscriptionAnalytics.cycleStartDate));
    
    return availableAnalytics;
  }
}