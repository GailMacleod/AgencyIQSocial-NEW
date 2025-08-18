/**
 * VEO 3.0 Usage Tracker
 * Prevents cost spiraling through comprehensive usage monitoring
 */

import { db } from '../db.ts';
import { videoUsage } from '../../shared/schema.js';
import { eq, and, gte, sql } from 'drizzle-orm';

class VeoUsageTracker {
  constructor() {
    // Cost protection limits
    this.limits = {
      monthlySeconds: 80,      // 10 videos @ 8 seconds each
      dailySeconds: 20,        // 2-3 videos per day max
      costPerSecond: 0.75,     // $0.75 per second from VEO pricing
      maxMonthlyCost: 60.00,   // $60 monthly budget
      maxDailyCost: 15.00      // $15 daily budget
    };
  }

  // Record VEO usage for cost tracking
  async recordUsage(userId, operationId, durationSeconds, costUsd) {
    try {
      const [usage] = await db.insert(videoUsage).values({
        userId: userId.toString(),
        operationId: operationId,
        durationSeconds: durationSeconds,
        costUsd: costUsd.toFixed(4)
      }).returning();

      console.log(`💰 VEO usage recorded: ${durationSeconds}s @ $${costUsd}`);
      return usage;
    } catch (error) {
      console.error('Failed to record VEO usage:', error);
      throw new Error('Usage tracking failed');
    }
  }

  // Get current usage statistics
  async getUsageStats(userId) {
    try {
      const now = new Date();
      const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
      const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());

      // Monthly usage
      const monthlyUsage = await db.select({
        totalSeconds: sql`COALESCE(SUM(${videoUsage.durationSeconds}), 0)`,
        totalCost: sql`COALESCE(SUM(${videoUsage.costUsd}), 0)`
      }).from(videoUsage).where(
        and(
          eq(videoUsage.userId, userId.toString()),
          gte(videoUsage.createdAt, startOfMonth)
        )
      );

      // Daily usage
      const dailyUsage = await db.select({
        totalSeconds: sql`COALESCE(SUM(${videoUsage.durationSeconds}), 0)`,
        totalCost: sql`COALESCE(SUM(${videoUsage.costUsd}), 0)`
      }).from(videoUsage).where(
        and(
          eq(videoUsage.userId, userId.toString()),
          gte(videoUsage.createdAt, startOfDay)
        )
      );

      return {
        monthly: {
          secondsUsed: parseInt(monthlyUsage[0].totalSeconds) || 0,
          costSpent: parseFloat(monthlyUsage[0].totalCost) || 0,
          limit: this.limits.monthlySeconds,
          budgetLimit: this.limits.maxMonthlyCost
        },
        daily: {
          secondsUsed: parseInt(dailyUsage[0].totalSeconds) || 0,
          costSpent: parseFloat(dailyUsage[0].totalCost) || 0,
          limit: this.limits.dailySeconds,
          budgetLimit: this.limits.maxDailyCost
        }
      };
    } catch (error) {
      console.error('Failed to get usage stats:', error);
      return {
        monthly: { secondsUsed: 0, costSpent: 0, limit: this.limits.monthlySeconds, budgetLimit: this.limits.maxMonthlyCost },
        daily: { secondsUsed: 0, costSpent: 0, limit: this.limits.dailySeconds, budgetLimit: this.limits.maxDailyCost }
      };
    }
  }

  // Check if user can generate video within limits
  async canGenerateVideo(userId, durationSeconds = 8) {
    try {
      const stats = await this.getUsageStats(userId);
      const estimatedCost = durationSeconds * this.limits.costPerSecond;

      // Check monthly limits
      const monthlySecondsAfter = stats.monthly.secondsUsed + durationSeconds;
      const monthlyCostAfter = stats.monthly.costSpent + estimatedCost;

      // Check daily limits  
      const dailySecondsAfter = stats.daily.secondsUsed + durationSeconds;
      const dailyCostAfter = stats.daily.costSpent + estimatedCost;

      const validation = {
        canGenerate: true,
        estimatedCost: estimatedCost,
        remainingMonthly: this.limits.monthlySeconds - stats.monthly.secondsUsed,
        remainingDaily: this.limits.dailySeconds - stats.daily.secondsUsed,
        warnings: []
      };

      // Monthly checks
      if (monthlySecondsAfter > this.limits.monthlySeconds) {
        validation.canGenerate = false;
        validation.warnings.push(`Monthly limit exceeded: ${monthlySecondsAfter}/${this.limits.monthlySeconds} seconds`);
      }

      if (monthlyCostAfter > this.limits.maxMonthlyCost) {
        validation.canGenerate = false;
        validation.warnings.push(`Monthly budget exceeded: $${monthlyCostAfter.toFixed(2)}/$${this.limits.maxMonthlyCost}`);
      }

      // Daily checks
      if (dailySecondsAfter > this.limits.dailySeconds) {
        validation.canGenerate = false;
        validation.warnings.push(`Daily limit exceeded: ${dailySecondsAfter}/${this.limits.dailySeconds} seconds`);
      }

      if (dailyCostAfter > this.limits.maxDailyCost) {
        validation.canGenerate = false;
        validation.warnings.push(`Daily budget exceeded: $${dailyCostAfter.toFixed(2)}/$${this.limits.maxDailyCost}`);
      }

      if (!validation.canGenerate) {
        throw new Error(validation.warnings.join(', '));
      }

      return validation;
    } catch (error) {
      throw new Error(`VEO quota validation failed: ${error.message}`);
    }
  }

  // Get user's detailed usage breakdown
  async getUserUsage(userId) {
    const stats = await this.getUsageStats(userId);
    
    return {
      monthlySeconds: stats.monthly.secondsUsed,
      monthlyLimit: this.limits.monthlySeconds,
      monthlyCost: stats.monthly.costSpent,
      monthlyBudget: this.limits.maxMonthlyCost,
      dailySeconds: stats.daily.secondsUsed,
      dailyLimit: this.limits.dailySeconds,
      dailyCost: stats.daily.costSpent,
      dailyBudget: this.limits.maxDailyCost,
      costPerSecond: this.limits.costPerSecond
    };
  }

  // Emergency shutdown check
  async isEmergencyShutdownRequired(userId) {
    const stats = await this.getUsageStats(userId);
    
    // Emergency if over 150% of limits or budget
    const emergencyMonthly = stats.monthly.secondsUsed > (this.limits.monthlySeconds * 1.5) ||
                            stats.monthly.costSpent > (this.limits.maxMonthlyCost * 1.5);
                            
    const emergencyDaily = stats.daily.secondsUsed > (this.limits.dailySeconds * 1.5) ||
                          stats.daily.costSpent > (this.limits.maxDailyCost * 1.5);

    return emergencyMonthly || emergencyDaily;
  }
}

export { VeoUsageTracker };