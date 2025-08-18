import type { Express } from 'express';
import { QuotaTracker } from '../services/QuotaTracker';

export function registerQuotaRoutes(app: Express) {
  // Get quota status for a user
  app.get('/api/quota-status', async (req: any, res) => {
    try {
      const userId = req.session?.userId;
      if (!userId) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const quotaTracker = QuotaTracker.getInstance();
      const platforms = ['facebook', 'instagram', 'linkedin', 'twitter', 'youtube'];
      
      const quotaStatus: any = {};
      
      for (const platform of platforms) {
        const usage = await quotaTracker.getQuotaUsage(userId, platform);
        quotaStatus[platform] = {
          posts: {
            current: usage.posts,
            limit: usage.limits.posts,
            remaining: Math.max(0, usage.limits.posts - usage.posts),
            percentage: Math.round((usage.posts / usage.limits.posts) * 100)
          },
          api_calls: {
            current: usage.api_calls,
            limit: usage.limits.api_calls,
            remaining: Math.max(0, usage.limits.api_calls - usage.api_calls),
            percentage: Math.round((usage.api_calls / usage.limits.api_calls) * 100)
          }
        };
      }
      
      // Calculate overall status
      const totalPosts = Object.values(quotaStatus).reduce((sum: number, platform: any) => sum + platform.posts.current, 0);
      const totalPostLimit = Object.values(quotaStatus).reduce((sum: number, platform: any) => sum + platform.posts.limit, 0);
      const totalAPICalls = Object.values(quotaStatus).reduce((sum: number, platform: any) => sum + platform.api_calls.current, 0);
      const totalAPILimit = Object.values(quotaStatus).reduce((sum: number, platform: any) => sum + platform.api_calls.limit, 0);
      
      res.json({
        userId,
        timestamp: new Date().toISOString(),
        hourly_window: true,
        overall: {
          posts: {
            current: totalPosts,
            limit: totalPostLimit,
            percentage: Math.round((totalPosts / totalPostLimit) * 100)
          },
          api_calls: {
            current: totalAPICalls,
            limit: totalAPILimit,
            percentage: Math.round((totalAPICalls / totalAPILimit) * 100)
          }
        },
        platforms: quotaStatus,
        warnings: generateQuotaWarnings(quotaStatus)
      });
      
    } catch (error) {
      console.error('Error getting quota status:', error);
      res.status(500).json({ error: 'Failed to get quota status' });
    }
  });

  // Reset quota for development/testing
  app.post('/api/quota-reset', async (req: any, res) => {
    try {
      if (process.env.NODE_ENV !== 'development') {
        return res.status(403).json({ error: 'Quota reset only allowed in development' });
      }

      const userId = req.session?.userId;
      const { platform } = req.body;

      if (!userId) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const quotaTracker = QuotaTracker.getInstance();
      await quotaTracker.resetQuota(userId, platform);

      res.json({
        success: true,
        message: `Quota reset for user ${userId}${platform ? ` on ${platform}` : ' (all platforms)'}`,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Error resetting quota:', error);
      res.status(500).json({ error: 'Failed to reset quota' });
    }
  });
}

function generateQuotaWarnings(quotaStatus: any): string[] {
  const warnings: string[] = [];
  
  Object.entries(quotaStatus).forEach(([platform, status]: [string, any]) => {
    if (status.posts.percentage >= 90) {
      warnings.push(`${platform} posting quota is ${status.posts.percentage}% full`);
    }
    if (status.api_calls.percentage >= 80) {
      warnings.push(`${platform} API quota is ${status.api_calls.percentage}% full`);
    }
  });
  
  return warnings;
}