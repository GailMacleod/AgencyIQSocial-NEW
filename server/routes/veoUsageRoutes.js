/**
 * VEO 3.0 Usage Monitoring Routes
 * Provides cost monitoring and quota management endpoints
 */

import { VeoUsageTracker } from '../services/VeoUsageTracker.js';
// import { requireAuth } from '../middleware/subscriptionAuth.js';

export default function registerVeoUsageRoutes(app) {
  const veoTracker = new VeoUsageTracker();

  // Get current VEO usage statistics
  app.get('/api/veo/usage', async (req, res) => {
    try {
      const userId = req.session.userId;
      const stats = await veoTracker.getUsageStats(userId);
      
      res.json({
        success: true,
        usage: stats,
        costPerSecond: 0.75,
        limits: {
          monthly: 80, // seconds
          daily: 20    // seconds
        }
      });
    } catch (error) {
      console.error('VEO usage stats error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to fetch VEO usage statistics'
      });
    }
  });

  // Check if user can generate video  
  app.get('/api/veo/can-generate', async (req, res) => {
    try {
      const userId = req.session.userId;
      const duration = parseInt(req.query.duration) || 8;
      
      const validation = await veoTracker.canGenerateVideo(userId, duration);
      
      res.json({
        success: true,
        canGenerate: validation.canGenerate,
        estimatedCost: validation.estimatedCost,
        remaining: {
          monthly: validation.remainingMonthly,
          daily: validation.remainingDaily
        }
      });
    } catch (error) {
      res.status(429).json({
        success: false,
        canGenerate: false,
        error: error.message
      });
    }
  });

  // Get VEO cost analysis dashboard
  app.get('/api/veo/cost-dashboard', async (req, res) => {
    try {
      const userId = req.session.userId;
      const usage = await veoTracker.getUserUsage(userId);
      
      const dashboard = {
        currentMonth: {
          videosGenerated: Math.floor(usage.monthlySeconds / 8),
          secondsUsed: usage.monthlySeconds,
          totalCost: usage.monthlyCost,
          limit: usage.monthlyLimit,
          remaining: usage.monthlyLimit - usage.monthlySeconds
        },
        today: {
          videosGenerated: Math.floor(usage.dailySeconds / 8),
          secondsUsed: usage.dailySeconds,
          totalCost: usage.dailyCost,
          limit: usage.dailyLimit,
          remaining: usage.dailyLimit - usage.dailySeconds
        },
        pricing: {
          perSecond: 0.75,
          per8SecondVideo: 6.00,
          monthlyBudget: 60.00
        },
        warnings: []
      };

      // Add warnings for high usage
      if (usage.monthlySeconds > usage.monthlyLimit * 0.8) {
        dashboard.warnings.push('Monthly VEO limit 80% exceeded');
      }
      if (usage.dailySeconds > usage.dailyLimit * 0.9) {
        dashboard.warnings.push('Daily VEO limit 90% exceeded');
      }

      res.json({
        success: true,
        dashboard
      });
    } catch (error) {
      console.error('VEO cost dashboard error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to generate cost dashboard'
      });
    }
  });
}