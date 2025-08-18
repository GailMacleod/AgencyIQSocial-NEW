/**
 * VEO 3.0 Cost Protection Middleware
 * Prevents API cost spiraling through pre-generation validation
 */

import { VeoUsageTracker } from '../services/VeoUsageTracker.js';

const veoTracker = new VeoUsageTracker();

// VEO cost protection middleware
export const veoProtection = async (req, res, next) => {
  try {
    const userId = req.session?.userId;
    
    if (!userId) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required for VEO generation'
      });
    }

    // Check if user can generate video within cost limits
    const duration = req.body.durationSeconds || 8; // Default 8 seconds
    
    console.log(`🔍 VEO protection check for user ${userId}: ${duration}s video`);
    
    const validation = await veoTracker.canGenerateVideo(userId, duration);
    
    if (!validation.canGenerate) {
      console.log(`❌ VEO protection: Generation blocked for user ${userId}:`, validation.warnings);
      return res.status(429).json({
        success: false,
        error: 'VEO usage limit exceeded',
        details: validation.warnings.join(', '),
        limits: {
          monthlyRemaining: validation.remainingMonthly,
          dailyRemaining: validation.remainingDaily,
          estimatedCost: validation.estimatedCost
        }
      });
    }

    console.log(`✅ VEO protection: Generation approved for user ${userId} ($${validation.estimatedCost})`);
    
    // Add usage info to request for potential logging
    req.veoUsage = {
      estimatedCost: validation.estimatedCost,
      remainingMonthly: validation.remainingMonthly,
      remainingDaily: validation.remainingDaily
    };
    
    next();
  } catch (error) {
    console.error('VEO protection middleware error:', error);
    
    // Emergency shutdown check
    try {
      const emergencyShutdown = await veoTracker.isEmergencyShutdownRequired(req.session?.userId);
      if (emergencyShutdown) {
        console.error('🚨 EMERGENCY: VEO cost limits severely exceeded');
        return res.status(503).json({
          success: false,
          error: 'VEO service temporarily suspended due to cost protection',
          emergency: true
        });
      }
    } catch (emergencyError) {
      console.error('Emergency shutdown check failed:', emergencyError);
    }
    
    // Allow generation but log error
    console.warn('⚠️ VEO protection check failed, allowing generation:', error.message);
    next();
  }
};

export default veoProtection;