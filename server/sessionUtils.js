/**
 * Session Utilities for VEO 3.0 Integration
 * Handles secure session management, token validation, and auto-posting integration
 */

class SessionManager {
  constructor() {
    this.sessionCookieName = process.env.SESSION_COOKIE_NAME || 'theagencyiq.session';
  }

  /**
   * Extract session cookie from request headers
   */
  extractSessionCookie(req) {
    try {
      // Check for session in cookies first
      if (req.cookies && req.cookies[this.sessionCookieName]) {
        return req.cookies[this.sessionCookieName];
      }

      // Check for session in headers
      const cookieHeader = req.headers.cookie;
      if (cookieHeader) {
        const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
          const [name, value] = cookie.trim().split('=');
          acc[name] = value;
          return acc;
        }, {});
        
        return cookies[this.sessionCookieName];
      }

      return null;
    } catch (error) {
      console.error('❌ Session extraction failed:', error.message);
      return null;
    }
  }

  /**
   * Validate session and handle 401 responses
   */
  async validateSession(req, res, next) {
    try {
      const sessionCookie = this.extractSessionCookie(req);
      
      if (!sessionCookie) {
        return res.status(401).json({
          error: 'Session required',
          redirectTo: '/login',
          message: 'Please log in to continue'
        });
      }

      // Check if session is valid with backend
      if (req.session && req.session.userId) {
        req.validatedSession = {
          userId: req.session.userId,
          userEmail: req.session.userEmail
        };
        return next();
      }

      // Session invalid - require re-authentication
      return res.status(401).json({
        error: 'Session expired',
        redirectTo: '/login',
        message: 'Your session has expired. Please log in again.'
      });

    } catch (error) {
      console.error('❌ Session validation failed:', error.message);
      return res.status(401).json({
        error: 'Session validation failed',
        redirectTo: '/login',
        message: 'Authentication error. Please log in again.'
      });
    }
  }

  /**
   * Refresh OAuth tokens if needed
   */
  async refreshTokensIfNeeded(userId) {
    try {
      const { storage } = await import('./storage');
      
      // Check if tokens need refresh (within 24 hours of expiry)
      const platformConnections = await storage.getPlatformConnections(userId);
      const refreshedTokens = {};

      for (const [platform, connection] of Object.entries(platformConnections)) {
        if (connection.refreshToken && this.isTokenNearExpiry(connection.expiresAt)) {
          console.log(`🔄 Refreshing ${platform} token for user ${userId}`);
          
          try {
            const refreshedConnection = await this.refreshPlatformToken(platform, connection);
            if (refreshedConnection) {
              await storage.updatePlatformConnection(userId, platform, refreshedConnection);
              refreshedTokens[platform] = refreshedConnection;
            }
          } catch (refreshError) {
            console.error(`❌ Failed to refresh ${platform} token:`, refreshError.message);
          }
        }
      }

      return refreshedTokens;
    } catch (error) {
      console.error('❌ Token refresh failed:', error.message);
      return {};
    }
  }

  /**
   * Check if token expires within 24 hours
   */
  isTokenNearExpiry(expiresAt) {
    if (!expiresAt) return false;
    const expiryTime = new Date(expiresAt);
    const now = new Date();
    const twentyFourHours = 24 * 60 * 60 * 1000;
    
    return (expiryTime.getTime() - now.getTime()) < twentyFourHours;
  }

  /**
   * Refresh platform-specific tokens
   */
  async refreshPlatformToken(platform, connection) {
    // Implementation would depend on platform OAuth specs
    // This is a placeholder for the actual refresh logic
    console.log(`🔄 Refreshing ${platform} token...`);
    return null; // Would return refreshed connection data
  }

  /**
   * Auto-posting integration after video generation
   */
  async triggerAutoPosting(videoUri, platform, userId, postContent) {
    try {
      console.log(`🚀 Triggering auto-posting for ${platform} - User ${userId}`);
      
      // Import PostingQueue service
      const { PostingQueue } = await import('./PostingQueue');
      const postingQueue = new PostingQueue();

      // Create post data for auto-posting
      const postData = {
        userId: userId,
        platform: platform,
        content: postContent,
        videoUri: videoUri,
        scheduledFor: new Date(), // Immediate posting
        status: 'queued'
      };

      // Add to posting queue with platform-specific delays
      const queueResult = await postingQueue.addPost(postData);
      
      console.log(`✅ Post added to queue: ${queueResult.queueId}`);
      return {
        success: true,
        queueId: queueResult.queueId,
        platform: platform,
        scheduledFor: postData.scheduledFor
      };

    } catch (error) {
      console.error(`❌ Auto-posting failed for ${platform}:`, error.message);
      return {
        success: false,
        error: error.message,
        platform: platform
      };
    }
  }

  /**
   * Handle customer onboarding with session validation
   */
  async validateOnboardingSession(req, res, next) {
    try {
      // Extract user ID from validated session
      const userId = req.validatedSession?.userId;
      
      if (!userId) {
        return res.status(401).json({
          error: 'User session required for onboarding',
          redirectTo: '/login',
          step: 'authentication'
        });
      }

      // Refresh tokens if needed for onboarding
      await this.refreshTokensIfNeeded(userId);
      
      req.onboardingUserId = userId;
      next();

    } catch (error) {
      console.error('❌ Onboarding session validation failed:', error.message);
      return res.status(401).json({
        error: 'Onboarding session validation failed',
        redirectTo: '/login',
        step: 'authentication',
        details: error.message
      });
    }
  }
}

// Export singleton instance
const sessionManager = new SessionManager();

export default sessionManager;
export { SessionManager };