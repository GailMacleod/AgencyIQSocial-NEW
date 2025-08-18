/**
 * OAuth Routes with Passport.js Integration
 * Complete OAuth flow for all social media platforms
 */

import express from 'express';
import passport from 'passport';
import OAuthTokenManager from './tokenManager.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();
const tokenManager = new OAuthTokenManager();

/**
 * Twitter OAuth Routes
 */
router.get('/auth/twitter', 
  passport.authenticate('twitter', { 
    scope: ['read', 'write'] 
  })
);

router.get('/auth/twitter/callback',
  passport.authenticate('twitter', { 
    failureRedirect: '/oauth/error?platform=twitter',
    failureMessage: true 
  }),
  async (req, res) => {
    try {
      console.log('🐦 Twitter OAuth callback successful');
      res.redirect('/platform-connect?success=twitter');
    } catch (error) {
      console.error('❌ Twitter OAuth callback error:', error);
      res.redirect('/oauth/error?platform=twitter&error=' + encodeURIComponent(error.message));
    }
  }
);

/**
 * Facebook OAuth Routes
 */
router.get('/auth/facebook',
  passport.authenticate('facebook', { 
    scope: [
      'email',
      'public_profile',
      'pages_manage_posts',
      'pages_read_engagement',
      'publish_to_groups',
      'instagram_basic',
      'instagram_content_publish'
    ]
  })
);

router.get('/auth/facebook/callback',
  passport.authenticate('facebook', { 
    failureRedirect: '/oauth/error?platform=facebook',
    failureMessage: true 
  }),
  async (req, res) => {
    try {
      console.log('📘 Facebook OAuth callback successful');
      res.redirect('/platform-connect?success=facebook');
    } catch (error) {
      console.error('❌ Facebook OAuth callback error:', error);
      res.redirect('/oauth/error?platform=facebook&error=' + encodeURIComponent(error.message));
    }
  }
);

/**
 * Google/YouTube OAuth Routes
 */
router.get('/auth/google',
  passport.authenticate('google', { 
    scope: [
      'profile',
      'email',
      'https://www.googleapis.com/auth/youtube.upload',
      'https://www.googleapis.com/auth/youtube',
      'https://www.googleapis.com/auth/youtube.force-ssl'
    ],
    accessType: 'offline',
    prompt: 'consent'
  })
);

router.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/oauth/error?platform=google',
    failureMessage: true 
  }),
  async (req, res) => {
    try {
      console.log('🔴 Google OAuth callback successful');
      res.redirect('/platform-connect?success=google');
    } catch (error) {
      console.error('❌ Google OAuth callback error:', error);
      res.redirect('/oauth/error?platform=google&error=' + encodeURIComponent(error.message));
    }
  }
);

/**
 * LinkedIn OAuth Routes
 */
router.get('/auth/linkedin',
  passport.authenticate('linkedin', { 
    scope: [
      'r_liteprofile',
      'r_emailaddress',
      'w_member_social'
    ]
  })
);

router.get('/auth/linkedin/callback',
  passport.authenticate('linkedin', { 
    failureRedirect: '/oauth/error?platform=linkedin',
    failureMessage: true 
  }),
  async (req, res) => {
    try {
      console.log('💼 LinkedIn OAuth callback successful');
      res.redirect('/platform-connect?success=linkedin');
    } catch (error) {
      console.error('❌ LinkedIn OAuth callback error:', error);
      res.redirect('/oauth/error?platform=linkedin&error=' + encodeURIComponent(error.message));
    }
  }
);

/**
 * Token Refresh Endpoint
 * Handles automatic token refresh on 401 errors
 */
router.post('/api/oauth/refresh', requireAuth, async (req, res) => {
  try {
    const { platform } = req.body;
    
    if (!platform) {
      return res.status(400).json({
        success: false,
        message: 'Platform parameter required',
        code: 'MISSING_PLATFORM'
      });
    }

    console.log(`🔄 Manual token refresh requested for user ${req.userId}, platform ${platform}`);

    const refreshedToken = await tokenManager.getValidToken(req.userId, platform);
    
    res.json({
      success: true,
      message: 'Token refreshed successfully',
      platform,
      expiresAt: refreshedToken.expiresAt,
      scopes: refreshedToken.scopes
    });

  } catch (error) {
    console.error('❌ Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'Token refresh failed',
      error: error.message,
      code: 'REFRESH_FAILED'
    });
  }
});

/**
 * Token Validation Endpoint
 * Checks if user has valid tokens with required scopes
 */
router.post('/api/oauth/validate', requireAuth, async (req, res) => {
  try {
    const { platform, requiredScopes = [] } = req.body;
    
    if (!platform) {
      return res.status(400).json({
        success: false,
        message: 'Platform parameter required',
        code: 'MISSING_PLATFORM'
      });
    }

    console.log(`🔍 Token validation for user ${req.userId}, platform ${platform}`);

    const validation = await tokenManager.validateTokenScopes(req.userId, platform, requiredScopes);
    
    if (validation.valid) {
      res.json({
        success: true,
        message: 'Token valid',
        platform,
        scopes: validation.scopes
      });
    } else {
      res.status(403).json({
        success: false,
        message: 'Token invalid or insufficient scopes',
        platform,
        missingScopes: validation.missingScopes,
        currentScopes: validation.currentScopes,
        error: validation.error,
        code: 'INVALID_TOKEN'
      });
    }

  } catch (error) {
    console.error('❌ Token validation error:', error);
    res.status(500).json({
      success: false,
      message: 'Token validation failed',
      error: error.message,
      code: 'VALIDATION_FAILED'
    });
  }
});

/**
 * Disconnect Platform Endpoint
 * Revokes OAuth tokens and removes platform connection
 */
router.delete('/api/oauth/disconnect', requireAuth, async (req, res) => {
  try {
    const { platform } = req.body;
    
    if (!platform) {
      return res.status(400).json({
        success: false,
        message: 'Platform parameter required',
        code: 'MISSING_PLATFORM'
      });
    }

    console.log(`🗑️ Disconnecting platform ${platform} for user ${req.userId}`);

    await tokenManager.revokeToken(req.userId, platform);
    
    res.json({
      success: true,
      message: `${platform} disconnected successfully`,
      platform
    });

  } catch (error) {
    console.error('❌ Platform disconnect error:', error);
    res.status(500).json({
      success: false,
      message: 'Platform disconnect failed',
      error: error.message,
      code: 'DISCONNECT_FAILED'
    });
  }
});

/**
 * OAuth Error Page
 * Handles OAuth authentication failures
 */
router.get('/oauth/error', (req, res) => {
  const { platform, error } = req.query;
  
  console.error(`❌ OAuth error for platform ${platform}:`, error);
  
  // In production, this would render an error page
  // For now, redirect back to platform connections with error
  res.redirect(`/platform-connect?error=${platform}&message=${encodeURIComponent(error || 'Authentication failed')}`);
});

/**
 * Get Available Platforms
 * Returns list of configured OAuth platforms
 */
router.get('/api/oauth/platforms', (req, res) => {
  const platforms = [];
  
  if (process.env.TWITTER_CONSUMER_KEY) {
    platforms.push({
      platform: 'twitter',
      name: 'X (Twitter)',
      scopes: ['read', 'write'],
      authUrl: '/auth/twitter'
    });
  }
  
  if (process.env.FACEBOOK_APP_ID) {
    platforms.push({
      platform: 'facebook',
      name: 'Facebook',
      scopes: ['pages_manage_posts', 'publish_to_groups'],
      authUrl: '/auth/facebook'
    });
  }
  
  if (process.env.GOOGLE_CLIENT_ID) {
    platforms.push({
      platform: 'google',
      name: 'YouTube',
      scopes: ['youtube.upload', 'youtube'],
      authUrl: '/auth/google'
    });
  }
  
  if (process.env.LINKEDIN_CLIENT_ID) {
    platforms.push({
      platform: 'linkedin',
      name: 'LinkedIn',
      scopes: ['w_member_social'],
      authUrl: '/auth/linkedin'
    });
  }
  
  res.json({
    success: true,
    platforms,
    totalPlatforms: platforms.length
  });
});

export default router;