// Enhanced OAuth Routes with Passport.js Integration
// Comprehensive OAuth handling for all social media platforms

import { Router } from 'express';
import passport from 'passport';
import { passportOAuthManager } from '../services/PassportOAuthManager';
import { requireAuth } from '../middleware/auth-validation';
import { logSecurityEvent } from '../middleware/enhanced-security';

const router = Router();

// OAuth initiation routes
router.get('/auth/facebook', 
  logSecurityEvent('OAUTH_INITIATE'),
  passport.authenticate('facebook', { 
    scope: ['pages_manage_posts', 'pages_read_engagement', 'pages_show_list'] 
  })
);

router.get('/auth/google', 
  logSecurityEvent('OAUTH_INITIATE'),
  passport.authenticate('google', { 
    scope: ['https://www.googleapis.com/auth/youtube.upload'] 
  })
);

router.get('/auth/linkedin', 
  logSecurityEvent('OAUTH_INITIATE'),
  passport.authenticate('linkedin', { 
    scope: ['w_member_social', 'r_organization_social'] 
  })
);

router.get('/auth/twitter', 
  logSecurityEvent('OAUTH_INITIATE'),
  passport.authenticate('twitter')
);

// OAuth callback routes
router.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/auth/failure' }),
  (req, res) => {
    res.redirect('/dashboard?connected=facebook');
  }
);

router.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth/failure' }),
  (req, res) => {
    res.redirect('/dashboard?connected=google');
  }
);

router.get('/auth/linkedin/callback',
  passport.authenticate('linkedin', { failureRedirect: '/auth/failure' }),
  (req, res) => {
    res.redirect('/dashboard?connected=linkedin');
  }
);

router.get('/auth/twitter/callback',
  passport.authenticate('twitter', { failureRedirect: '/auth/failure' }),
  (req, res) => {
    res.redirect('/dashboard?connected=twitter');
  }
);

// OAuth management API routes
router.get('/api/oauth/status', requireAuth, async (req, res) => {
  try {
    const userId = req.user!.id;
    
    const platforms = ['facebook', 'google', 'linkedin', 'twitter'];
    const status = {};
    
    for (const platform of platforms) {
      const isValid = await passportOAuthManager.validateToken(userId, platform);
      status[platform] = {
        connected: isValid,
        platform
      };
    }
    
    res.json({
      success: true,
      platforms: status
    });
  } catch (error) {
    console.error('OAuth status check failed:', error);
    res.status(500).json({
      error: 'Failed to check OAuth status',
      code: 'OAUTH_STATUS_ERROR'
    });
  }
});

router.post('/api/oauth/refresh/:platform', requireAuth, async (req, res) => {
  try {
    const { platform } = req.params;
    const userId = req.user!.id;
    
    const newToken = await passportOAuthManager.refreshToken(userId, platform);
    
    if (newToken) {
      res.json({
        success: true,
        message: `${platform} token refreshed successfully`
      });
    } else {
      res.status(400).json({
        error: `Failed to refresh ${platform} token`,
        code: 'REFRESH_FAILED'
      });
    }
  } catch (error) {
    console.error('Token refresh failed:', error);
    res.status(500).json({
      error: 'Token refresh failed',
      code: 'REFRESH_ERROR'
    });
  }
});

router.delete('/api/oauth/disconnect/:platform', requireAuth, async (req, res) => {
  try {
    const { platform } = req.params;
    const userId = req.user!.id;
    
    const revoked = await passportOAuthManager.revokeToken(userId, platform);
    
    if (revoked) {
      res.json({
        success: true,
        message: `${platform} disconnected successfully`
      });
    } else {
      res.status(400).json({
        error: `Failed to disconnect ${platform}`,
        code: 'DISCONNECT_FAILED'
      });
    }
  } catch (error) {
    console.error('Token revocation failed:', error);
    res.status(500).json({
      error: 'Disconnect failed',
      code: 'DISCONNECT_ERROR'
    });
  }
});

// OAuth failure route
router.get('/auth/failure', (req, res) => {
  res.redirect('/dashboard?error=oauth_failed');
});

export default router;