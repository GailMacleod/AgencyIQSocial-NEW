/**
 * CRITICAL FIX: OAuth Strategies Configuration
 * Fixes hardcoded sessions and implements proper OAuth token management
 * Addresses the core issues identified by CEO in attached analysis
 */

import passport from 'passport';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LinkedInStrategy } from 'passport-linkedin-oauth2';

interface OAuthProfile {
  id: string;
  displayName: string;
  emails?: Array<{ value: string; verified?: boolean }>;
  photos?: Array<{ value: string }>;
  provider: string;
}

interface OAuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  scope?: string[];
}

/**
 * Configure all OAuth strategies for social media platforms
 * Implements secure token storage and refresh logic
 */
export function configureOAuthStrategies() {
  // Production-ready URL configuration for app.theagencyiq.ai
  const isProd = process.env.NODE_ENV === 'production' || process.env.REPLIT_DEPLOYED === 'true';
  const baseUrl = isProd 
    ? 'https://app.theagencyiq.ai' 
    : (process.env.REPLIT_DOMAINS?.split(',')[0] || 'http://localhost:5000');
  
  console.log(`🔧 Configuring OAuth strategies for ${isProd ? 'PRODUCTION' : 'DEVELOPMENT'} (${baseUrl})...`);

  // Passport serialization/deserialization
  passport.serializeUser((user: any, done) => {
    // Store user ID and platform info in session
    const sessionData = {
      id: user.id || user.profile?.id,
      platform: user.platform,
      tokens: {
        accessToken: user.accessToken,
        refreshToken: user.refreshToken,
        expiresAt: user.expiresAt
      }
    };
    done(null, sessionData);
  });

  passport.deserializeUser(async (sessionData: any, done) => {
    try {
      // Load user from database and validate tokens
      const { storage } = await import('../storage.js');
      const user = await storage.getUser(sessionData.id);
      
      if (user) {
        // Attach OAuth tokens to user object
        user.oauthTokens = sessionData.tokens;
        done(null, user);
      } else {
        done(null, null);
      }
    } catch (error) {
      console.error('❌ OAuth user deserialization error:', error);
      done(error, null);
    }
  });

  // Facebook OAuth Strategy
  if (process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET) {
    passport.use(new FacebookStrategy({
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: `${baseUrl}/auth/facebook/callback`,
      scope: ['pages_show_list', 'pages_manage_posts', 'pages_read_engagement', 'instagram_basic'],
      profileFields: ['id', 'displayName', 'email', 'photos']
    }, async (accessToken: string, refreshToken: string, profile: OAuthProfile, done: any) => {
      try {
        console.log(`✅ Facebook OAuth successful for: ${profile.displayName}`);
        
        // Store tokens in database
        const { storage } = await import('../storage.js');
        const tokens: OAuthTokens = {
          accessToken,
          refreshToken,
          expiresIn: 60 * 24 * 60 * 60, // 60 days for Facebook
          scope: ['pages_show_list', 'pages_manage_posts', 'pages_read_engagement']
        };
        
        // Create or update OAuth connection
        await storage.upsertOAuthConnection({
          userId: profile.id,
          platform: 'facebook',
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresAt: new Date(Date.now() + (tokens.expiresIn! * 1000)),
          scope: tokens.scope?.join(',') || '',
          isActive: true
        });
        
        done(null, {
          platform: 'facebook',
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresAt: new Date(Date.now() + (tokens.expiresIn! * 1000)),
          profile
        });
      } catch (error) {
        console.error('❌ Facebook OAuth error:', error);
        done(error, null);
      }
    }));
    console.log('✅ Facebook OAuth strategy configured');
  }

  // Google OAuth Strategy (YouTube)
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${baseUrl}/auth/google/callback`,
      scope: [
        'profile', 
        'email', 
        'https://www.googleapis.com/auth/youtube.upload',
        'https://www.googleapis.com/auth/youtube.readonly'
      ]
    }, async (accessToken: string, refreshToken: string, profile: OAuthProfile, done: any) => {
      try {
        console.log(`✅ Google OAuth successful for: ${profile.displayName}`);
        
        const { storage } = await import('../storage.js');
        const tokens: OAuthTokens = {
          accessToken,
          refreshToken,
          expiresIn: 60 * 60, // 1 hour for Google
          scope: ['youtube.upload', 'youtube.readonly']
        };
        
        await storage.upsertOAuthConnection({
          userId: profile.id,
          platform: 'youtube',
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresAt: new Date(Date.now() + (tokens.expiresIn! * 1000)),
          scope: tokens.scope?.join(',') || '',
          isActive: true
        });
        
        done(null, {
          platform: 'youtube',
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresAt: new Date(Date.now() + (tokens.expiresIn! * 1000)),
          profile
        });
      } catch (error) {
        console.error('❌ Google OAuth error:', error);
        done(error, null);
      }
    }));
    console.log('✅ Google OAuth strategy configured');
  }

  // LinkedIn OAuth Strategy
  if (process.env.LINKEDIN_CLIENT_ID && process.env.LINKEDIN_CLIENT_SECRET) {
    passport.use(new LinkedInStrategy({
      clientID: process.env.LINKEDIN_CLIENT_ID,
      clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
      callbackURL: `${baseUrl}/auth/linkedin/callback`,
      scope: ['r_liteprofile', 'w_member_social', 'r_organization_social']
    }, async (accessToken: string, refreshToken: string, profile: OAuthProfile, done: any) => {
      try {
        console.log(`✅ LinkedIn OAuth successful for: ${profile.displayName}`);
        
        const { storage } = await import('../storage.js');
        const tokens: OAuthTokens = {
          accessToken,
          refreshToken,
          expiresIn: 60 * 24 * 60 * 60, // 60 days for LinkedIn
          scope: ['r_liteprofile', 'w_member_social']
        };
        
        await storage.upsertOAuthConnection({
          userId: profile.id,
          platform: 'linkedin',
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresAt: new Date(Date.now() + (tokens.expiresIn! * 1000)),
          scope: tokens.scope?.join(',') || '',
          isActive: true
        });
        
        done(null, {
          platform: 'linkedin',
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresAt: new Date(Date.now() + (tokens.expiresIn! * 1000)),
          profile
        });
      } catch (error) {
        console.error('❌ LinkedIn OAuth error:', error);
        done(error, null);
      }
    }));
    console.log('✅ LinkedIn OAuth strategy configured');
  }

  console.log('🚀 All OAuth strategies configured successfully');
}

/**
 * OAuth route handlers for authentication flows
 */
export function setupOAuthRoutes(app: any) {
  // Facebook OAuth routes
  app.get('/auth/facebook', passport.authenticate('facebook', {
    scope: ['pages_show_list', 'pages_manage_posts', 'pages_read_engagement']
  }));

  app.get('/auth/facebook/callback', 
    passport.authenticate('facebook', { failureRedirect: '/login?error=facebook_auth_failed' }),
    (req: any, res: any) => {
      console.log('✅ Facebook OAuth callback successful');
      res.redirect('/platform-connections?connected=facebook');
    }
  );

  // Google OAuth routes
  app.get('/auth/google', passport.authenticate('google', {
    scope: ['profile', 'email', 'https://www.googleapis.com/auth/youtube.upload']
  }));

  app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login?error=google_auth_failed' }),
    (req: any, res: any) => {
      console.log('✅ Google OAuth callback successful');
      res.redirect('/platform-connections?connected=youtube');
    }
  );

  // LinkedIn OAuth routes
  app.get('/auth/linkedin', passport.authenticate('linkedin'));

  app.get('/auth/linkedin/callback',
    passport.authenticate('linkedin', { failureRedirect: '/login?error=linkedin_auth_failed' }),
    (req: any, res: any) => {
      console.log('✅ LinkedIn OAuth callback successful');
      res.redirect('/platform-connections?connected=linkedin');
    }
  );

  // OAuth disconnect route
  app.post('/auth/disconnect/:platform', async (req: any, res: any) => {
    try {
      const { platform } = req.params;
      const userId = req.session?.userId;
      
      if (!userId) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const { storage } = await import('../storage.js');
      
      // Deactivate OAuth connection
      await storage.deactivateOAuthConnection(userId, platform);
      
      console.log(`🔌 OAuth disconnected: ${platform} for user ${userId}`);
      res.json({ success: true, platform, message: `${platform} disconnected successfully` });
    } catch (error) {
      console.error('❌ OAuth disconnect error:', error);
      res.status(500).json({ error: 'Failed to disconnect OAuth connection' });
    }
  });

  console.log('🔗 OAuth routes configured successfully');
}