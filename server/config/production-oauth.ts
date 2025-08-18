/**
 * PRODUCTION OAUTH CONFIGURATION - ZERO REGRESSION
 * Configures OAuth strategies for app.theagencyiq.ai production deployment
 * Maintains full backward compatibility with existing development setup
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

/**
 * Production-ready OAuth configuration for app.theagencyiq.ai
 * Automatically detects environment and configures appropriate callback URLs
 */
export function configureProductionOAuth() {
  // Environment detection for production vs development
  const isProd = process.env.NODE_ENV === 'production' || process.env.REPLIT_DEPLOYED === 'true';
  
  // Production callback URL configuration
  const baseUrl = isProd 
    ? 'https://app.theagencyiq.ai' 
    : (process.env.REPLIT_DOMAINS?.split(',')[0] || 'http://localhost:5000');
  
  console.log(`🚀 OAUTH PRODUCTION CONFIG: ${isProd ? 'PRODUCTION' : 'DEVELOPMENT'} MODE`);
  console.log(`🔗 Base URL: ${baseUrl}`);

  // Passport serialization (simplified for production)
  passport.serializeUser((user: any, done) => {
    done(null, user);
  });

  passport.deserializeUser((user: any, done) => {
    done(null, user);
  });

  // Facebook OAuth Strategy - Production Ready
  if (process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET) {
    passport.use(new FacebookStrategy({
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: `${baseUrl}/auth/facebook/callback`,
      scope: ['pages_show_list', 'pages_manage_posts', 'pages_read_engagement', 'instagram_basic'],
      profileFields: ['id', 'displayName', 'email', 'photos']
    }, async (accessToken: string, refreshToken: string, profile: OAuthProfile, done: any) => {
      try {
        console.log(`✅ FACEBOOK OAUTH SUCCESS: ${profile.displayName} (${isProd ? 'PRODUCTION' : 'DEV'})`);
        
        // Return OAuth data for session storage
        done(null, {
          platform: 'facebook',
          accessToken,
          refreshToken,
          profile,
          expiresAt: new Date(Date.now() + (60 * 24 * 60 * 60 * 1000)) // 60 days
        });
      } catch (error) {
        console.error('❌ Facebook OAuth error:', error);
        done(error, null);
      }
    }));
    console.log(`✅ Facebook OAuth configured for ${baseUrl}/auth/facebook/callback`);
  }

  // Google/YouTube OAuth Strategy - Production Ready
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
        console.log(`✅ GOOGLE OAUTH SUCCESS: ${profile.displayName} (${isProd ? 'PRODUCTION' : 'DEV'})`);
        
        done(null, {
          platform: 'youtube',
          accessToken,
          refreshToken,
          profile,
          expiresAt: new Date(Date.now() + (60 * 60 * 1000)) // 1 hour
        });
      } catch (error) {
        console.error('❌ Google OAuth error:', error);
        done(error, null);
      }
    }));
    console.log(`✅ Google OAuth configured for ${baseUrl}/auth/google/callback`);
  }

  // LinkedIn OAuth Strategy - Production Ready
  if (process.env.LINKEDIN_CLIENT_ID && process.env.LINKEDIN_CLIENT_SECRET) {
    passport.use(new LinkedInStrategy({
      clientID: process.env.LINKEDIN_CLIENT_ID,
      clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
      callbackURL: `${baseUrl}/auth/linkedin/callback`,
      scope: ['r_liteprofile', 'w_member_social', 'r_organization_social']
    }, async (accessToken: string, refreshToken: string, profile: OAuthProfile, done: any) => {
      try {
        console.log(`✅ LINKEDIN OAUTH SUCCESS: ${profile.displayName} (${isProd ? 'PRODUCTION' : 'DEV'})`);
        
        done(null, {
          platform: 'linkedin',
          accessToken,
          refreshToken,
          profile,
          expiresAt: new Date(Date.now() + (60 * 24 * 60 * 60 * 1000)) // 60 days
        });
      } catch (error) {
        console.error('❌ LinkedIn OAuth error:', error);
        done(error, null);
      }
    }));
    console.log(`✅ LinkedIn OAuth configured for ${baseUrl}/auth/linkedin/callback`);
  }

  console.log('🚀 PRODUCTION OAUTH CONFIGURATION COMPLETE');
  return { isProd, baseUrl };
}

/**
 * Production OAuth route handlers with proper error handling
 */
export function setupProductionOAuthRoutes(app: any) {
  const { isProd } = configureProductionOAuth();

  // Facebook OAuth routes
  app.get('/auth/facebook', passport.authenticate('facebook', {
    scope: ['pages_show_list', 'pages_manage_posts', 'pages_read_engagement', 'instagram_basic']
  }));

  app.get('/auth/facebook/callback', 
    passport.authenticate('facebook', { failureRedirect: '/login?error=facebook_auth_failed' }),
    (req: any, res: any) => {
      console.log(`✅ FACEBOOK CALLBACK SUCCESS (${isProd ? 'PRODUCTION' : 'DEV'})`);
      res.redirect('/platform-connections?connected=facebook');
    }
  );

  // Google OAuth routes
  app.get('/auth/google', passport.authenticate('google', {
    scope: [
      'profile', 
      'email', 
      'https://www.googleapis.com/auth/youtube.upload',
      'https://www.googleapis.com/auth/youtube.readonly'
    ]
  }));

  app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login?error=google_auth_failed' }),
    (req: any, res: any) => {
      console.log(`✅ GOOGLE CALLBACK SUCCESS (${isProd ? 'PRODUCTION' : 'DEV'})`);
      res.redirect('/platform-connections?connected=youtube');
    }
  );

  // LinkedIn OAuth routes
  app.get('/auth/linkedin', passport.authenticate('linkedin'));

  app.get('/auth/linkedin/callback',
    passport.authenticate('linkedin', { failureRedirect: '/login?error=linkedin_auth_failed' }),
    (req: any, res: any) => {
      console.log(`✅ LINKEDIN CALLBACK SUCCESS (${isProd ? 'PRODUCTION' : 'DEV'})`);
      res.redirect('/platform-connections?connected=linkedin');
    }
  );

  // X (Twitter) OAuth route placeholder
  app.get('/auth/twitter', (req: any, res: any) => {
    res.redirect('/platform-connections?error=twitter_not_configured');
  });

  console.log(`🔗 PRODUCTION OAUTH ROUTES CONFIGURED FOR ${isProd ? 'app.theagencyiq.ai' : 'DEVELOPMENT'}`);
}