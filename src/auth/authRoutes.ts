import { Router } from 'express';
import passport from 'passport';
// import { Strategy as FacebookStrategy } from 'passport-facebook'; // DISABLED - using custom implementation
import { Strategy as LinkedInStrategy } from 'passport-linkedin-oauth2';
import { Strategy as TwitterStrategy } from 'passport-twitter';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { storage } from '../../server/storage';

const authRouter = Router();

// OAuth redirect base URL configuration - dynamic environment handling
const baseUrl = process.env.NODE_ENV === 'production'
  ? 'https://app.theagencyiq.ai'
  : 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

// TypeScript interfaces for OAuth callback handling
interface OAuthProfile {
  id: string;
  displayName?: string;
  username?: string;
  name?: {
    givenName?: string;
    familyName?: string;
  };
  emails?: Array<{ value: string }>;
}

interface OAuthTokens {
  accessToken: string;
  refreshToken?: string | null;
  tokenSecret?: string; // For Twitter OAuth 1.0a
}

interface OAuthCallbackParams {
  req: any;
  profile: OAuthProfile;
  tokens: OAuthTokens;
  platform: string;
}

interface OAuthResult {
  platform: string;
  success: boolean;
  error?: string;
}

// Unified OAuth callback handler with comprehensive error handling
async function handleOAuthCallback(params: OAuthCallbackParams): Promise<OAuthResult> {
  const { req, profile, tokens, platform } = params;
  
  try {
    // Step 1: Validate user session
    let userId = req.session?.userId;
    
    // LinkedIn session recovery - handle lost sessions during OAuth flow
    if (!userId && platform === 'linkedin' && profile.emails?.[0]) {
      const user = await storage.getUserByEmail(profile.emails[0].value);
      if (user) {
        userId = user.id;
        req.session.userId = userId;
        req.session.save();
      }
    }
    
    if (!userId) {
      throw new Error(`User session lost during ${platform} OAuth - please log in again`);
    }

    // Step 2: Validate OAuth tokens (no mock/demo tokens)
    const primaryToken = tokens.accessToken || tokens.tokenSecret;
    if (!primaryToken || 
        primaryToken.includes('demo') || 
        primaryToken.includes('mock') || 
        primaryToken.length < 10) {
      throw new Error(`Invalid ${platform} OAuth token received`);
    }

    // Step 3: Extract platform-specific user data
    const platformData = extractPlatformData(profile, platform);
    
    console.log(`${platform} OAuth successful:`, {
      profileId: profile.id,
      displayName: platformData.displayName,
      userId: userId,
      tokenType: 'live_oauth'
    });

    // Step 4: Store platform connection
    await storage.createPlatformConnection({
      userId,
      platform,
      platformUserId: profile.id,
      platformUsername: platformData.displayName,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken || tokens.tokenSecret || null,
      isActive: true
    });

    return { platform, success: true };
    
  } catch (error: any) {
    console.error(`${platform} OAuth error:`, error);
    return { 
      platform, 
      success: false, 
      error: error.message 
    };
  }
}

// Extract platform-specific display name and user data
function extractPlatformData(profile: OAuthProfile, platform: string): { displayName: string } {
  switch (platform) {
    case 'facebook':
    case 'youtube':
      return { displayName: profile.displayName || profile.id };
    
    case 'linkedin':
      return { 
        displayName: profile.displayName || 
                    (profile.name ? `${profile.name.givenName} ${profile.name.familyName}` : profile.id)
      };
    
    case 'x':
      return { displayName: profile.username || profile.displayName || profile.id };
    
    default:
      return { displayName: profile.displayName || profile.id };
  }
}

// Configure Passport strategies
export function configurePassportStrategies() {
  // Facebook OAuth Strategy - DISABLED (using custom implementation in authModule)
  console.log('Facebook OAuth: Passport strategy disabled, using custom implementation');
  // Note: Custom Facebook OAuth handler implemented in authModule.ts to bypass passport-facebook errors

  // LinkedIn OAuth Strategy
  passport.use(new LinkedInStrategy({
    clientID: process.env.LINKEDIN_CLIENT_ID!,
    clientSecret: process.env.LINKEDIN_CLIENT_SECRET!,
    callbackURL: `${baseUrl}/auth/linkedin/callback`,
    scope: ['profile', 'w_member_social', 'email'],
    passReqToCallback: true
  }, async (req: any, accessToken: string, refreshToken: string, profile: any, done: any) => {
    const result = await handleOAuthCallback({
      req,
      profile,
      tokens: { accessToken, refreshToken },
      platform: 'linkedin'
    });
    
    return result.success 
      ? done(null, result) 
      : done(new Error(result.error));
  }));

  // X (Twitter) OAuth Strategy
  passport.use(new TwitterStrategy({
    consumerKey: process.env.X_0AUTH_CLIENT_ID!,
    consumerSecret: process.env.X_0AUTH_CLIENT_SECRET!,
    callbackURL: `${baseUrl}/auth/twitter/callback`,
    userProfileURL: "https://api.twitter.com/1.1/account/verify_credentials.json?include_email=true",
    passReqToCallback: true
  }, async (req: any, token: string, tokenSecret: string, profile: any, done: any) => {
    const result = await handleOAuthCallback({
      req,
      profile,
      tokens: { accessToken: token, tokenSecret },
      platform: 'x'
    });
    
    return result.success 
      ? done(null, result) 
      : done(new Error(result.error));
  }));

  // YouTube (Google) OAuth Strategy
  passport.use('youtube', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    callbackURL: `${baseUrl}/auth/youtube/callback`,
    scope: ['https://www.googleapis.com/auth/youtube.readonly', 'https://www.googleapis.com/auth/youtube.upload'],
    passReqToCallback: true
  }, async (req: any, accessToken: string, refreshToken: string, profile: any, done: any) => {
    const result = await handleOAuthCallback({
      req,
      profile,
      tokens: { accessToken, refreshToken },
      platform: 'youtube'
    });
    
    return result.success 
      ? done(null, result) 
      : done(new Error(result.error));
  }));

  // Passport serialization
  passport.serializeUser((user: any, done) => {
    done(null, user);
  });

  passport.deserializeUser((user: any, done) => {
    done(null, user);
  });
}

// OAuth route handlers - Facebook routes disabled (using custom implementation)
// Note: Facebook OAuth routes implemented in authModule.ts as custom handlers

authRouter.get('/linkedin', passport.authenticate('linkedin', { scope: ['profile', 'w_member_social', 'email'] }));
authRouter.get('/linkedin/callback', passport.authenticate('linkedin', { failureRedirect: '/login' }), (req, res) => {
  res.redirect('/dashboard?connected=linkedin');
});

authRouter.get('/twitter', passport.authenticate('twitter'));
authRouter.get('/twitter/callback', passport.authenticate('twitter', { failureRedirect: '/login' }), (req, res) => {
  res.redirect('/dashboard?connected=x');
});

authRouter.get('/youtube', passport.authenticate('youtube', { scope: ['https://www.googleapis.com/auth/youtube.upload'] }));
authRouter.get('/youtube/callback', passport.authenticate('youtube', { failureRedirect: '/login' }), (req, res) => {
  res.redirect('/dashboard?connected=youtube');
});

// OAuth configuration test endpoint
authRouter.get('/test-config', (req, res) => {
  const config = {
    timestamp: new Date().toISOString(),
    baseUrl: baseUrl,
    strategies: {
      facebook: {
        configured: !!(process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET),
        appId: process.env.FACEBOOK_APP_ID ? 'configured' : 'missing',
        callbackUrl: `${baseUrl}/auth/facebook/callback`
      },
      linkedin: {
        configured: !!(process.env.LINKEDIN_CLIENT_ID && process.env.LINKEDIN_CLIENT_SECRET),
        callbackUrl: `${baseUrl}/auth/linkedin/callback`
      },
      twitter: {
        configured: !!(process.env.X_0AUTH_CLIENT_ID && process.env.X_0AUTH_CLIENT_SECRET),
        callbackUrl: `${baseUrl}/auth/twitter/callback`
      },
      youtube: {
        configured: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
        callbackUrl: `${baseUrl}/auth/youtube/callback`
      }
    },
    packageVersions: {
      passport: '0.7.0',
      passportFacebook: '3.0.0'
    }
  };
  
  res.json(config);
});

export { authRouter };