/**
 * Passport.js OAuth Setup with PostgreSQL Token Storage
 * Comprehensive OAuth strategies for all social media platforms
 */

import passport from 'passport';
import { Strategy as TwitterStrategy } from 'passport-twitter';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LinkedInStrategy } from 'passport-linkedin-oauth2';

// Import database and schema
import { db } from '../db.js';
import { users, oauthTokens } from '@shared/schema';
import { eq } from 'drizzle-orm';

/**
 * Initialize Passport.js with OAuth strategies
 */
function setupPassport() {
  console.log('🔐 Setting up Passport.js OAuth strategies...');

  // Serialize user for session
  passport.serializeUser((user, done) => {
    console.log(`📝 Serializing user: ${user.id}`);
    done(null, user.id);
  });

  // Deserialize user from session
  passport.deserializeUser(async (id, done) => {
    try {
      console.log(`🔍 Deserializing user: ${id}`);
      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, id));
      
      if (!user) {
        return done(new Error('User not found'), null);
      }
      
      console.log(`✅ User deserialized: ${user.email}`);
      done(null, user);
    } catch (error) {
      console.error('❌ Deserialization error:', error);
      done(error, null);
    }
  });

  // Twitter OAuth Strategy
  if (process.env.TWITTER_CONSUMER_KEY && process.env.TWITTER_CONSUMER_SECRET) {
    passport.use(new TwitterStrategy({
      consumerKey: process.env.TWITTER_CONSUMER_KEY,
      consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
      callbackURL: process.env.TWITTER_CALLBACK_URL || '/auth/twitter/callback',
      includeEmail: true
    }, async (token, tokenSecret, profile, done) => {
      try {
        console.log(`🐦 Twitter OAuth callback for user: ${profile.username}`);
        
        const user = await handleOAuthCallback({
          platform: 'twitter',
          platformId: profile.id,
          username: profile.username,
          email: profile.emails?.[0]?.value,
          displayName: profile.displayName,
          profileImageUrl: profile.photos?.[0]?.value,
          accessToken: token,
          refreshToken: tokenSecret, // Twitter uses token secret as refresh mechanism
          scopes: ['read', 'write'] // Twitter OAuth 1.1 default scopes
        });
        
        done(null, user);
      } catch (error) {
        console.error('❌ Twitter OAuth error:', error);
        done(error, null);
      }
    }));
    console.log('✅ Twitter OAuth strategy configured');
  }

  // Facebook OAuth Strategy
  if (process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET) {
    passport.use(new FacebookStrategy({
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL || '/auth/facebook/callback',
      profileFields: ['id', 'emails', 'name', 'picture.type(large)'],
      scope: ['email', 'public_profile', 'pages_manage_posts', 'pages_read_engagement', 'publish_to_groups']
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        console.log(`📘 Facebook OAuth callback for user: ${profile.id}`);
        
        const user = await handleOAuthCallback({
          platform: 'facebook',
          platformId: profile.id,
          username: profile.username || profile.id,
          email: profile.emails?.[0]?.value,
          displayName: `${profile.name.givenName} ${profile.name.familyName}`,
          profileImageUrl: profile.photos?.[0]?.value,
          accessToken,
          refreshToken,
          scopes: ['email', 'public_profile', 'pages_manage_posts', 'pages_read_engagement', 'publish_to_groups']
        });
        
        done(null, user);
      } catch (error) {
        console.error('❌ Facebook OAuth error:', error);
        done(error, null);
      }
    }));
    console.log('✅ Facebook OAuth strategy configured');
  }

  // Google OAuth Strategy (for YouTube)
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback',
      scope: ['profile', 'email', 'https://www.googleapis.com/auth/youtube.upload', 'https://www.googleapis.com/auth/youtube']
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        console.log(`🔴 Google OAuth callback for user: ${profile.id}`);
        
        const user = await handleOAuthCallback({
          platform: 'youtube',
          platformId: profile.id,
          username: profile.emails?.[0]?.value,
          email: profile.emails?.[0]?.value,
          displayName: profile.displayName,
          profileImageUrl: profile.photos?.[0]?.value,
          accessToken,
          refreshToken,
          scopes: ['profile', 'email', 'youtube.upload', 'youtube']
        });
        
        done(null, user);
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
      callbackURL: process.env.LINKEDIN_CALLBACK_URL || '/auth/linkedin/callback',
      scope: ['r_liteprofile', 'r_emailaddress', 'w_member_social'],
      state: true
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        console.log(`💼 LinkedIn OAuth callback for user: ${profile.id}`);
        
        const user = await handleOAuthCallback({
          platform: 'linkedin',
          platformId: profile.id,
          username: profile.emails?.[0]?.value,
          email: profile.emails?.[0]?.value,
          displayName: profile.displayName,
          profileImageUrl: profile.photos?.[0]?.value,
          accessToken,
          refreshToken,
          scopes: ['r_liteprofile', 'r_emailaddress', 'w_member_social']
        });
        
        done(null, user);
      } catch (error) {
        console.error('❌ LinkedIn OAuth error:', error);
        done(error, null);
      }
    }));
    console.log('✅ LinkedIn OAuth strategy configured');
  }

  console.log('🎉 Passport.js OAuth setup complete');
}

/**
 * Handle OAuth callback for all platforms
 * Creates or updates user and stores tokens in PostgreSQL
 */
async function handleOAuthCallback({
  platform,
  platformId,
  username,
  email,
  displayName,
  profileImageUrl,
  accessToken,
  refreshToken,
  scopes
}) {
  try {
    console.log(`🔄 Processing OAuth callback for ${platform}: ${username}`);
    
    // Find or create user
    let [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email));
    
    if (!user) {
      console.log(`👤 Creating new user for ${email}`);
      [user] = await db
        .insert(users)
        .values({
          email,
          firstName: displayName?.split(' ')[0] || username,
          lastName: displayName?.split(' ').slice(1).join(' ') || '',
          profileImageUrl,
          subscriptionPlan: 'professional',
          subscriptionActive: true,
          totalPosts: 52,
          remainingPosts: 52
        })
        .returning();
    }
    
    // Store or update OAuth tokens in PostgreSQL
    const tokenExpiry = new Date();
    tokenExpiry.setHours(tokenExpiry.getHours() + 1); // Default 1 hour expiry
    
    // Check if token already exists for this user/platform
    const [existingToken] = await db
      .select()
      .from(oauthTokens)
      .where(eq(oauthTokens.userId, user.id))
      .where(eq(oauthTokens.platform, platform));
    
    const tokenData = {
      userId: user.id,
      platform,
      platformUserId: platformId,
      platformUsername: username,
      accessToken,
      refreshToken,
      scopes: scopes.join(','),
      expiresAt: tokenExpiry,
      isActive: true
    };
    
    if (existingToken) {
      console.log(`🔄 Updating existing ${platform} token for user ${user.id}`);
      await db
        .update(oauthTokens)
        .set({
          ...tokenData,
          updatedAt: new Date()
        })
        .where(eq(oauthTokens.id, existingToken.id));
    } else {
      console.log(`💾 Storing new ${platform} token for user ${user.id}`);
      await db
        .insert(oauthTokens)
        .values(tokenData);
    }
    
    console.log(`✅ OAuth callback processed successfully for ${platform}`);
    return user;
    
  } catch (error) {
    console.error(`❌ OAuth callback processing error for ${platform}:`, error);
    throw error;
  }
}

export {
  setupPassport,
  handleOAuthCallback
};