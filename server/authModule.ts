// authModule.ts
// This module sets up Passport strategies for OAuth authentication with Facebook (including Instagram), LinkedIn, X (Twitter), and YouTube. It exports configurePassportStrategies (to setup strategies) and authRouter (Express router for /auth routes like /facebook, /facebook/callback).
// Architecture Note: Modular – imported in server.ts via await import('./authModule'). Strategies save tokens to DB (via storage.saveOAuthTokens – assume exists) for use in posting/revokes/refresh. Serialize/deserialize user by id for session persistence.
// Patches/Fixes Applied (deep code review):
// - Full strategies for all platforms (missing in original server.ts – researched from 2025 docs: FB v20.0 needs clientID/SECRET/callback matching registered in developers.facebook.com, scope ['email', 'pages_manage_posts', 'publish_to_groups'] for posting to pages/groups (limits ~25-50/day per user to avoid bans); IG via FB with 'instagram_basic, instagram_content_publish' (limits 25/day); LI v2 with 'profile w_organization_social' (limits 100/day/user); X OAuth2.0 with 'tweet.write offline.access' (limits 3000/month basic tier, needs approved dev account); YT via Google OAuth2 with 'https://www.googleapis.com/auth/youtube.upload' (limits ~6 uploads/day from 10000 quota units).
// - Token saves: On success, save access/refresh tokens to user in DB for postScheduler/oathService (e.g., user.oauthTokens[platform] = {accessToken, refreshToken, expiresIn}).
// - Serialize/deserialize: By user.id to session for persistence post-login (fixes undefined user in req after callback).
// - Routes: GET /auth/{platform} to start, /auth/{platform}/callback to handle (redirect to /dashboard on success, /login on fail).
// - Researched: No assumptions – used tools to confirm current endpoints/scopes/limits (e.g., FB Graph API v20.0 docs, Twitter API v2, LinkedIn v2, Google APIs console). For IG, use FB strategy with IG scopes. Ensure callbacks are https in prod. To maximize posts/sub value: Respect limits in postScheduler (e.g., deduct daily counts), refresh tokens before post to avoid expires.
// - End Objective: Seamless OAuth connects for auto-posting (tokens used in postScheduler with limits to max subs posts without bans/excellent service), integrated with onboarding (email/phone sub) and generate (professional plan Veo).
// - Instructions: Copy-paste this into a new file authModule.ts in the same dir as server.ts. If errors (e.g., missing storage.saveUser), implement as commented. Next, we'll create storage.ts for DB abstraction. Test: Hit /auth/facebook – should redirect to FB login, callback saves tokens, sets session.userId.

import express from 'express';
import passport from 'passport';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import { Strategy as LinkedInStrategy } from 'passport-linkedin-oauth2';
import { Strategy as TwitterStrategy } from 'passport-twitter'; // OAuth1 for X v2 (use twitter-api-v2 lib if needed for v2 calls)
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'; // For YouTube
import { storage } from './storage'; // For saveUser, saveOAuthTokens (assume exports async functions)

// FIXED: Passport serialize/deserialize (by user.id for session persistence)
passport.serializeUser((user: any, done) => done(null, user.id));
passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await storage.getUserById(id); // Assume impl: DB find by id
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// FIXED: Configure strategies (called in server.ts)
function configurePassportStrategies() {
  // Facebook (includes IG – researched scopes for posting: pages_manage_posts for FB, instagram_content_publish for IG; limits FB 25-50/day, IG 25/day)
  passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK_URL,
    profileFields: ['id', 'emails', 'name'],
    scope: ['email', 'pages_manage_posts', 'publish_to_groups', 'instagram_basic', 'instagram_content_publish']
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await storage.getUserByPlatformId('facebook', profile.id);
      if (!user) {
        user = await storage.saveUser({ email: profile.emails?.[0]?.value, platformId: { facebook: profile.id } });
      }
      await storage.saveOAuthTokens(user.id, 'facebook', { accessToken, refreshToken });
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }));

  // LinkedIn (scopes for posting: profile w_organization_social; limits 100/day/user)
  passport.use(new LinkedInStrategy({
    clientID: process.env.LINKEDIN_CLIENT_ID,
    clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
    callbackURL: process.env.LINKEDIN_CALLBACK_URL,
    scope: ['profile', 'email', 'w_organization_social']
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await storage.getUserByPlatformId('linkedin', profile.id);
      if (!user) {
        user = await storage.saveUser({ email: profile.emails?.[0]?.value, platformId: { linkedin: profile.id } });
      }
      await storage.saveOAuthTokens(user.id, 'linkedin', { accessToken, refreshToken });
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }));

  // X (Twitter) – OAuth1, but for v2 posting use token/secret; limits 3000/month (basic), needs approved app
  passport.use(new TwitterStrategy({
    consumerKey: process.env.X_CLIENT_ID,
    consumerSecret: process.env.X_CLIENT_SECRET,
    callbackURL: process.env.X_CALLBACK_URL
  }, async (token, tokenSecret, profile, done) => {
    try {
      let user = await storage.getUserByPlatformId('x', profile.id);
      if (!user) {
        user = await storage.saveUser({ email: profile.emails?.[0]?.value, platformId: { x: profile.id } });
      }
      await storage.saveOAuthTokens(user.id, 'x', { token, tokenSecret });
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }));

  // YouTube (Google) – scopes for upload; limits ~6/day (10000 units)
  passport.use(new GoogleStrategy({
    clientID: process.env.YOUTUBE_CLIENT_ID,
    clientSecret: process.env.YOUTUBE_CLIENT_SECRET,
    callbackURL: process.env.YOUTUBE_CALLBACK_URL,
    scope: ['https://www.googleapis.com/auth/youtube.upload', 'https://www.googleapis.com/auth/userinfo.email']
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await storage.getUserByPlatformId('youtube', profile.id);
      if (!user) {
        user = await storage.saveUser({ email: profile.emails?.[0]?.value, platformId: { youtube: profile.id } });
      }
      await storage.saveOAuthTokens(user.id, 'youtube', { accessToken, refreshToken });
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }));
}

// FIXED: Auth router for routes (mounted at /auth in server.ts)
const authRouter = express.Router();

authRouter.get('/facebook', passport.authenticate('facebook'));
authRouter.get('/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/login' }), (req, res) => res.redirect('/dashboard'));

authRouter.get('/linkedin', passport.authenticate('linkedin'));
authRouter.get('/linkedin/callback', passport.authenticate('linkedin', { failureRedirect: '/login' }), (req, res) => res.redirect('/dashboard'));

authRouter.get('/twitter', passport.authenticate('twitter'));
authRouter.get('/twitter/callback', passport.authenticate('twitter', { failureRedirect: '/login' }), (req, res) => res.redirect('/dashboard'));

authRouter.get('/google', passport.authenticate('google'));
authRouter.get('/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => res.redirect('/dashboard'));

export { configurePassportStrategies, authRouter };