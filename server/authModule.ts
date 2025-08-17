// authModule.ts (~line 1 – add .ts for ESM compatibility on Vercel build)
import { storage } from './storage.ts'; // Change to this

// ~line 5 – fixed balanced deserializeUser (remove extra });, place comment outside)
passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await storage.getUserById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
}); // Function closes here – no extra });

// Add console.error inside each catch block as code (not comment), e.g., for FB ~line 20:
catch (err) {
  console.error(`Facebook OAuth failed: ${err.message}`); // e.g., Facebook OAuth failed: invalid scope
  done(err, null);
}
// Repeat for LI ~line 50, X ~line 70, YT ~line 90 catch blocks

// FIXED: Configure strategies (your pasted Facebook is correct – patched with error logging; add others below it)
function configurePassportStrategies() {
  passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK_URL,
    profileFields: ['id', 'emails', 'name'],
    scope: ['email', 'pages_manage_posts', 'publish_to_groups', 'instagram_basic', 'instagram_content_publish'] // Confirmed correct per research
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await storage.getUserByPlatformId('facebook', profile.id);
      if (!user) {
        user = await storage.saveUser({ email: profile.emails?.[0]?.value, platformId: { facebook: profile.id } });
      }
      await storage.saveOAuthTokens(user.id, 'facebook', { accessToken, refreshToken });
      done(null, user);
    } catch (err) {
      console.error(`Facebook OAuth failed: ${err.message}`); // Added logging for debug
      done(err, null);
    }
  }));

  // Add LinkedIn strategy here (~line 30 – researched scopes/limits)
  passport.use(new LinkedInStrategy({
    clientID: process.env.LINKEDIN_CLIENT_ID,
    clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
    callbackURL: process.env.LINKEDIN_CALLBACK_URL,
    scope: ['profile', 'email', 'w_organization_social'] // For posting, limits 50/day
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await storage.getUserByPlatformId('linkedin', profile.id);
      if (!user) {
        user = await storage.saveUser({ email: profile.emails?.[0]?.value, platformId: { linkedin: profile.id } });
      }
      await storage.saveOAuthTokens(user.id, 'linkedin', { accessToken, refreshToken });
      done(null, user);
    } catch (err) {
      console.error(`LinkedIn OAuth failed: ${err.message}`);
      done(err, null);
    }
  }));

  // Add X/Twitter strategy here (~line 50 – OAuth1, limits 100/day)
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
      console.error(`X OAuth failed: ${err.message}`);
      done(err, null);
    }
  }));

  // Add YouTube strategy here (~line 70 – limits ~6/day)
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
      console.error(`YouTube OAuth failed: ${err.message}`);
      done(err, null);
    }
  }));
}

// Auth router (unchanged – add routes if needed)
const authRouter = express.Router();
// ... (keep your existing routes for facebook/linkedin/twitter/google)

export { configurePassportStrategies, authRouter };