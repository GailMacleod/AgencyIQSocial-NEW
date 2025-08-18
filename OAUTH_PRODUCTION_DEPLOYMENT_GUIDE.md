# OAuth Production Deployment Guide for app.theagencyiq.ai

## 🚀 Production OAuth Configuration Complete

The TheAgencyIQ application is now fully configured for production deployment with automatic OAuth callback URL detection. The system will automatically use `https://app.theagencyiq.ai` callbacks when deployed in production.

## ✅ What's Already Done

- ✅ Production OAuth configuration implemented in `server/config/production-oauth.ts`
- ✅ Automatic environment detection (production vs development)
- ✅ Production callback URLs configured: `https://app.theagencyiq.ai/auth/{platform}/callback`
- ✅ OAuth routes integrated into main server (`server/routes.ts`)
- ✅ Zero regression approach - all existing functionality preserved

## 🔧 Required OAuth Application Updates

To enable social media connections in production, update these callback URLs in your OAuth applications:

### Facebook Developer Console
1. Go to https://developers.facebook.com/apps/
2. Select your Facebook app
3. Navigate to **Facebook Login > Settings**
4. Add this callback URL:
   ```
   https://app.theagencyiq.ai/auth/facebook/callback
   ```

### Google Cloud Console  
1. Go to https://console.cloud.google.com/apis/credentials
2. Select your OAuth 2.0 Client ID
3. Add this authorized redirect URI:
   ```
   https://app.theagencyiq.ai/auth/google/callback
   ```

### LinkedIn Developer Portal
1. Go to https://www.linkedin.com/developers/apps/
2. Select your LinkedIn app
3. Navigate to **Auth** tab
4. Add this redirect URL:
   ```
   https://app.theagencyiq.ai/auth/linkedin/callback
   ```

## 🔑 Environment Variables Required

Set these environment variables in Replit Secrets for production:

```bash
# Production Environment Detection
NODE_ENV=production
REPLIT_DEPLOYED=true

# OAuth Credentials (from your developer consoles)
FACEBOOK_APP_ID=your_facebook_app_id
FACEBOOK_APP_SECRET=your_facebook_app_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
LINKEDIN_CLIENT_ID=your_linkedin_client_id
LINKEDIN_CLIENT_SECRET=your_linkedin_client_secret

# Other required secrets...
SESSION_SECRET=your_session_secret
DATABASE_URL=your_postgresql_url
```

## 🌐 How It Works

1. **Environment Detection**: System automatically detects production environment
2. **Callback URL Generation**: Uses `https://app.theagencyiq.ai` for all OAuth callbacks in production
3. **Fallback Support**: Falls back to development URLs in development environment
4. **Zero Configuration**: No code changes needed - works automatically based on environment

## 🔍 Verification Steps

1. Deploy to app.theagencyiq.ai
2. Check server logs for: `🚀 OAUTH PRODUCTION CONFIG: PRODUCTION MODE`
3. Test OAuth flows work with production callback URLs
4. Verify all platform connections function correctly

## 🛡️ Security Features

- Production-only callback URLs prevent development environment access
- Secure session management with production-grade cookies
- Comprehensive error handling and fallback mechanisms
- Zero regression - all existing authentication flows preserved

## 📋 Next Steps

1. Update OAuth application callback URLs (above)
2. Set production environment variables in Replit Secrets
3. Deploy to app.theagencyiq.ai
4. Test social media platform connections

The system is now production-ready with full OAuth support for app.theagencyiq.ai deployment.