# Facebook OAuth Configuration Fix

## Issue Identified
The Facebook OAuth redirect error "failed to obtain request token" was caused by inconsistent callback URIs across different OAuth configuration files.

## Root Cause
- Multiple OAuth configurations using different callback paths:
  - `server/oauth-config.ts`: `/auth/facebook/callback`
  - `server/index.ts`: `/callback` 
  - `authModule.ts`: `/auth/facebook/callback`

## Solution Implemented
1. **Unified Callback URI**: All OAuth providers now use `/callback` as the consistent callback path
2. **Updated Facebook OAuth Strategy**: Changed from `/auth/facebook/callback` to `/callback`
3. **Updated All Platforms**: LinkedIn, X, Instagram, YouTube all use `/callback`

## Required Facebook App Settings
To complete the fix, the following must be added to Facebook App Settings:

### App Domains
- Development: `4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev`
- Production: `app.theagencyiq.ai`

### Valid OAuth Redirect URIs
- Development: `https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/callback`
- Production: `https://app.theagencyiq.ai/callback`

### Required Settings
1. **Products > Facebook Login > Settings > Valid OAuth Redirect URIs**
   - Add the callback URLs above
2. **Settings > Basic > App Domains**
   - Add the domains above
3. **Products > Facebook Login > Settings > Client OAuth Settings**
   - Enable "Client OAuth Login"
   - Enable "Web OAuth Login"

## Status
- ✅ Server configuration unified
- ✅ All platforms use consistent `/callback` URI
- ⚠️ Facebook App settings need manual configuration
- ✅ Platform connections restored for User ID 2
- ✅ UI components updated to use unified data structure

## Testing
After Facebook App settings are updated, test OAuth flow:
1. Navigate to connect-platforms page
2. Click "Reconnect" for Facebook
3. OAuth popup should work without redirect errors
4. Connection status should sync across all pages