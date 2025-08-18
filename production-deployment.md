# TheAgencyIQ Production Deployment Guide

## Current Issue
The domain `app.theagencyiq.ai` is returning HTTP 500 Internal Server Error because the production environment is not properly configured.

## Root Cause Analysis
1. **Domain Configuration**: The domain resolves to Google Cloud (34.111.179.208) but the server isn't running correctly
2. **Environment Variables**: Production environment may be missing required environment variables
3. **Server Configuration**: The server is configured for development, not production deployment
4. **Build Process**: The application may need to be built for production

## Production Deployment Steps

### 1. Environment Configuration
Ensure these environment variables are set in production:
```bash
NODE_ENV=production
PORT=8080
DATABASE_URL=postgresql://...
FB_CLIENT_ID=1409057863445071
FB_CLIENT_SECRET=your_secret_here
SESSION_SECRET=your_session_secret
GOOGLE_CLIENT_ID=your_google_client_id
LINKEDIN_CLIENT_ID=86pwc38hsqem
X_CLIENT_ID=your_x_client_id
```

### 2. Build the Application
```bash
npm run build
```

### 3. Production Server Start
```bash
node start-production.js
```

## Recommended Fixes

### Option A: Use Replit Deployments
1. Click the "Deploy" button in Replit
2. Configure the production domain
3. Set environment variables in deployment settings

### Option B: Fix Current Production Server
1. Check server logs on the production environment
2. Ensure all dependencies are installed
3. Verify environment variables are properly set
4. Update server configuration for production

## Immediate Actions Needed
1. Identify the current production hosting platform (appears to be Google Cloud)
2. Access the production server logs to see specific error messages
3. Verify environment variables are properly configured
4. Ensure the server is starting correctly with production settings

## Testing Commands
```bash
# Test health endpoint
curl https://app.theagencyiq.ai/health

# Test with verbose output
curl -v https://app.theagencyiq.ai

# Check server response headers
curl -I https://app.theagencyiq.ai
```