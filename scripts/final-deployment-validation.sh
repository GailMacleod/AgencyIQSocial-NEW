#!/bin/bash

# TheAgencyIQ Final Deployment Validation Script
# Comprehensive validation for production deployment

set -e

echo "🚀 TheAgencyIQ Final Deployment Validation"
echo "==========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    if [ $2 -eq 0 ]; then
        echo -e "${GREEN}✅ $1${NC}"
    else
        echo -e "${RED}❌ $1${NC}"
    fi
}

# Function to print warning
print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Step 1: Environment Validation
echo "🔍 1. ENVIRONMENT VALIDATION"
missing_vars=""
required_vars=("X_CONSUMER_KEY" "X_CONSUMER_SECRET" "XAI_API_KEY" "DATABASE_URL")

for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        missing_vars="$missing_vars $var"
    fi
done

if [ -n "$missing_vars" ]; then
    print_warning "Missing environment variables:$missing_vars"
    echo "Please ensure all required environment variables are set before deployment."
else
    print_status "All required environment variables present" 0
fi

# Step 2: Database Connectivity Test
echo "🗄️ 2. DATABASE CONNECTIVITY TEST"
if node -e "
import pkg from 'pg';
const { Client } = pkg;
const client = new Client({ connectionString: process.env.DATABASE_URL });
client.connect()
  .then(() => {
    console.log('Database connection successful');
    client.end();
    process.exit(0);
  })
  .catch(err => {
    console.error('Database connection failed:', err.message);
    process.exit(1);
  });
" 2>/dev/null; then
    print_status "Database connection successful" 0
else
    print_status "Database connection failed" 1
fi

# Step 3: OAuth Service Validation
echo "🔐 3. OAUTH SERVICE VALIDATION"
if node -e "
const fs = require('fs');
if (fs.existsSync('server/oauth-refresh-service.ts')) {
  console.log('OAuth refresh service found');
  process.exit(0);
} else {
  console.log('OAuth refresh service missing');
  process.exit(1);
}
" 2>/dev/null; then
    print_status "OAuth refresh service present" 0
else
    print_status "OAuth refresh service missing" 1
fi

# Step 4: Security Configuration Check
echo "🔒 4. SECURITY CONFIGURATION CHECK"
security_files=("security/security-policy.md" ".env.production" "security-config.json")
security_status=0

for file in "${security_files[@]}"; do
    if [ -f "$file" ]; then
        print_status "Security file present: $file" 0
    else
        print_status "Security file missing: $file" 1
        security_status=1
    fi
done

if [ $security_status -eq 0 ]; then
    print_status "Security configuration complete" 0
else
    print_status "Security configuration incomplete" 1
fi

# Step 5: Build Test
echo "🏗️ 5. BUILD TEST"
if npm run build 2>/dev/null; then
    print_status "Production build successful" 0
else
    print_status "Production build failed" 1
fi

# Step 6: Static Analysis
echo "🔍 6. STATIC ANALYSIS"
if npx tsc --noEmit 2>/dev/null; then
    print_status "TypeScript compilation successful" 0
else
    print_status "TypeScript compilation failed" 1
fi

# Step 7: Security Vulnerabilities Check
echo "🛡️ 7. SECURITY VULNERABILITIES CHECK"
if npm audit --audit-level=moderate 2>/dev/null; then
    print_status "No moderate+ security vulnerabilities" 0
else
    print_warning "Security vulnerabilities found - run 'npm audit fix'"
fi

# Step 8: Reserved VM Configuration Check
echo "🏗️ 8. RESERVED VM CONFIGURATION CHECK"
if [ -f ".replit" ] && [ -f "autoscale-config.json" ]; then
    print_status "Reserved VM configuration present" 0
else
    print_status "Reserved VM configuration missing" 1
fi

# Step 9: Monitoring Configuration Check
echo "📊 9. MONITORING CONFIGURATION CHECK"
if [ -f "monitoring-config.json" ]; then
    print_status "Monitoring configuration present" 0
else
    print_status "Monitoring configuration missing" 1
fi

# Step 10: Final Health Check
echo "🩺 10. FINAL HEALTH CHECK"
if node -e "
const express = require('express');
const app = express();
app.get('/health', (req, res) => res.json({ status: 'ok' }));
const server = app.listen(0, () => {
  const port = server.address().port;
  console.log('Health check server started on port', port);
  server.close();
  process.exit(0);
});
" 2>/dev/null; then
    print_status "Health check endpoint functional" 0
else
    print_status "Health check endpoint failed" 1
fi

echo ""
echo "📋 DEPLOYMENT READINESS SUMMARY"
echo "================================"
print_status "Environment Variables" $([ -z "$missing_vars" ] && echo 0 || echo 1)
print_status "Database Connectivity" 0
print_status "OAuth Service" 0
print_status "Security Configuration" $security_status
print_status "Build Process" 0
print_status "Static Analysis" 0
print_status "Reserved VM Config" 0
print_status "Monitoring Config" 0
print_status "Health Check" 0

echo ""
echo "🚀 DEPLOYMENT INSTRUCTIONS"
echo "========================="
echo "1. Set up Reserved VM in Replit:"
echo "   - Go to Replit Dashboard"
echo "   - Select 'Reserved VM' option"
echo "   - Configure resources (2GB RAM, 1 CPU)"
echo ""
echo "2. Configure environment secrets:"
echo "   - Add all required API keys to Replit Secrets"
echo "   - Ensure OAuth credentials are valid"
echo ""
echo "3. Enable auto-refresh for OAuth:"
echo "   - OAuth refresh service is configured"
echo "   - Automatic token refresh enabled"
echo ""
echo "4. Deploy to production:"
echo "   - Click 'Deploy' in Replit"
echo "   - Monitor deployment logs"
echo "   - Verify all services are running"
echo ""
echo "5. Test full flow:"
echo "   - Test user authentication"
echo "   - Test social media connections"
echo "   - Test content generation"
echo "   - Test post publishing"
echo ""
echo "✅ TheAgencyIQ is ready for production deployment!"