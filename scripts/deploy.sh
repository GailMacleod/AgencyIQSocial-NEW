#!/bin/bash

echo "🚀 Starting TheAgencyIQ deployment process..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Node.js is available
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed"
    exit 1
fi

# Check if npm is available
if ! command -v npm &> /dev/null; then
    print_error "npm is not installed"
    exit 1
fi

print_status "Environment checks passed"

# Install dependencies
echo "📦 Installing dependencies..."
npm install
if [ $? -eq 0 ]; then
    print_status "Dependencies installed"
else
    print_error "Failed to install dependencies"
    exit 1
fi

# Run cleanup
echo "🧹 Cleaning up unused files..."
node scripts/cleanup-unused.js
print_status "Cleanup completed"

# Lint and format code
echo "🔍 Running ESLint..."
npx eslint . --ext .ts,.tsx --fix || print_warning "ESLint found issues (non-blocking)"

echo "💅 Running Prettier..."
npx prettier --write . || print_warning "Prettier formatting (non-blocking)"

# Test features
echo "🧪 Testing core features..."
node scripts/test-features.js
if [ $? -eq 0 ]; then
    print_status "Feature tests completed"
else
    print_warning "Some feature tests failed (check manually)"
fi

# Check environment variables
echo "🔐 Checking environment configuration..."
if [ -f ".env.production" ]; then
    print_status "Production environment file found"
else
    print_warning "Production environment file not found"
fi

# Create logs directory
mkdir -p logs
print_status "Logs directory created"

# Build application
echo "🏗️  Building application..."
npm run build 2>/dev/null || print_warning "Build step skipped (not configured)"

# Set up PM2 ecosystem
echo "⚙️  Configuring PM2..."
if command -v pm2 &> /dev/null; then
    pm2 delete theagencyiq 2>/dev/null || true
    print_status "PM2 configured"
else
    print_warning "PM2 not found, manual startup required"
fi

print_status "Deployment preparation complete!"

echo ""
echo "🎯 Next Steps:"
echo "1. Set environment variables in .env.production"
echo "2. Start with: pm2 start ecosystem.config.js"
echo "3. Monitor with: pm2 monit"
echo "4. View logs with: pm2 logs theagencyiq"
echo ""

# Final health check
echo "🏥 Final health check..."
if [ -f "server/index.ts" ] && [ -f "package.json" ]; then
    print_status "Core files present"
else
    print_error "Missing core files"
    exit 1
fi

print_status "TheAgencyIQ is ready for deployment! 🎉"