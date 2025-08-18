// SURGICAL FIX 2: Environment validation for deployment
console.log('\n🔍 DEPLOYMENT ENVIRONMENT VALIDATION');
console.log('=====================================');

// Critical environment variables
const requiredVars = [
  'SESSION_SECRET',
  'DATABASE_URL',
  'NODE_ENV'
];

const oauthVars = [
  'FACEBOOK_CLIENT_ID',
  'FACEBOOK_CLIENT_SECRET',
  'LINKEDIN_CLIENT_ID', 
  'LINKEDIN_CLIENT_SECRET',
  'X_CONSUMER_KEY',
  'X_CONSUMER_SECRET'
];

// Validate required variables
console.log('\n📋 Required Environment Variables:');
requiredVars.forEach(varName => {
  const value = process.env[varName];
  if (value) {
    console.log(`✅ ${varName}: ${varName === 'SESSION_SECRET' ? '[HIDDEN]' : value.substring(0, 20) + '...'}`);
  } else {
    console.log(`❌ ${varName}: MISSING`);
  }
});

// Validate OAuth variables
console.log('\n🔐 OAuth Environment Variables:');
oauthVars.forEach(varName => {
  const value = process.env[varName];
  if (value && value !== 'YOUR_' + varName) {
    console.log(`✅ ${varName}: Configured`);
  } else {
    console.log(`⚠️  ${varName}: Not configured or using placeholder`);
  }
});

// Deployment detection
console.log('\n🌍 Deployment Detection:');
console.log(`NODE_ENV: ${process.env.NODE_ENV}`);
console.log(`REPLIT_DEPLOYED: ${process.env.REPLIT_DEPLOYED || 'undefined'}`);
console.log(`REPLIT_DOMAINS: ${process.env.REPLIT_DOMAINS || 'undefined'}`);

const isProd = process.env.REPLIT_DEPLOYED === 'true' || process.env.NODE_ENV === 'production';
console.log(`🎯 Production Mode Detected: ${isProd}`);

// Database validation
console.log('\n💾 Database Configuration:');
if (process.env.DATABASE_URL) {
  try {
    const dbUrl = new URL(process.env.DATABASE_URL);
    console.log(`✅ Database Host: ${dbUrl.hostname}`);
    console.log(`✅ Database Name: ${dbUrl.pathname.substring(1)}`);
    console.log(`✅ Database SSL: ${dbUrl.searchParams.get('sslmode') || 'not specified'}`);
  } catch (error) {
    console.log(`❌ Database URL parsing failed: ${error.message}`);
  }
} else {
  console.log('❌ DATABASE_URL not configured');
}

console.log('\n=====================================\n');

export { isProd };