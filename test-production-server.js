/**
 * Production Server Test - Real Database Integration
 * Tests auto-posting with actual database connections and quota validation
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🚀 Testing TheAgencyIQ Production Server with Real Database...');

// Start the production server
const server = spawn('node', ['server/production-server.js'], {
  cwd: __dirname,
  stdio: 'pipe',
  env: {
    ...process.env,
    NODE_ENV: 'production'
  }
});

let serverOutput = '';
server.stdout.on('data', (data) => {
  serverOutput += data.toString();
  console.log('Server:', data.toString().trim());
});

server.stderr.on('data', (data) => {
  console.error('Server Error:', data.toString().trim());
});

// Wait for server to start
setTimeout(async () => {
  console.log('\n📋 Testing Production API endpoints...');
  
  const tests = [
    {
      name: 'Health Check',
      url: 'http://localhost:5000/api/health',
      method: 'GET',
      expected: 'database connection status'
    },
    {
      name: 'User Status (Real Data)',
      url: 'http://localhost:5000/api/user-status',
      method: 'GET',
      expected: 'actual subscription and quota info'
    },
    {
      name: 'Subscription Usage (Real Data)',
      url: 'http://localhost:5000/api/subscription-usage',
      method: 'GET',
      expected: 'actual post counts from database'
    },
    {
      name: 'Posts List (Real Data)',
      url: 'http://localhost:5000/api/posts',
      method: 'GET',
      expected: 'actual posts from database'
    },
    {
      name: 'Auto-Posting Enforcer (Real Processing)',
      url: 'http://localhost:5000/api/enforce-auto-posting',
      method: 'POST',
      expected: 'actual database updates'
    }
  ];

  console.log('\n📊 Production Test Results:');
  console.log('=' + '='.repeat(70));
  
  let passedTests = 0;
  let totalTests = tests.length;
  let criticalFindings = [];
  
  for (const test of tests) {
    try {
      const response = await fetch(test.url, {
        method: test.method,
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      const data = await response.json();
      
      if (response.ok) {
        console.log(`✅ ${test.name}: PASSED`);
        
        // Analyze critical data
        if (test.name === 'Health Check') {
          console.log(`   Database: ${data.database}`);
          if (data.database === 'disconnected') {
            criticalFindings.push('Database connection failed');
          }
        }
        
        if (test.name === 'User Status (Real Data)') {
          console.log(`   User: ${data.userEmail}`);
          console.log(`   Subscription: ${data.user.subscriptionPlan}`);
          console.log(`   Active: ${data.user.subscriptionActive}`);
          console.log(`   Remaining Posts: ${data.user.remainingPosts}/${data.user.totalPosts}`);
          console.log(`   Days Remaining: ${data.user.daysRemaining}`);
          
          if (!data.user.subscriptionActive) {
            criticalFindings.push('Subscription not active');
          }
          if (data.user.remainingPosts === 0) {
            criticalFindings.push('No remaining posts in quota');
          }
        }
        
        if (test.name === 'Subscription Usage (Real Data)') {
          console.log(`   Total Allocation: ${data.totalAllocation}`);
          console.log(`   Used Posts: ${data.usedPosts}`);
          console.log(`   Published: ${data.publishedPosts}`);
          console.log(`   Failed: ${data.failedPosts}`);
          console.log(`   Approved: ${data.approvedPosts}`);
          console.log(`   Draft: ${data.draftPosts}`);
          console.log(`   Usage: ${data.usagePercentage}%`);
          console.log(`   Period Valid: ${data.subscriptionPeriodValid}`);
          
          if (!data.subscriptionPeriodValid) {
            criticalFindings.push('Subscription period expired');
          }
        }
        
        if (test.name === 'Posts List (Real Data)') {
          console.log(`   Total Posts: ${data.length}`);
          const published = data.filter(p => p.status === 'published').length;
          const approved = data.filter(p => p.status === 'approved').length;
          const failed = data.filter(p => p.status === 'failed').length;
          console.log(`   Published: ${published}, Approved: ${approved}, Failed: ${failed}`);
          
          if (published === 0 && approved === 0) {
            criticalFindings.push('No posts available for publishing');
          }
        }
        
        if (test.name === 'Auto-Posting Enforcer (Real Processing)') {
          console.log(`   Posts Processed: ${data.postsProcessed}`);
          console.log(`   Posts Published: ${data.postsPublished}`);
          console.log(`   Posts Failed: ${data.postsFailed}`);
          console.log(`   Success: ${data.success}`);
          console.log(`   Errors: ${data.errors.length}`);
          
          if (data.errors.length > 0) {
            console.log(`   Error Details: ${data.errors.join(', ')}`);
            criticalFindings.push(...data.errors);
          }
          
          if (data.postsPublished === 0 && data.postsProcessed > 0) {
            criticalFindings.push('No posts successfully published');
          }
        }
        
        passedTests++;
      } else {
        console.log(`❌ ${test.name}: FAILED (${response.status})`);
        console.log(`   Error: ${data.error || data.message || 'Unknown error'}`);
        criticalFindings.push(`${test.name} failed: ${data.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.log(`❌ ${test.name}: FAILED (Connection Error)`);
      console.log(`   Error: ${error.message}`);
      criticalFindings.push(`${test.name} connection failed: ${error.message}`);
    }
  }
  
  console.log('=' + '='.repeat(70));
  console.log(`📈 Production Test Summary: ${passedTests}/${totalTests} tests passed`);
  
  // Critical findings analysis
  console.log('\n🔍 Critical Findings:');
  if (criticalFindings.length === 0) {
    console.log('✅ No critical issues found - system operational');
  } else {
    console.log(`❌ ${criticalFindings.length} critical issues found:`);
    criticalFindings.forEach((finding, index) => {
      console.log(`   ${index + 1}. ${finding}`);
    });
  }
  
  // Resolution recommendations
  console.log('\n🛠️  Resolution Recommendations:');
  if (criticalFindings.includes('Database connection failed')) {
    console.log('• Fix PostgreSQL connection - check DATABASE_URL environment variable');
  }
  if (criticalFindings.includes('Subscription not active')) {
    console.log('• Activate subscription in database or Stripe');
  }
  if (criticalFindings.includes('Subscription period expired')) {
    console.log('• Renew subscription or extend subscription period');
  }
  if (criticalFindings.includes('No remaining posts in quota')) {
    console.log('• Reset quota or upgrade subscription plan');
  }
  if (criticalFindings.includes('No posts available for publishing')) {
    console.log('• Create approved posts or check post status in database');
  }
  if (criticalFindings.some(f => f.includes('No posts successfully published'))) {
    console.log('• Check OAuth connections and platform API status');
  }
  
  console.log('\n📊 System Status:');
  if (passedTests === totalTests && criticalFindings.length === 0) {
    console.log('🎉 PRODUCTION READY - All systems operational!');
  } else if (passedTests >= totalTests * 0.8) {
    console.log('⚠️  PARTIALLY OPERATIONAL - Some issues need attention');
  } else {
    console.log('❌ SYSTEM FAILURE - Critical issues must be resolved');
  }
  
  // Kill server and exit
  server.kill();
  process.exit(0);
  
}, 3000);

// Handle server startup errors
server.on('error', (error) => {
  console.error('❌ Failed to start production server:', error.message);
  process.exit(1);
});

server.on('exit', (code) => {
  if (code !== 0) {
    console.error(`❌ Production server exited with code ${code}`);
  }
});