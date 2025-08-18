/**
 * Final Production Test - Resolve Auto-Posting Contradiction
 * Tests real database operations and resolves the discrepancy between
 * test results showing "3/3 posts published" vs user seeing "0 successful posts"
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🔍 RESOLVING AUTO-POSTING CONTRADICTION');
console.log('Testing final production server with real database...');

// Start the final production server
const server = spawn('node', ['server/final-production-server.js'], {
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
  console.log('\n📊 CONTRADICTION ANALYSIS - Before Auto-Posting');
  console.log('=' + '='.repeat(60));
  
  try {
    // Get initial state
    const initialUsage = await fetch('http://localhost:5000/api/subscription-usage');
    const initialUsageData = await initialUsage.json();
    
    const initialPosts = await fetch('http://localhost:5000/api/posts');
    const initialPostsData = await initialPosts.json();
    
    console.log('📈 INITIAL STATE:');
    console.log(`   Published Posts: ${initialUsageData.publishedPosts}`);
    console.log(`   Approved Posts: ${initialUsageData.approvedPosts}`);
    console.log(`   Failed Posts: ${initialUsageData.failedPosts}`);
    console.log(`   Draft Posts: ${initialUsageData.draftPosts}`);
    console.log(`   Remaining Quota: ${initialUsageData.remainingPosts}/${initialUsageData.totalAllocation}`);
    console.log(`   Usage: ${initialUsageData.usagePercentage}%`);
    console.log(`   Subscription Active: ${initialUsageData.subscriptionActive}`);
    console.log(`   Period Valid: ${initialUsageData.subscriptionPeriodValid}`);
    console.log(`   Days Remaining: ${initialUsageData.daysRemaining}`);
    
    // Execute auto-posting enforcer
    console.log('\n🚀 EXECUTING AUTO-POSTING ENFORCER');
    console.log('=' + '='.repeat(60));
    
    const autoPostResponse = await fetch('http://localhost:5000/api/enforce-auto-posting', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    const autoPostResult = await autoPostResponse.json();
    
    console.log('📊 AUTO-POSTING RESULTS:');
    console.log(`   Success: ${autoPostResult.success}`);
    console.log(`   Posts Processed: ${autoPostResult.postsProcessed}`);
    console.log(`   Posts Published: ${autoPostResult.postsPublished}`);
    console.log(`   Posts Failed: ${autoPostResult.postsFailed}`);
    console.log(`   Errors: ${autoPostResult.errors.length}`);
    
    if (autoPostResult.errors.length > 0) {
      console.log('   Error Details:');
      autoPostResult.errors.forEach((error, index) => {
        console.log(`     ${index + 1}. ${error}`);
      });
    }
    
    if (autoPostResult.connectionRepairs.length > 0) {
      console.log('   Connection Repairs:');
      autoPostResult.connectionRepairs.forEach((repair, index) => {
        console.log(`     ${index + 1}. ${repair}`);
      });
    }
    
    // Get final state
    console.log('\n📊 CONTRADICTION ANALYSIS - After Auto-Posting');
    console.log('=' + '='.repeat(60));
    
    const finalUsage = await fetch('http://localhost:5000/api/subscription-usage');
    const finalUsageData = await finalUsage.json();
    
    const finalPosts = await fetch('http://localhost:5000/api/posts');
    const finalPostsData = await finalPosts.json();
    
    console.log('📈 FINAL STATE:');
    console.log(`   Published Posts: ${finalUsageData.publishedPosts}`);
    console.log(`   Approved Posts: ${finalUsageData.approvedPosts}`);
    console.log(`   Failed Posts: ${finalUsageData.failedPosts}`);
    console.log(`   Draft Posts: ${finalUsageData.draftPosts}`);
    console.log(`   Remaining Quota: ${finalUsageData.remainingPosts}/${finalUsageData.totalAllocation}`);
    console.log(`   Usage: ${finalUsageData.usagePercentage}%`);
    
    // Calculate changes
    const publishedChange = finalUsageData.publishedPosts - initialUsageData.publishedPosts;
    const approvedChange = finalUsageData.approvedPosts - initialUsageData.approvedPosts;
    const failedChange = finalUsageData.failedPosts - initialUsageData.failedPosts;
    
    console.log('\n📊 CHANGES ANALYSIS:');
    console.log(`   Published Posts Change: ${publishedChange > 0 ? '+' : ''}${publishedChange}`);
    console.log(`   Approved Posts Change: ${approvedChange > 0 ? '+' : ''}${approvedChange}`);
    console.log(`   Failed Posts Change: ${failedChange > 0 ? '+' : ''}${failedChange}`);
    
    // Contradiction resolution
    console.log('\n🔍 CONTRADICTION RESOLUTION:');
    console.log('=' + '='.repeat(60));
    
    if (autoPostResult.success && autoPostResult.postsPublished > 0) {
      if (publishedChange > 0) {
        console.log('✅ RESOLVED: Auto-posting is working correctly!');
        console.log(`   ${autoPostResult.postsPublished} posts were successfully published`);
        console.log(`   Database reflects ${publishedChange} new published posts`);
        console.log('   The contradiction was due to previous testing with mock data');
      } else {
        console.log('❌ CONTRADICTION PERSISTS: Auto-posting claims success but database unchanged');
        console.log('   This indicates a database update issue or transaction rollback');
      }
    } else {
      console.log('❌ AUTO-POSTING FAILED: No posts were published');
      console.log('   This explains the user\'s experience of "0 successful posts"');
    }
    
    // Root cause analysis
    console.log('\n🔍 ROOT CAUSE ANALYSIS:');
    console.log('=' + '='.repeat(60));
    
    if (autoPostResult.errors.length > 0) {
      console.log('Issues found:');
      autoPostResult.errors.forEach((error, index) => {
        console.log(`   ${index + 1}. ${error}`);
      });
    }
    
    // User experience summary
    console.log('\n📊 USER EXPERIENCE SUMMARY:');
    console.log('=' + '='.repeat(60));
    
    const userExperience = {
      currentState: `${finalUsageData.publishedPosts} published posts out of ${finalUsageData.totalAllocation} allocated`,
      quotaRemaining: `${finalUsageData.remainingPosts} posts remaining`,
      subscriptionValid: finalUsageData.subscriptionPeriodValid,
      daysLeft: finalUsageData.daysRemaining,
      canPublish: finalUsageData.subscriptionActive && finalUsageData.remainingPosts > 0,
      autoPostingWorking: autoPostResult.success && publishedChange > 0
    };
    
    console.log(`   Current State: ${userExperience.currentState}`);
    console.log(`   Quota Remaining: ${userExperience.quotaRemaining}`);
    console.log(`   Subscription Valid: ${userExperience.subscriptionValid}`);
    console.log(`   Days Left: ${userExperience.daysLeft}`);
    console.log(`   Can Publish: ${userExperience.canPublish}`);
    console.log(`   Auto-Posting Working: ${userExperience.autoPostingWorking}`);
    
    // Recommendations
    console.log('\n🛠️  RECOMMENDATIONS:');
    console.log('=' + '='.repeat(60));
    
    if (userExperience.autoPostingWorking) {
      console.log('✅ System is working correctly - run auto-posting enforcer regularly');
    } else {
      console.log('❌ Auto-posting needs fixing:');
      console.log('   1. Check OAuth platform connections');
      console.log('   2. Verify subscription period validity');
      console.log('   3. Ensure approved posts exist in database');
      console.log('   4. Test individual platform publishing');
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }
  
  // Kill server and exit
  server.kill();
  process.exit(0);
  
}, 3000);

// Handle server startup errors
server.on('error', (error) => {
  console.error('❌ Failed to start final production server:', error.message);
  process.exit(1);
});

server.on('exit', (code) => {
  if (code !== 0) {
    console.error(`❌ Final production server exited with code ${code}`);
  }
});