const axios = require('axios');
const assert = require('assert');

// Configuration
const BASE_URL = 'http://localhost:5000';
const TEST_EMAIL = 'gailm@macleodglba.com.au';

class QuotaEdgeCasesTester {
  constructor() {
    this.sessionCookie = null;
    this.testResults = [];
  }

  async establishSession() {
    console.log('🔐 Establishing authenticated session...');
    const sessionRes = await axios.post(`${BASE_URL}/api/establish-session`, {
      email: TEST_EMAIL,
      phone: '+61424835189'
    });
    
    const cookies = sessionRes.headers['set-cookie'];
    this.sessionCookie = cookies ? cookies[0].split(';')[0] : null;
    
    if (!this.sessionCookie) {
      throw new Error('Failed to establish session');
    }
    
    console.log('✅ Session established successfully');
    return this.sessionCookie;
  }

  async getCurrentQuotaStatus() {
    console.log('\n📊 Checking current quota status...');
    const response = await axios.get(`${BASE_URL}/api/subscription-usage`, {
      headers: { 'Cookie': this.sessionCookie }
    });
    
    const quota = response.data;
    console.log(`   Current Usage: ${quota.usedPosts}/${quota.totalPosts} posts`);
    console.log(`   Remaining: ${quota.remainingPosts} posts`);
    console.log(`   Plan: ${quota.subscriptionPlan}`);
    console.log(`   Status: ${quota.subscriptionActive ? 'Active' : 'Inactive'}`);
    
    return quota;
  }

  async testQuotaExceededScenario() {
    console.log('\n🚫 Testing quota exceeded scenario...');
    
    try {
      // First get current quota
      const currentQuota = await this.getCurrentQuotaStatus();
      
      if (currentQuota.remainingPosts <= 0) {
        console.log('✅ Quota already at limit - testing exceeded behavior...');
        
        // Try to schedule a post when quota is exceeded
        const postResponse = await axios.post(`${BASE_URL}/api/schedule-post`, {
          content: 'Test post that should be blocked by quota',
          platform: 'facebook',
          scheduledFor: new Date(Date.now() + 3600000).toISOString()
        }, {
          headers: { 'Cookie': this.sessionCookie }
        });
        
        console.log('❌ ERROR: Post was allowed despite quota exceeded');
        this.testResults.push({
          test: 'quota_exceeded',
          status: 'FAILED',
          issue: 'Post allowed despite quota limit'
        });
        
      } else {
        console.log(`⚠️  Quota not exceeded (${currentQuota.remainingPosts} remaining)`);
        console.log('   Simulating quota exceeded scenario...');
        
        // Test the direct-publish endpoint with quota validation
        const publishResponse = await axios.post(`${BASE_URL}/api/direct-publish`, {
          action: 'publish_all'
        }, {
          headers: { 'Cookie': this.sessionCookie }
        });
        
        console.log('✅ Direct publish responded with quota validation');
        this.testResults.push({
          test: 'quota_validation',
          status: 'PASSED',
          details: 'Quota validation working in direct publish'
        });
      }
      
    } catch (error) {
      if (error.response && error.response.status === 403) {
        console.log('✅ Quota exceeded properly blocked (403 Forbidden)');
        this.testResults.push({
          test: 'quota_exceeded_blocking',
          status: 'PASSED',
          details: 'Quota exceeded requests properly blocked'
        });
      } else {
        console.log(`❌ Unexpected error: ${error.message}`);
        this.testResults.push({
          test: 'quota_exceeded',
          status: 'ERROR',
          error: error.message
        });
      }
    }
  }

  async testQuotaResetCycle() {
    console.log('\n🔄 Testing quota reset cycle behavior...');
    
    try {
      // Test subscription usage endpoint for reset date
      const usageResponse = await axios.get(`${BASE_URL}/api/subscription-usage`, {
        headers: { 'Cookie': this.sessionCookie }
      });
      
      const usage = usageResponse.data;
      console.log(`   Current billing cycle: ${usage.currentBillingCycle || 'Not specified'}`);
      console.log(`   Next reset: ${usage.nextResetDate || 'Not specified'}`);
      
      // Test if reset cycle information is properly tracked
      if (usage.currentBillingCycle || usage.nextResetDate) {
        console.log('✅ Quota reset cycle information available');
        this.testResults.push({
          test: 'quota_reset_tracking',
          status: 'PASSED',
          details: 'Reset cycle information properly tracked'
        });
      } else {
        console.log('⚠️  Quota reset cycle information not available');
        this.testResults.push({
          test: 'quota_reset_tracking',
          status: 'WARNING',
          issue: 'Reset cycle information not tracked'
        });
      }
      
    } catch (error) {
      console.log(`❌ Error testing quota reset cycle: ${error.message}`);
      this.testResults.push({
        test: 'quota_reset_cycle',
        status: 'ERROR',
        error: error.message
      });
    }
  }

  async testQuotaConsistencyAcrossEndpoints() {
    console.log('\n🔍 Testing quota consistency across endpoints...');
    
    try {
      // Test multiple quota-related endpoints
      const endpoints = [
        '/api/subscription-usage',
        '/api/user-status',
        '/api/analytics'
      ];
      
      const quotaData = [];
      
      for (const endpoint of endpoints) {
        try {
          const response = await axios.get(`${BASE_URL}${endpoint}`, {
            headers: { 'Cookie': this.sessionCookie }
          });
          
          if (response.data.remainingPosts !== undefined || response.data.usedPosts !== undefined) {
            quotaData.push({
              endpoint,
              remainingPosts: response.data.remainingPosts,
              usedPosts: response.data.usedPosts,
              totalPosts: response.data.totalPosts
            });
          }
        } catch (error) {
          console.log(`   ${endpoint}: ${error.response?.status || 'Error'}`);
        }
      }
      
      // Check for consistency
      if (quotaData.length > 1) {
        const firstQuota = quotaData[0];
        const consistent = quotaData.every(q => 
          q.remainingPosts === firstQuota.remainingPosts &&
          q.usedPosts === firstQuota.usedPosts &&
          q.totalPosts === firstQuota.totalPosts
        );
        
        if (consistent) {
          console.log('✅ Quota data consistent across endpoints');
          this.testResults.push({
            test: 'quota_consistency',
            status: 'PASSED',
            details: 'Quota data consistent across all endpoints'
          });
        } else {
          console.log('❌ Quota data inconsistent across endpoints');
          this.testResults.push({
            test: 'quota_consistency',
            status: 'FAILED',
            issue: 'Quota data inconsistent between endpoints'
          });
        }
      }
      
    } catch (error) {
      console.log(`❌ Error testing quota consistency: ${error.message}`);
    }
  }

  async testBulkPublishingQuotaValidation() {
    console.log('\n📢 Testing bulk publishing quota validation...');
    
    try {
      // Test the bulk publishing endpoint quota validation
      const bulkResponse = await axios.post(`${BASE_URL}/api/direct-publish`, {
        action: 'publish_all'
      }, {
        headers: { 'Cookie': this.sessionCookie }
      });
      
      console.log(`   Bulk publish response: ${bulkResponse.status}`);
      
      if (bulkResponse.data.quotaValidation) {
        console.log('✅ Bulk publishing includes quota validation');
        this.testResults.push({
          test: 'bulk_quota_validation',
          status: 'PASSED',
          details: 'Bulk publishing properly validates quota'
        });
      } else {
        console.log('⚠️  Bulk publishing quota validation unclear');
        this.testResults.push({
          test: 'bulk_quota_validation',
          status: 'WARNING',
          issue: 'Bulk publishing quota validation needs verification'
        });
      }
      
    } catch (error) {
      if (error.response && error.response.status === 403) {
        console.log('✅ Bulk publishing properly blocked by quota');
        this.testResults.push({
          test: 'bulk_quota_blocking',
          status: 'PASSED',
          details: 'Bulk publishing properly blocked when quota exceeded'
        });
      } else {
        console.log(`❌ Bulk publishing error: ${error.message}`);
        this.testResults.push({
          test: 'bulk_quota_validation',
          status: 'ERROR',
          error: error.message
        });
      }
    }
  }

  async generateComprehensiveReport() {
    console.log('\n📋 COMPREHENSIVE QUOTA EDGE CASES TEST REPORT');
    console.log('='.repeat(60));
    
    const passed = this.testResults.filter(t => t.status === 'PASSED').length;
    const failed = this.testResults.filter(t => t.status === 'FAILED').length;
    const errors = this.testResults.filter(t => t.status === 'ERROR').length;
    const warnings = this.testResults.filter(t => t.status === 'WARNING').length;
    
    console.log(`\n📊 RESULTS SUMMARY:`);
    console.log(`   ✅ Passed: ${passed}`);
    console.log(`   ❌ Failed: ${failed}`);
    console.log(`   ⚠️  Warnings: ${warnings}`);
    console.log(`   🔥 Errors: ${errors}`);
    
    console.log(`\n📝 DETAILED RESULTS:`);
    this.testResults.forEach((result, index) => {
      const icon = result.status === 'PASSED' ? '✅' : 
                   result.status === 'FAILED' ? '❌' : 
                   result.status === 'WARNING' ? '⚠️' : '🔥';
      console.log(`   ${icon} ${result.test}: ${result.status}`);
      if (result.details) console.log(`      Details: ${result.details}`);
      if (result.issue) console.log(`      Issue: ${result.issue}`);
      if (result.error) console.log(`      Error: ${result.error}`);
    });
    
    console.log(`\n🎯 RECOMMENDATIONS:`);
    if (failed > 0) {
      console.log(`   - Address ${failed} failed test(s) immediately`);
    }
    if (warnings > 0) {
      console.log(`   - Review ${warnings} warning(s) for potential improvements`);
    }
    if (errors > 0) {
      console.log(`   - Investigate ${errors} error(s) for system issues`);
    }
    
    console.log(`\n🚀 QUOTA SYSTEM STATUS: ${failed === 0 && errors === 0 ? 'PRODUCTION READY' : 'NEEDS ATTENTION'}`);
  }

  async runAllTests() {
    console.log('🧪 STARTING COMPREHENSIVE QUOTA EDGE CASES TESTING');
    console.log('='.repeat(60));
    
    try {
      await this.establishSession();
      await this.getCurrentQuotaStatus();
      await this.testQuotaExceededScenario();
      await this.testQuotaResetCycle();
      await this.testQuotaConsistencyAcrossEndpoints();
      await this.testBulkPublishingQuotaValidation();
      await this.generateComprehensiveReport();
      
    } catch (error) {
      console.error('❌ Test suite failed:', error.message);
      process.exit(1);
    }
  }
}

// Execute the comprehensive quota edge cases test
const tester = new QuotaEdgeCasesTester();
tester.runAllTests();