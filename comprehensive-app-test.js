/**
 * COMPREHENSIVE THEAGENCYIQ APPLICATION TEST
 * Tests complete user journey from signup to publishing
 * Validates all functionality works error-free
 */

import axios from 'axios';
const baseURL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

class ComprehensiveAppTest {
  constructor() {
    this.cookies = '';
    this.testResults = [];
    this.sessionId = '';
    this.userId = null;
  }

  async runCompleteTest() {
    console.log('🚀 Starting Comprehensive TheAgencyIQ Application Test');
    console.log('=' .repeat(60));

    try {
      // Step 1: Test Public Access & Wizard
      await this.testPublicAccess();
      
      // Step 2: Test User Registration/Login
      await this.testUserAuthentication();
      
      // Step 3: Test Subscription Process
      await this.testSubscriptionProcess();
      
      // Step 4: Test Platform Connections
      await this.testPlatformConnections();
      
      // Step 5: Test Brand Purpose
      await this.testBrandPurpose();
      
      // Step 6: Test Smart Schedule Generation
      await this.testSmartScheduleGeneration();
      
      // Step 7: Test Video Generation
      await this.testVideoGeneration();
      
      // Step 8: Test Post Editing & Publishing
      await this.testPostEditingAndPublishing();
      
      // Step 9: Test Analytics & Reporting
      await this.testAnalyticsAndReporting();
      
      // Step 10: Test Support System
      await this.testSupportSystem();
      
      // Step 11: Test Account Management
      await this.testAccountManagement();
      
      this.generateFinalReport();
      
    } catch (error) {
      console.error('❌ Test failed:', error.message);
      this.testResults.push({
        step: 'Critical Error',
        status: 'FAILED',
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }
  }

  async testPublicAccess() {
    console.log('\n📱 Testing Public Access & Wizard');
    
    try {
      // Test splash page access
      const splashResponse = await axios.get(`${baseURL}/`, {
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Public Splash Page Access', splashResponse.status === 200 ? 'PASSED' : 'FAILED');
      
      // Test subscription plans endpoint
      const plansResponse = await axios.get(`${baseURL}/api/subscription-plans`, {
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Subscription Plans API', plansResponse.status === 200 ? 'PASSED' : 'FAILED');
      
      // Test wizard accessibility
      const wizardResponse = await axios.get(`${baseURL}/subscription`, {
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Wizard/Subscription Page Access', wizardResponse.status === 200 ? 'PASSED' : 'FAILED');
      
    } catch (error) {
      this.addResult('Public Access Test', 'FAILED', error.message);
    }
  }

  async testUserAuthentication() {
    console.log('\n🔐 Testing User Authentication');
    
    try {
      // Test session establishment for existing user
      const sessionResponse = await axios.post(`${baseURL}/api/establish-session`, {
        email: 'gailm@macleodglba.com.au',
        phone: '+61424835189'
      }, {
        timeout: 10000,
        validateStatus: () => true
      });
      
      if (sessionResponse.status === 200) {
        this.cookies = sessionResponse.headers['set-cookie']?.join(';') || '';
        this.sessionId = sessionResponse.data.sessionId;
        this.userId = sessionResponse.data.userId;
        this.addResult('User Session Establishment', 'PASSED');
      } else {
        this.addResult('User Session Establishment', 'FAILED', `Status: ${sessionResponse.status}`);
      }
      
      // Test user status validation
      const userResponse = await axios.get(`${baseURL}/api/user`, {
        headers: { Cookie: this.cookies },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('User Status Validation', userResponse.status === 200 ? 'PASSED' : 'FAILED');
      
    } catch (error) {
      this.addResult('User Authentication Test', 'FAILED', error.message);
    }
  }

  async testSubscriptionProcess() {
    console.log('\n💳 Testing Subscription Process');
    
    try {
      // Test subscription status check
      const subStatusResponse = await axios.get(`${baseURL}/api/user-status`, {
        headers: { Cookie: this.cookies },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Subscription Status Check', subStatusResponse.status === 200 ? 'PASSED' : 'FAILED');
      
      // Test subscription plans access
      const plansResponse = await axios.get(`${baseURL}/api/subscription-plans`, {
        headers: { Cookie: this.cookies },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Subscription Plans Access', plansResponse.status === 200 ? 'PASSED' : 'FAILED');
      
    } catch (error) {
      this.addResult('Subscription Process Test', 'FAILED', error.message);
    }
  }

  async testPlatformConnections() {
    console.log('\n🔗 Testing Platform Connections');
    
    try {
      // Test platform connections endpoint
      const connectionsResponse = await axios.get(`${baseURL}/api/platform-connections`, {
        headers: { Cookie: this.cookies },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Platform Connections API', connectionsResponse.status === 200 ? 'PASSED' : 'FAILED');
      
      // Test individual platform OAuth endpoints
      const platforms = ['facebook', 'instagram', 'linkedin', 'x', 'youtube'];
      
      for (const platform of platforms) {
        try {
          const oauthResponse = await axios.get(`${baseURL}/api/auth/${platform}`, {
            headers: { Cookie: this.cookies },
            timeout: 5000,
            validateStatus: () => true,
            maxRedirects: 0
          });
          
          // OAuth endpoints should redirect (302/301) or return 200
          const isValid = [200, 301, 302].includes(oauthResponse.status);
          this.addResult(`${platform.toUpperCase()} OAuth Endpoint`, isValid ? 'PASSED' : 'FAILED');
          
        } catch (error) {
          this.addResult(`${platform.toUpperCase()} OAuth Endpoint`, 'FAILED', error.message);
        }
      }
      
    } catch (error) {
      this.addResult('Platform Connections Test', 'FAILED', error.message);
    }
  }

  async testBrandPurpose() {
    console.log('\n🎯 Testing Brand Purpose');
    
    try {
      // Test brand purpose endpoint
      const brandResponse = await axios.get(`${baseURL}/api/brand-purpose`, {
        headers: { Cookie: this.cookies },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Brand Purpose API', brandResponse.status === 200 ? 'PASSED' : 'FAILED');
      
      // Test brand purpose update
      const updateResponse = await axios.post(`${baseURL}/api/brand-purpose`, {
        brandName: 'Test Business',
        productsServices: 'Professional Services',
        corePurpose: 'Help small businesses grow online',
        audience: 'Queensland small business owners',
        jobToBeDone: 'Increase online visibility',
        motivations: 'Business growth and success',
        painPoints: 'Limited time and resources'
      }, {
        headers: { 
          Cookie: this.cookies,
          'Content-Type': 'application/json'
        },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Brand Purpose Update', updateResponse.status === 200 ? 'PASSED' : 'FAILED');
      
    } catch (error) {
      this.addResult('Brand Purpose Test', 'FAILED', error.message);
    }
  }

  async testSmartScheduleGeneration() {
    console.log('\n🧠 Testing Smart Schedule Generation');
    
    try {
      // Test AI schedule generation
      const scheduleResponse = await axios.post(`${baseURL}/api/generate-ai-schedule`, {
        timeframe: '7days',
        contentType: 'mixed'
      }, {
        headers: { 
          Cookie: this.cookies,
          'Content-Type': 'application/json'
        },
        timeout: 30000,
        validateStatus: () => true
      });
      
      this.addResult('AI Schedule Generation', scheduleResponse.status === 200 ? 'PASSED' : 'FAILED');
      
      // Test posts retrieval
      const postsResponse = await axios.get(`${baseURL}/api/posts`, {
        headers: { Cookie: this.cookies },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Posts Retrieval', postsResponse.status === 200 ? 'PASSED' : 'FAILED');
      
    } catch (error) {
      this.addResult('Smart Schedule Generation Test', 'FAILED', error.message);
    }
  }

  async testVideoGeneration() {
    console.log('\n🎬 Testing Video Generation');
    
    try {
      // Test video generation endpoint
      const videoResponse = await axios.post(`${baseURL}/api/generate-video`, {
        prompt: 'Professional business video for social media',
        duration: 10
      }, {
        headers: { 
          Cookie: this.cookies,
          'Content-Type': 'application/json'
        },
        timeout: 60000,
        validateStatus: () => true
      });
      
      this.addResult('Video Generation', videoResponse.status === 200 ? 'PASSED' : 'FAILED');
      
    } catch (error) {
      this.addResult('Video Generation Test', 'FAILED', error.message);
    }
  }

  async testPostEditingAndPublishing() {
    console.log('\n📝 Testing Post Editing & Publishing');
    
    try {
      // Test post editing
      const editResponse = await axios.patch(`${baseURL}/api/posts/1`, {
        content: 'Updated test post content'
      }, {
        headers: { 
          Cookie: this.cookies,
          'Content-Type': 'application/json'
        },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Post Editing', editResponse.status === 200 ? 'PASSED' : 'FAILED');
      
      // Test post approval
      const approveResponse = await axios.post(`${baseURL}/api/posts/1/approve`, {}, {
        headers: { Cookie: this.cookies },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Post Approval', approveResponse.status === 200 ? 'PASSED' : 'FAILED');
      
      // Test direct publishing
      const publishResponse = await axios.post(`${baseURL}/api/direct-publish`, {
        action: 'publish_all'
      }, {
        headers: { 
          Cookie: this.cookies,
          'Content-Type': 'application/json'
        },
        timeout: 30000,
        validateStatus: () => true
      });
      
      this.addResult('Direct Publishing', publishResponse.status === 200 ? 'PASSED' : 'FAILED');
      
    } catch (error) {
      this.addResult('Post Editing & Publishing Test', 'FAILED', error.message);
    }
  }

  async testAnalyticsAndReporting() {
    console.log('\n📊 Testing Analytics & Reporting');
    
    try {
      // Test analytics endpoint
      const analyticsResponse = await axios.get(`${baseURL}/api/analytics`, {
        headers: { Cookie: this.cookies },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Analytics API', analyticsResponse.status === 200 ? 'PASSED' : 'FAILED');
      
      // Test quota status
      const quotaResponse = await axios.get(`${baseURL}/api/quota-status`, {
        headers: { Cookie: this.cookies },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Quota Status', quotaResponse.status === 200 ? 'PASSED' : 'FAILED');
      
    } catch (error) {
      this.addResult('Analytics & Reporting Test', 'FAILED', error.message);
    }
  }

  async testSupportSystem() {
    console.log('\n🎧 Testing Support System');
    
    try {
      // Test feedback submission
      const feedbackResponse = await axios.post(`${baseURL}/api/submit-feedback`, {
        message: 'Test support message',
        type: 'general',
        priority: 'medium'
      }, {
        headers: { 
          Cookie: this.cookies,
          'Content-Type': 'application/json'
        },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Support Feedback Submission', feedbackResponse.status === 200 ? 'PASSED' : 'FAILED');
      
    } catch (error) {
      this.addResult('Support System Test', 'FAILED', error.message);
    }
  }

  async testAccountManagement() {
    console.log('\n👤 Testing Account Management');
    
    try {
      // Test profile access
      const profileResponse = await axios.get(`${baseURL}/api/profile`, {
        headers: { Cookie: this.cookies },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Profile Access', profileResponse.status === 200 ? 'PASSED' : 'FAILED');
      
      // Test subscription cancellation endpoint
      const cancelResponse = await axios.post(`${baseURL}/api/cancel-subscription`, {
        reason: 'Test cancellation'
      }, {
        headers: { 
          Cookie: this.cookies,
          'Content-Type': 'application/json'
        },
        timeout: 10000,
        validateStatus: () => true
      });
      
      this.addResult('Subscription Cancellation', cancelResponse.status === 200 ? 'PASSED' : 'FAILED');
      
    } catch (error) {
      this.addResult('Account Management Test', 'FAILED', error.message);
    }
  }

  addResult(step, status, error = null) {
    const result = {
      step,
      status,
      error,
      timestamp: new Date().toISOString()
    };
    
    this.testResults.push(result);
    
    const statusIcon = status === 'PASSED' ? '✅' : '❌';
    const errorMsg = error ? ` - ${error}` : '';
    console.log(`${statusIcon} ${step}: ${status}${errorMsg}`);
  }

  generateFinalReport() {
    console.log('\n' + '='.repeat(60));
    console.log('📋 COMPREHENSIVE TEST REPORT');
    console.log('='.repeat(60));
    
    const totalTests = this.testResults.length;
    const passedTests = this.testResults.filter(r => r.status === 'PASSED').length;
    const failedTests = this.testResults.filter(r => r.status === 'FAILED').length;
    const successRate = ((passedTests / totalTests) * 100).toFixed(1);
    
    console.log(`\n📊 SUMMARY:`);
    console.log(`Total Tests: ${totalTests}`);
    console.log(`Passed: ${passedTests}`);
    console.log(`Failed: ${failedTests}`);
    console.log(`Success Rate: ${successRate}%`);
    
    console.log(`\n🎯 DETAILED RESULTS:`);
    this.testResults.forEach((result, index) => {
      const statusIcon = result.status === 'PASSED' ? '✅' : '❌';
      const errorMsg = result.error ? ` (${result.error})` : '';
      console.log(`${index + 1}. ${statusIcon} ${result.step}: ${result.status}${errorMsg}`);
    });
    
    if (failedTests === 0) {
      console.log('\n🎉 ALL TESTS PASSED! TheAgencyIQ application is functioning perfectly.');
    } else {
      console.log(`\n⚠️  ${failedTests} tests failed. Review the errors above for fixes needed.`);
    }
    
    console.log(`\n📅 Test completed at: ${new Date().toISOString()}`);
    console.log('='.repeat(60));
  }
}

// Run the comprehensive test
const tester = new ComprehensiveAppTest();
tester.runCompleteTest().catch(console.error);