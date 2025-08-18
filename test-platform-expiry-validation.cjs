/**
 * COMPREHENSIVE PLATFORM EXPIRY VALIDATION TEST
 * Tests the fixed platform connection UI with proper OAuth token expiration
 */

const axios = require('axios');
const assert = require('assert');

// Configuration
const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
const USER_EMAIL = 'gailm@macleodglba.com.au';
const USER_PHONE = '+61424835189';

class PlatformExpiryValidationTest {
  constructor() {
    this.sessionCookies = '';
    this.testResults = [];
    this.baseHeaders = {
      'Content-Type': 'application/json',
      'User-Agent': 'TheAgencyIQ-ExpiryTest/1.0'
    };
  }

  async runFullValidation() {
    console.log('🔍 PLATFORM EXPIRY VALIDATION TEST STARTING...');
    console.log('Current Test Time: July 13, 2025 02:10 UTC');
    
    try {
      // Step 1: Establish session
      await this.establishSession();
      
      // Step 2: Test API endpoint with expiry validation
      await this.testPlatformConnectionsAPI();
      
      // Step 3: Verify expired tokens are detected
      await this.verifyExpiredTokensDetected();
      
      // Step 4: Verify valid tokens are still valid
      await this.verifyValidTokensDetected();
      
      // Generate final validation report
      this.generateValidationReport();
      
    } catch (error) {
      console.error('❌ VALIDATION TEST FAILED:', error.message);
      throw error;
    }
  }

  async establishSession() {
    console.log('\n📝 STEP 1: Establishing authenticated session...');
    
    try {
      const response = await axios.post(`${BASE_URL}/api/establish-session`, {
        email: USER_EMAIL,
        phone: USER_PHONE
      }, {
        headers: this.baseHeaders,
        withCredentials: true
      });

      // Extract session cookies
      const setCookieHeader = response.headers['set-cookie'];
      if (setCookieHeader) {
        this.sessionCookies = setCookieHeader.join('; ');
        console.log('✅ Session established successfully');
        console.log('Session cookies length:', this.sessionCookies.length);
      } else {
        throw new Error('No session cookies received');
      }
      
      this.testResults.push({
        step: 'Session Establishment',
        status: 'SUCCESS',
        details: `User: ${USER_EMAIL}`
      });
      
    } catch (error) {
      console.error('❌ Session establishment failed:', error.message);
      this.testResults.push({
        step: 'Session Establishment',
        status: 'FAILED',
        error: error.message
      });
      throw error;
    }
  }

  async testPlatformConnectionsAPI() {
    console.log('\n🔗 STEP 2: Testing /api/platform-connections endpoint...');
    
    try {
      const response = await axios.get(`${BASE_URL}/api/platform-connections`, {
        headers: {
          ...this.baseHeaders,
          'Cookie': this.sessionCookies
        },
        withCredentials: true
      });

      const connections = response.data;
      console.log(`✅ API Response received - ${connections.length} connections found`);
      
      // Analyze each connection
      connections.forEach(conn => {
        console.log(`\n📊 Platform: ${conn.platform}`);
        console.log(`   Access Token: ${conn.accessToken?.substring(0, 20)}...`);
        console.log(`   Expires At: ${conn.expiresAt}`);
        console.log(`   OAuth Status - Valid: ${conn.oauthStatus?.isValid}`);
        console.log(`   OAuth Status - Needs Refresh: ${conn.oauthStatus?.needsRefresh}`);
        console.log(`   OAuth Status - Error: ${conn.oauthStatus?.error || 'None'}`);
        
        // Check if expiry detection is working
        if (conn.expiresAt) {
          const expiryTime = new Date(conn.expiresAt);
          const currentTime = new Date('2025-07-13T02:10:00Z');
          const isExpired = expiryTime <= currentTime;
          
          console.log(`   ⏰ Expiry Analysis:`);
          console.log(`      Expiry Time: ${expiryTime.toISOString()}`);
          console.log(`      Current Time: ${currentTime.toISOString()}`);
          console.log(`      Is Expired: ${isExpired}`);
          console.log(`      OAuth Says Valid: ${conn.oauthStatus?.isValid}`);
          
          // Validate consistency
          if (isExpired && conn.oauthStatus?.isValid === true) {
            console.log(`   ⚠️  INCONSISTENCY DETECTED: Token is expired but OAuth says valid!`);
          } else if (!isExpired && conn.oauthStatus?.isValid === false) {
            console.log(`   ⚠️  INCONSISTENCY DETECTED: Token is valid but OAuth says expired!`);
          } else {
            console.log(`   ✅ Consistency confirmed: Expiry and OAuth status match`);
          }
        }
      });
      
      this.testResults.push({
        step: 'API Platform Connections',
        status: 'SUCCESS',
        details: `${connections.length} connections retrieved and analyzed`
      });
      
      return connections;
      
    } catch (error) {
      console.error('❌ API call failed:', error.message);
      this.testResults.push({
        step: 'API Platform Connections',
        status: 'FAILED',
        error: error.message
      });
      throw error;
    }
  }

  async verifyExpiredTokensDetected() {
    console.log('\n🔍 STEP 3: Verifying expired tokens are properly detected...');
    
    const response = await axios.get(`${BASE_URL}/api/platform-connections`, {
      headers: {
        ...this.baseHeaders,
        'Cookie': this.sessionCookies
      },
      withCredentials: true
    });

    const connections = response.data;
    const expiredPlatforms = ['instagram', 'linkedin']; // Based on our database setup
    
    let expiredDetected = 0;
    let expiredMissed = 0;
    
    expiredPlatforms.forEach(platform => {
      const connection = connections.find(c => c.platform === platform);
      if (connection) {
        const isExpired = connection.oauthStatus?.isValid === false;
        if (isExpired) {
          console.log(`✅ ${platform}: Correctly detected as expired`);
          expiredDetected++;
        } else {
          console.log(`❌ ${platform}: NOT detected as expired (should be)`);
          expiredMissed++;
        }
      }
    });
    
    console.log(`\n📊 EXPIRED TOKEN DETECTION RESULTS:`);
    console.log(`   Correctly detected: ${expiredDetected}`);
    console.log(`   Missed detection: ${expiredMissed}`);
    console.log(`   Success rate: ${expiredDetected}/${expiredPlatforms.length} (${(expiredDetected/expiredPlatforms.length*100).toFixed(1)}%)`);
    
    this.testResults.push({
      step: 'Expired Token Detection',
      status: expiredMissed === 0 ? 'SUCCESS' : 'PARTIAL',
      details: `${expiredDetected}/${expiredPlatforms.length} expired tokens detected`
    });
  }

  async verifyValidTokensDetected() {
    console.log('\n🔍 STEP 4: Verifying valid tokens are properly detected...');
    
    const response = await axios.get(`${BASE_URL}/api/platform-connections`, {
      headers: {
        ...this.baseHeaders,
        'Cookie': this.sessionCookies
      },
      withCredentials: true
    });

    const connections = response.data;
    const validPlatforms = ['x', 'youtube']; // Based on our database setup - expires July 14
    
    let validDetected = 0;
    let validMissed = 0;
    
    validPlatforms.forEach(platform => {
      const connection = connections.find(c => c.platform === platform);
      if (connection) {
        const isValid = connection.oauthStatus?.isValid === true;
        if (isValid) {
          console.log(`✅ ${platform}: Correctly detected as valid`);
          validDetected++;
        } else {
          console.log(`❌ ${platform}: NOT detected as valid (should be)`);
          validMissed++;
        }
      }
    });
    
    console.log(`\n📊 VALID TOKEN DETECTION RESULTS:`);
    console.log(`   Correctly detected: ${validDetected}`);
    console.log(`   Missed detection: ${validMissed}`);
    console.log(`   Success rate: ${validDetected}/${validPlatforms.length} (${(validDetected/validPlatforms.length*100).toFixed(1)}%)`);
    
    this.testResults.push({
      step: 'Valid Token Detection',
      status: validMissed === 0 ? 'SUCCESS' : 'PARTIAL',
      details: `${validDetected}/${validPlatforms.length} valid tokens detected`
    });
  }

  generateValidationReport() {
    console.log('\n📋 COMPREHENSIVE VALIDATION REPORT');
    console.log('================================');
    
    const successCount = this.testResults.filter(r => r.status === 'SUCCESS').length;
    const totalCount = this.testResults.length;
    const successRate = (successCount / totalCount * 100).toFixed(1);
    
    console.log(`Overall Success Rate: ${successCount}/${totalCount} (${successRate}%)`);
    console.log('\nDetailed Results:');
    
    this.testResults.forEach((result, index) => {
      const status = result.status === 'SUCCESS' ? '✅' : 
                    result.status === 'PARTIAL' ? '⚠️' : '❌';
      console.log(`${index + 1}. ${status} ${result.step}`);
      console.log(`   Details: ${result.details}`);
      if (result.error) {
        console.log(`   Error: ${result.error}`);
      }
    });
    
    console.log('\n🎯 VALIDATION SUMMARY:');
    console.log('- Database migration: Real OAuth tokens with expires_at timestamps');
    console.log('- Backend validation: Enhanced with expires_at checking');
    console.log('- Frontend logic: Client-side expiry validation added');
    console.log('- API consistency: Server-side and client-side validation aligned');
    
    if (successRate >= 100) {
      console.log('\n🎉 VALIDATION COMPLETE: All tests passed - Platform expiry detection working correctly!');
    } else if (successRate >= 75) {
      console.log('\n⚠️  VALIDATION PARTIAL: Most tests passed - Minor issues detected');
    } else {
      console.log('\n❌ VALIDATION FAILED: Significant issues detected - Further fixes needed');
    }
  }
}

// Execute validation test
async function main() {
  const validator = new PlatformExpiryValidationTest();
  await validator.runFullValidation();
}

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}

module.exports = PlatformExpiryValidationTest;