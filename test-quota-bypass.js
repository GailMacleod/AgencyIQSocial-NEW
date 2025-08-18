/**
 * Test with quota bypass to verify the actual publishing mechanism
 */

import axios from 'axios';

class QuotaBypassTest {
  constructor() {
    this.baseURL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
    this.cookies = '';
  }

  async establishSession() {
    try {
      console.log('🔐 Establishing session...');
      const response = await axios.post(`${this.baseURL}/api/establish-session`, {
        email: 'gailm@macleodglba.com.au',
        phone: '+61424835189'
      }, {
        withCredentials: true
      });

      if (response.headers['set-cookie']) {
        this.cookies = response.headers['set-cookie'].join('; ');
        console.log('✅ Session established successfully');
        return true;
      }
    } catch (error) {
      console.error('❌ Session establishment failed:', error.response?.data || error.message);
      return false;
    }
  }

  async testForcePublishAll() {
    try {
      console.log('🚀 Testing force_publish_all (quota bypass)...');
      
      const response = await axios.post(`${this.baseURL}/api/direct-publish`, {
        action: 'force_publish_all'
      }, {
        headers: {
          'Cookie': this.cookies,
          'Content-Type': 'application/json'
        },
        withCredentials: true
      });

      console.log('✅ Force publish response:', response.data);
      return response.data;
    } catch (error) {
      console.error('❌ Force publish failed:', error.response?.data || error.message);
      return null;
    }
  }

  async runTest() {
    console.log('🧪 Starting Quota Bypass Test...\n');
    
    const sessionSuccess = await this.establishSession();
    if (!sessionSuccess) {
      console.log('❌ TEST FAILED: Could not establish session');
      return;
    }

    const result = await this.testForcePublishAll();
    if (result) {
      console.log('✅ Force publish test completed successfully');
      console.log(`📊 Result: ${result.message}`);
    } else {
      console.log('❌ Force publish test failed');
    }
  }
}

const test = new QuotaBypassTest();
test.runTest().catch(console.error);