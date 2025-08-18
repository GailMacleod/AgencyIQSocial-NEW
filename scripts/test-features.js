#!/usr/bin/env node

import axios from 'axios';
const BASE_URL = 'http://localhost:5000';

async function testFeatures() {
  console.log('🧪 Testing TheAgencyIQ features...');
  
  const tests = [
    {
      name: 'Health Check',
      test: () => axios.get(`${BASE_URL}/api/health`),
    },
    {
      name: 'User Session',
      test: () => axios.get(`${BASE_URL}/api/user`),
    },
    {
      name: 'Platform Connections',
      test: () => axios.get(`${BASE_URL}/api/platform-connections`),
    },
    {
      name: 'Subscription Usage',
      test: () => axios.get(`${BASE_URL}/api/subscription-usage`),
    },
    {
      name: 'Analytics Data',
      test: () => axios.get(`${BASE_URL}/api/analytics`),
    },
    {
      name: 'OAuth Status',
      test: () => axios.get(`${BASE_URL}/api/oauth/status`),
    },
  ];

  const results = [];
  
  for (const { name, test } of tests) {
    try {
      const response = await test();
      results.push({
        name,
        status: 'PASS',
        statusCode: response.status,
        message: 'OK',
      });
      console.log(`✅ ${name}: PASS`);
    } catch (error) {
      results.push({
        name,
        status: 'FAIL',
        statusCode: error.response?.status || 'N/A',
        message: error.response?.data?.error || error.message,
      });
      console.log(`❌ ${name}: FAIL - ${error.response?.data?.error || error.message}`);
    }
  }
  
  console.log('\n📊 Test Summary:');
  console.log(`Passed: ${results.filter(r => r.status === 'PASS').length}`);
  console.log(`Failed: ${results.filter(r => r.status === 'FAIL').length}`);
  
  return results;
}

// Run tests if this is the main module
if (import.meta.url === `file://${process.argv[1]}`) {
  testFeatures().catch(console.error);
}

export { testFeatures };