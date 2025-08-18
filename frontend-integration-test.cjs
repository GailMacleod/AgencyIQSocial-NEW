/**
 * FRONTEND INTEGRATION TEST
 * Tests key user workflows through actual frontend interactions
 */

const axios = require('axios');

const BASE_URL = 'http://localhost:5000';
const TEST_COOKIE = 'theagencyiq.session=s%3Aaiq_md9zaigr_aknyuyl19nd.BezvuNEUo23IMWaBetxnSP5hof3lSdNdsjLrdkNQtzs';

async function testFrontendEndpoints() {
  console.log('🌐 Testing Frontend Integration Points');
  
  const endpoints = [
    { path: '/', name: 'Homepage/Splash' },
    { path: '/schedule', name: 'Schedule Page' },
    { path: '/analytics', name: 'Analytics Page' },
    { path: '/brand-purpose', name: 'Brand Purpose Page' },
    { path: '/platform-connections', name: 'Platform Connections' },
    { path: '/admin/video-prompts', name: 'Admin Video Dashboard' }
  ];
  
  for (const endpoint of endpoints) {
    try {
      const response = await axios.get(`${BASE_URL}${endpoint.path}`, {
        headers: { 'Cookie': TEST_COOKIE },
        timeout: 10000
      });
      
      console.log(`✅ ${endpoint.name} (${endpoint.path}): ${response.status}`);
    } catch (error) {
      console.log(`❌ ${endpoint.name} (${endpoint.path}): ${error.response?.status || 'ERROR'}`);
    }
  }
}

testFrontendEndpoints().catch(console.error);