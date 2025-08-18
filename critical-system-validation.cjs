/**
 * CRITICAL SYSTEM VALIDATION
 * Focus on core business-critical functionality
 */

const axios = require('axios');

const BASE_URL = 'http://localhost:5000';
const TEST_COOKIE = 'theagencyiq.session=s%3Aaiq_md9zaigr_aknyuyl19nd.BezvuNEUo23IMWaBetxnSP5hof3lSdNdsjLrdkNQtzs';

async function validateCriticalSystems() {
  console.log('🎯 CRITICAL SYSTEM VALIDATION - Core Business Features');
  console.log('========================================================');
  
  const results = {
    critical: [],
    working: [],
    issues: []
  };

  // Test 1: Core Authentication & Session
  try {
    const response = await axios.get(`${BASE_URL}/api/user`, {
      headers: { 'Cookie': TEST_COOKIE }
    });
    
    if (response.status === 200 && response.data.id === 2) {
      results.critical.push('✅ Authentication System: WORKING');
    } else {
      results.issues.push('❌ Authentication System: FAILED');
    }
  } catch (error) {
    results.issues.push('❌ Authentication System: ERROR - ' + error.message);
  }

  // Test 2: Video Generation (Core Feature)
  try {
    const response = await axios.post(`${BASE_URL}/api/video/render`, {
      promptType: 'cinematic-auto',
      promptPreview: 'Critical system test',
      editedText: 'Brisbane business transformation',
      platform: 'youtube',
      postId: 8888
    }, {
      headers: { 'Cookie': TEST_COOKIE, 'Content-Type': 'application/json' }
    });
    
    if (response.status === 200 && response.data.success) {
      results.critical.push('✅ Video Generation: WORKING');
      console.log(`   Video ID: ${response.data.videoId}`);
    } else {
      results.issues.push('❌ Video Generation: FAILED');
    }
  } catch (error) {
    results.issues.push('❌ Video Generation: ERROR - ' + error.message);
  }

  // Test 3: Admin Dashboard
  try {
    const response = await axios.get(`${BASE_URL}/api/admin/video-prompts`, {
      headers: { 'Cookie': TEST_COOKIE }
    });
    
    if (response.status === 200 && response.data.summary) {
      results.critical.push('✅ Admin Dashboard: WORKING');
      console.log(`   Total prompts: ${response.data.summary.totalPrompts}`);
    } else {
      results.issues.push('❌ Admin Dashboard: FAILED');
    }
  } catch (error) {
    results.issues.push('❌ Admin Dashboard: ERROR - ' + error.message);
  }

  // Test 4: Posts System
  try {
    const response = await axios.get(`${BASE_URL}/api/posts`, {
      headers: { 'Cookie': TEST_COOKIE }
    });
    
    if (response.status === 200 && Array.isArray(response.data)) {
      results.critical.push('✅ Posts System: WORKING');
      console.log(`   Total posts: ${response.data.length}`);
    } else {
      results.issues.push('❌ Posts System: FAILED');
    }
  } catch (error) {
    results.issues.push('❌ Posts System: ERROR - ' + error.message);
  }

  // Test 5: Brand Purpose
  try {
    const response = await axios.get(`${BASE_URL}/api/brand-purpose`, {
      headers: { 'Cookie': TEST_COOKIE }
    });
    
    if (response.status === 200 && response.data.brandName) {
      results.critical.push('✅ Brand Purpose: WORKING');
    } else {
      results.issues.push('❌ Brand Purpose: FAILED');
    }
  } catch (error) {
    results.issues.push('❌ Brand Purpose: ERROR - ' + error.message);
  }

  // Test 6: Platform Connections
  try {
    const response = await axios.get(`${BASE_URL}/api/platform-connections`, {
      headers: { 'Cookie': TEST_COOKIE }
    });
    
    if (response.status === 200 && Array.isArray(response.data)) {
      results.critical.push('✅ Platform Connections: WORKING');
      console.log(`   Connected platforms: ${response.data.length}`);
    } else {
      results.issues.push('❌ Platform Connections: FAILED');
    }
  } catch (error) {
    results.issues.push('❌ Platform Connections: ERROR - ' + error.message);
  }

  // Results Summary
  console.log('');
  console.log('📊 CRITICAL SYSTEMS STATUS');
  console.log('===========================');
  
  results.critical.forEach(item => console.log(item));
  results.working.forEach(item => console.log(item));
  
  if (results.issues.length > 0) {
    console.log('');
    console.log('⚠️  ISSUES DETECTED:');
    results.issues.forEach(item => console.log(item));
  }
  
  console.log('');
  const totalTests = results.critical.length + results.issues.length;
  const successRate = ((results.critical.length / totalTests) * 100).toFixed(1);
  
  if (results.issues.length === 0) {
    console.log('🎉 ALL CRITICAL SYSTEMS OPERATIONAL');
    console.log('✅ System ready for production use');
  } else {
    console.log(`📈 Success Rate: ${successRate}% (${results.critical.length}/${totalTests})`);
    if (successRate >= 80) {
      console.log('✅ System mostly stable - minor issues to address');
    } else {
      console.log('⚠️  System needs attention before production');
    }
  }
}

validateCriticalSystems().catch(console.error);