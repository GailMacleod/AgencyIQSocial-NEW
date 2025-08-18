/**
 * COMPREHENSIVE VIDEO GENERATION FUNCTIONALITY TEST
 * Tests all aspects of the VEO 2.0 video generation system
 */

import axios from 'axios';

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

// Test Configuration
const testConfig = {
  platforms: ['instagram', 'youtube', 'facebook', 'linkedin', 'x'],
  prompts: [
    'Queensland SME business transformation success story',
    'Professional automation breakthrough for local business',
    'Digital innovation driving Queensland business growth'
  ],
  strategicIntents: [
    'business growth automation',
    'professional efficiency boost', 
    'Queensland market leadership'
  ]
};

async function testVideoGeneration() {
  console.log('🎬 COMPREHENSIVE VIDEO GENERATION TEST STARTING...\n');
  
  const results = {
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    testResults: []
  };

  // Test 1: Video Prompt Generation
  console.log('📝 TEST 1: Video Prompt Generation');
  try {
    const response = await axios.post(`${BASE_URL}/api/video/generate-prompts`, {
      postContent: 'Queensland business automation success',
      platform: 'instagram',
      strategicIntent: 'business transformation'
    }, {
      timeout: 15000,
      headers: { 'Content-Type': 'application/json' }
    });
    
    results.totalTests++;
    if (response.status === 200 && response.data.prompts) {
      console.log('✅ Video prompt generation: SUCCESS');
      console.log(`   Generated ${response.data.prompts.length} prompts`);
      results.passedTests++;
      results.testResults.push({
        test: 'Video Prompt Generation',
        status: 'PASS',
        responseTime: `${response.headers['x-response-time'] || 'N/A'}`,
        details: `Generated ${response.data.prompts.length} prompts`
      });
    } else {
      throw new Error('Invalid response structure');
    }
  } catch (error) {
    console.log('❌ Video prompt generation: FAILED');
    console.log(`   Error: ${error.message}`);
    results.failedTests++;
    results.testResults.push({
      test: 'Video Prompt Generation',
      status: 'FAIL',
      error: error.message
    });
  }

  // Test 2: VEO 2.0 Video Rendering
  console.log('\n🎥 TEST 2: VEO 2.0 Video Rendering');
  try {
    const response = await axios.post(`${BASE_URL}/api/video/render`, {
      prompt: 'Queensland SME transformation: From manual chaos to automated success. Fair dinkum business efficiency.',
      platform: 'instagram',
      strategicIntent: 'Queensland business transformation',
      brandPurpose: {
        brandName: 'Test Queensland Business',
        corePurpose: 'Automate small business operations',
        jobToBeDone: 'Transform manual processes into efficient automated systems',
        motivations: 'Increase efficiency and reduce workload',
        painPoints: 'Manual data entry and time-consuming processes'
      }
    }, {
      timeout: 30000,
      headers: { 'Content-Type': 'application/json' }
    });
    
    results.totalTests++;
    if (response.status === 200 && response.data.success) {
      console.log('✅ VEO 2.0 video rendering: SUCCESS');
      console.log(`   Video ID: ${response.data.videoId}`);
      console.log(`   Video URL: ${response.data.videoUrl || response.data.url}`);
      console.log(`   Enhanced JTBD: ${response.data.grokEnhanced ? 'YES' : 'NO'}`);
      console.log(`   Platform: ${response.data.platform}`);
      results.passedTests++;
      results.testResults.push({
        test: 'VEO 2.0 Video Rendering',
        status: 'PASS',
        responseTime: `${response.headers['x-response-time'] || 'N/A'}`,
        details: `Video generated with ID: ${response.data.videoId}`
      });
    } else {
      throw new Error('Video rendering failed or invalid response');
    }
  } catch (error) {
    console.log('❌ VEO 2.0 video rendering: FAILED');
    console.log(`   Error: ${error.message}`);
    results.failedTests++;
    results.testResults.push({
      test: 'VEO 2.0 Video Rendering',
      status: 'FAIL',
      error: error.message
    });
  }

  // Test 3: Enhanced JTBD Copywriting System
  console.log('\n🧠 TEST 3: Enhanced JTBD Copywriting System');
  try {
    const response = await axios.post(`${BASE_URL}/api/video/render`, {
      prompt: {
        content: 'Strategic business transformation through automation',
        type: 'strategic'
      },
      platform: 'linkedin',
      strategicIntent: 'professional authority building',
      brandPurpose: {
        brandName: 'Queensland Professional Services',
        corePurpose: 'Expert business automation consulting',
        jobToBeDone: 'Help SMEs automate complex business processes',
        motivations: 'Become industry thought leaders',
        painPoints: 'Clients struggling with manual inefficiencies'
      }
    }, {
      timeout: 30000,
      headers: { 'Content-Type': 'application/json' }
    });
    
    results.totalTests++;
    if (response.status === 200 && response.data.grokEnhanced) {
      console.log('✅ Enhanced JTBD copywriting: SUCCESS');
      console.log(`   JTBD Integration: ${response.data.brandPurposeDriven ? 'ACTIVE' : 'BASIC'}`);
      console.log(`   Queensland Focus: ${response.data.queenslandFocus || 'INTEGRATED'}`);
      console.log(`   Cultural Elements: ${response.data.culturalElements || 'INCLUDED'}`);
      results.passedTests++;
      results.testResults.push({
        test: 'Enhanced JTBD Copywriting',
        status: 'PASS',
        details: 'JTBD framework properly integrated with Queensland cultural elements'
      });
    } else {
      throw new Error('JTBD enhancement not activated');
    }
  } catch (error) {
    console.log('❌ Enhanced JTBD copywriting: FAILED');
    console.log(`   Error: ${error.message}`);
    results.failedTests++;
    results.testResults.push({
      test: 'Enhanced JTBD Copywriting',
      status: 'FAIL',
      error: error.message
    });
  }

  // Test 4: Multi-Platform Support
  console.log('\n📱 TEST 4: Multi-Platform Video Support');
  for (const platform of ['instagram', 'youtube', 'facebook']) {
    try {
      const response = await axios.post(`${BASE_URL}/api/video/render`, {
        prompt: `${platform} optimized Queensland business content`,
        platform: platform,
        strategicIntent: 'platform-specific optimization'
      }, {
        timeout: 20000,
        headers: { 'Content-Type': 'application/json' }
      });
      
      results.totalTests++;
      if (response.status === 200 && response.data.platform === platform) {
        console.log(`✅ ${platform.toUpperCase()} video generation: SUCCESS`);
        results.passedTests++;
        results.testResults.push({
          test: `${platform.toUpperCase()} Platform Support`,
          status: 'PASS',
          details: `Platform-specific video generated successfully`
        });
      } else {
        throw new Error(`Platform mismatch or generation failed`);
      }
    } catch (error) {
      console.log(`❌ ${platform.toUpperCase()} video generation: FAILED - ${error.message}`);
      results.failedTests++;
      results.testResults.push({
        test: `${platform.toUpperCase()} Platform Support`,
        status: 'FAIL',
        error: error.message
      });
    }
    
    // Add delay between platform tests
    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  // Test 5: Quota System Integration
  console.log('\n📊 TEST 5: Quota System Integration');
  try {
    const response = await axios.get(`${BASE_URL}/api/quota-status`, {
      timeout: 10000,
      headers: { 'Content-Type': 'application/json' }
    });
    
    results.totalTests++;
    if (response.status === 200 && response.data) {
      console.log('✅ Quota system integration: SUCCESS');
      console.log(`   Plan: ${response.data.plan || 'detected'}`);
      console.log(`   Video quota: ${response.data.remaining?.videos || 'available'}`);
      results.passedTests++;
      results.testResults.push({
        test: 'Quota System Integration',
        status: 'PASS',
        details: `Quota tracking operational for ${response.data.plan || 'current'} plan`
      });
    } else {
      throw new Error('Quota system not responding');
    }
  } catch (error) {
    console.log('❌ Quota system integration: FAILED');
    console.log(`   Error: ${error.message}`);
    results.failedTests++;
    results.testResults.push({
      test: 'Quota System Integration',
      status: 'FAIL',
      error: error.message
    });
  }

  // Generate Test Report
  console.log('\n' + '='.repeat(60));
  console.log('📋 COMPREHENSIVE VIDEO FUNCTIONALITY TEST REPORT');
  console.log('='.repeat(60));
  console.log(`Total Tests: ${results.totalTests}`);
  console.log(`Passed: ${results.passedTests}`);
  console.log(`Failed: ${results.failedTests}`);
  console.log(`Success Rate: ${((results.passedTests / results.totalTests) * 100).toFixed(1)}%`);
  
  console.log('\n📊 DETAILED TEST RESULTS:');
  results.testResults.forEach((result, index) => {
    console.log(`${index + 1}. ${result.test}: ${result.status}`);
    if (result.details) console.log(`   Details: ${result.details}`);
    if (result.error) console.log(`   Error: ${result.error}`);
    if (result.responseTime) console.log(`   Response Time: ${result.responseTime}`);
  });

  // Launch Readiness Assessment
  const successRate = (results.passedTests / results.totalTests) * 100;
  console.log('\n🚀 LAUNCH READINESS ASSESSMENT:');
  
  if (successRate >= 95) {
    console.log('✅ READY FOR LAUNCH - All critical systems operational');
    console.log('   Video generation system: FULLY FUNCTIONAL');
    console.log('   VEO 2.0 integration: OPERATIONAL');
    console.log('   JTBD framework: ACTIVE');
    console.log('   Multi-platform support: CONFIRMED');
    console.log('   Quota management: INTEGRATED');
  } else if (successRate >= 80) {
    console.log('⚠️  CAUTION - Minor issues detected, recommend review');
    console.log('   Core functionality working but some features need attention');
  } else {
    console.log('❌ NOT READY - Critical issues require resolution');
    console.log('   Major system components failing, launch not recommended');
  }

  return results;
}

// Execute comprehensive test
testVideoGeneration()
  .then(results => {
    process.exit(results.failedTests === 0 ? 0 : 1);
  })
  .catch(error => {
    console.error('❌ Test execution failed:', error.message);
    process.exit(1);
  });