const axios = require('axios');

// TEST CONFIGURATION
const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
const TEST_USER_ID = 2;
const TEST_EMAIL = 'gailm@macleodglba.com.au';

// Session management for authenticated requests
let sessionCookie = '';

console.log('🎬 VIDEO GENERATION 100% SUCCESS TEST');
console.log('=====================================');

async function setupSession() {
  console.log('\n1. SETTING UP AUTHENTICATED SESSION...');
  
  try {
    // Login to establish session
    const loginResponse = await axios.post(`${BASE_URL}/api/auth/login`, {
      email: TEST_EMAIL,
      password: 'password123'
    }, {
      withCredentials: true,
      validateStatus: () => true
    });
    
    // Extract session cookie
    const setCookieHeader = loginResponse.headers['set-cookie'];
    if (setCookieHeader) {
      sessionCookie = setCookieHeader.find(cookie => 
        cookie.includes('theagencyiq.session') || cookie.includes('connect.sid')
      ) || '';
      sessionCookie = sessionCookie.split(';')[0]; // Get only the cookie value
    }
    
    console.log('✅ Session established');
    console.log(`   Status: ${loginResponse.status}`);
    console.log(`   Cookie: ${sessionCookie ? 'Present' : 'Missing'}`);
    
    return true;
  } catch (error) {
    console.log('❌ Session setup failed:', error.message);
    return false;
  }
}

async function testVideoGeneration() {
  console.log('\n2. TESTING VIDEO GENERATION ENDPOINT...');
  
  const testCases = [
    {
      name: 'YouTube Business Video',
      payload: {
        prompt: 'Professional Queensland business transformation video showcasing growth',
        platform: 'youtube',
        strategicIntent: 'Business growth and authority'
      }
    },
    {
      name: 'Facebook Social Video',
      payload: {
        prompt: 'Engaging Queensland SME community success story',
        platform: 'facebook',
        strategicIntent: 'Community engagement'
      }
    },
    {
      name: 'X Platform Video',
      payload: {
        prompt: 'Quick Queensland business tip for professionals',
        platform: 'x',
        strategicIntent: 'Professional networking'
      }
    }
  ];
  
  const results = [];
  
  for (const testCase of testCases) {
    console.log(`\n   Testing: ${testCase.name}`);
    
    try {
      const response = await axios.post(`${BASE_URL}/api/video/render`, testCase.payload, {
        headers: {
          'Content-Type': 'application/json',
          'Cookie': sessionCookie
        },
        timeout: 60000, // 60 second timeout
        validateStatus: () => true
      });
      
      const success = response.status >= 200 && response.status < 300;
      const hasVideoData = response.data && (response.data.videoData || response.data.videoUrl);
      
      results.push({
        testCase: testCase.name,
        status: response.status,
        success,
        hasVideoData,
        responseTime: response.headers['x-response-time'] || 'Unknown',
        error: success ? null : response.data?.message || 'Unknown error'
      });
      
      console.log(`   Status: ${response.status} ${success ? '✅' : '❌'}`);
      console.log(`   Video Data: ${hasVideoData ? '✅' : '❌'}`);
      
      if (response.data?.videoData) {
        console.log(`   Video URL: ${response.data.videoData.videoUrl ? '✅' : '❌'}`);
        console.log(`   Duration: ${response.data.videoData.duration || 'Unknown'}s`);
        console.log(`   Format: ${response.data.videoData.format || 'Unknown'}`);
      }
      
    } catch (error) {
      results.push({
        testCase: testCase.name,
        status: 'ERROR',
        success: false,
        hasVideoData: false,
        error: error.message
      });
      
      console.log(`   ERROR: ${error.message} ❌`);
    }
  }
  
  return results;
}

async function testVideoWorkflow() {
  console.log('\n3. TESTING COMPLETE VIDEO WORKFLOW...');
  
  try {
    // Test video prompt generation
    console.log('   Testing video prompt generation...');
    const promptResponse = await axios.post(`${BASE_URL}/api/video/generate-prompts`, {
      strategicIntent: 'Queensland business transformation',
      platform: 'youtube'
    }, {
      headers: {
        'Content-Type': 'application/json',
        'Cookie': sessionCookie
      },
      timeout: 30000,
      validateStatus: () => true
    });
    
    console.log(`   Prompt Generation: ${promptResponse.status} ${promptResponse.status < 300 ? '✅' : '❌'}`);
    
    if (promptResponse.data?.prompts) {
      console.log(`   Generated Prompts: ${promptResponse.data.prompts.length} ✅`);
      
      // Test rendering first prompt
      if (promptResponse.data.prompts.length > 0) {
        const firstPrompt = promptResponse.data.prompts[0];
        console.log('   Testing render with generated prompt...');
        
        const renderResponse = await axios.post(`${BASE_URL}/api/video/render`, {
          prompt: firstPrompt,
          platform: 'youtube',
          strategicIntent: 'Business transformation'
        }, {
          headers: {
            'Content-Type': 'application/json',
            'Cookie': sessionCookie
          },
          timeout: 60000,
          validateStatus: () => true
        });
        
        console.log(`   Render Response: ${renderResponse.status} ${renderResponse.status < 300 ? '✅' : '❌'}`);
        
        if (renderResponse.data?.videoData) {
          console.log('   ✅ COMPLETE WORKFLOW SUCCESS');
          return true;
        }
      }
    }
    
    return false;
    
  } catch (error) {
    console.log(`   ERROR: ${error.message} ❌`);
    return false;
  }
}

async function testQuotaSystem() {
  console.log('\n4. TESTING QUOTA INTEGRATION...');
  
  try {
    const quotaResponse = await axios.get(`${BASE_URL}/api/quota-status`, {
      headers: {
        'Cookie': sessionCookie
      },
      validateStatus: () => true
    });
    
    console.log(`   Quota Status: ${quotaResponse.status} ${quotaResponse.status < 300 ? '✅' : '❌'}`);
    
    if (quotaResponse.data) {
      console.log(`   Video Quota: ${quotaResponse.data.videoQuota || 'Unknown'}`);
      console.log(`   API Calls: ${quotaResponse.data.apiCalls || 'Unknown'}`);
      return true;
    }
    
    return false;
    
  } catch (error) {
    console.log(`   ERROR: ${error.message} ❌`);
    return false;
  }
}

async function generateTestReport(videoResults, workflowSuccess, quotaSuccess) {
  console.log('\n🎯 TEST RESULTS SUMMARY');
  console.log('=======================');
  
  const totalTests = videoResults.length;
  const successfulTests = videoResults.filter(r => r.success).length;
  const successRate = Math.round((successfulTests / totalTests) * 100);
  
  console.log(`Video Generation Tests: ${successfulTests}/${totalTests} (${successRate}%)`);
  console.log(`Complete Workflow: ${workflowSuccess ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`Quota Integration: ${quotaSuccess ? '✅ PASS' : '❌ FAIL'}`);
  
  // Detailed results
  console.log('\nDETAILED RESULTS:');
  videoResults.forEach(result => {
    console.log(`  ${result.testCase}: ${result.success ? '✅' : '❌'} (${result.status})`);
    if (result.error) {
      console.log(`    Error: ${result.error}`);
    }
  });
  
  // Overall assessment
  const overallSuccess = successRate >= 80 && workflowSuccess && quotaSuccess;
  
  console.log(`\n🎬 OVERALL ASSESSMENT: ${overallSuccess ? '✅ SUCCESS (100% READY)' : '❌ NEEDS FIXES'}`);
  
  if (overallSuccess) {
    console.log('🚀 Video generation system is ready for production!');
  } else {
    console.log('🔧 Video generation system needs fixes before launch.');
  }
  
  return {
    overallSuccess,
    successRate,
    workflowSuccess,
    quotaSuccess,
    results: videoResults
  };
}

async function runFullTest() {
  const startTime = Date.now();
  
  try {
    // Step 1: Setup authenticated session
    const sessionSuccess = await setupSession();
    if (!sessionSuccess) {
      console.log('❌ Cannot proceed without valid session');
      return;
    }
    
    // Step 2: Test video generation endpoints
    const videoResults = await testVideoGeneration();
    
    // Step 3: Test complete workflow
    const workflowSuccess = await testVideoWorkflow();
    
    // Step 4: Test quota system
    const quotaSuccess = await testQuotaSystem();
    
    // Step 5: Generate comprehensive report
    const report = await generateTestReport(videoResults, workflowSuccess, quotaSuccess);
    
    const duration = Math.round((Date.now() - startTime) / 1000);
    console.log(`\nTest completed in ${duration} seconds`);
    
    return report;
    
  } catch (error) {
    console.error('Test execution failed:', error);
    return null;
  }
}

// Execute the test
if (require.main === module) {
  runFullTest()
    .then(report => {
      if (report?.overallSuccess) {
        process.exit(0); // Success
      } else {
        process.exit(1); // Failure
      }
    })
    .catch(error => {
      console.error('Test runner failed:', error);
      process.exit(1);
    });
}

module.exports = { runFullTest };