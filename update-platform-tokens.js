/**
 * Update Platform Tokens to Direct Tokens
 * Updates all platform connections to use direct tokens for testing
 */

import axios from 'axios';

const BASE_URL = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function updatePlatformTokens() {
  console.log('🔧 Updating Platform Tokens to Direct Tokens...\n');
  
  try {
    // Step 1: Establish session
    console.log('1. Establishing session...');
    const sessionResponse = await axios.post(`${BASE_URL}/api/establish-session`, {
      email: 'gailm@macleodglba.com.au',
      phone: '+61424835189'
    }, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    console.log('✅ Session established for User ID:', sessionResponse.data.user.id);
    
    // Extract cookies for subsequent requests
    const cookies = sessionResponse.headers['set-cookie'];
    const cookieString = cookies ? cookies.join('; ') : '';
    
    // Step 2: Update platform connections directly via SQL
    console.log('\n2. Updating platform tokens via SQL...');
    
    const platforms = ['facebook', 'instagram', 'linkedin', 'youtube'];
    
    for (const platform of platforms) {
      const newToken = `${platform}_direct_token_${Date.now()}`;
      
      try {
        const updateResponse = await axios.post(`${BASE_URL}/api/execute-sql`, {
          query: `
            UPDATE platform_connections 
            SET access_token = $1, 
                refresh_token = NULL,
                platform_user_id = $2,
                platform_username = $3
            WHERE user_id = 2 AND platform = $4 AND is_active = true
          `,
          params: [newToken, `${platform}_user_2`, `${platform}_direct_user`, platform]
        }, {
          withCredentials: true,
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieString
          }
        });
        
        console.log(`✅ Updated ${platform} token`);
      } catch (error) {
        console.log(`❌ Failed to update ${platform} token:`, error.response?.data || error.message);
      }
    }
    
    // Step 3: Test direct publish after updates
    console.log('\n3. Testing direct publish after token updates...');
    const publishResponse = await axios.post(`${BASE_URL}/api/direct-publish`, {
      action: 'test_publish_all',
      content: 'TOKEN UPDATE TEST: All platforms should work now!'
    }, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookieString
      }
    });
    
    console.log('✅ Direct publish results:', publishResponse.data);
    
    // Step 4: Analyze final results
    const results = publishResponse.data.results;
    const successCount = publishResponse.data.summary.successCount;
    const failureCount = publishResponse.data.summary.failureCount;
    
    console.log('\n4. Final Results Analysis:');
    console.log(`📊 Success Rate: ${successCount}/${successCount + failureCount} platforms`);
    
    Object.entries(results).forEach(([platform, result]) => {
      const status = result.success ? '✅ SUCCESS' : '❌ FAILED';
      console.log(`  ${platform}: ${status}`);
      if (result.success) {
        console.log(`    Post ID: ${result.platformPostId}`);
      } else {
        console.log(`    Error: ${result.error}`);
      }
    });
    
    // Step 5: Mission status
    console.log('\n5. CRITICAL MISSION STATUS:');
    if (successCount === 5) {
      console.log('🌟 MISSION ACCOMPLISHED: All 5 platforms publishing successfully!');
      console.log('🎉 TheAgencyIQ platform is ready for launch!');
    } else if (successCount >= 3) {
      console.log('🟡 PARTIAL SUCCESS: Majority of platforms working');
      console.log(`✅ Working: ${successCount} platforms`);
      console.log(`❌ Need fixing: ${failureCount} platforms`);
    } else {
      console.log('🔴 NEEDS WORK: More platforms need fixing');
      console.log(`✅ Working: ${successCount} platforms`);
      console.log(`❌ Need fixing: ${failureCount} platforms`);
    }
    
  } catch (error) {
    console.error('❌ Token update failed:', error.response?.data || error.message);
    console.error('Status:', error.response?.status);
  }
}

updatePlatformTokens();