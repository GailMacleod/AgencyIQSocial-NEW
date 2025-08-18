/**
 * Complete OAuth System Test with Updated LinkedIn Secret
 * Tests all 5 platforms with current credentials
 */

import axios from 'axios';

async function testCompleteOAuthSystem() {
  console.log('🔵 Testing Complete OAuth System...');
  
  const platforms = ['facebook', 'instagram', 'linkedin', 'x', 'youtube'];
  const results = {};
  
  try {
    // First establish session
    const sessionResponse = await axios.post('https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev/api/auth/establish-session', {}, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json',
      }
    });
    
    console.log('✅ Session established:', sessionResponse.data);
    
    // Extract session cookie
    const setCookie = sessionResponse.headers['set-cookie'];
    const sessionCookie = setCookie ? setCookie[0] : '';
    
    // Test each platform OAuth
    for (const platform of platforms) {
      console.log(`\n🔵 Testing ${platform} OAuth...`);
      
      // Map platform to OAuth route
      const oauthRoutes = {
        'facebook': '/auth/facebook',
        'instagram': '/auth/instagram', 
        'linkedin': '/auth/linkedin',
        'x': '/auth/twitter',
        'youtube': '/auth/youtube'
      };
      
      const oauthRoute = oauthRoutes[platform];
      
      try {
        const oauthResponse = await axios.get(`https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev${oauthRoute}`, {
          headers: {
            'Cookie': sessionCookie,
          },
          maxRedirects: 0,
          validateStatus: function (status) {
            return status >= 200 && status < 400;
          }
        });
        
        if (oauthResponse.status === 302) {
          const redirectUrl = oauthResponse.headers.location;
          console.log(`✅ ${platform} OAuth redirect successful`);
          console.log(`🔗 Redirect URL: ${redirectUrl}`);
          
          // Verify redirect URL structure
          if (redirectUrl) {
            if (platform === 'facebook' && redirectUrl.includes('facebook.com')) {
              results[platform] = { status: 'success', redirectUrl };
            } else if (platform === 'instagram' && redirectUrl.includes('facebook.com')) {
              results[platform] = { status: 'success', redirectUrl };
            } else if (platform === 'linkedin' && redirectUrl.includes('linkedin.com')) {
              results[platform] = { status: 'success', redirectUrl };
            } else if (platform === 'x' && redirectUrl.includes('api.twitter.com')) {
              results[platform] = { status: 'success', redirectUrl };
            } else if (platform === 'youtube' && redirectUrl.includes('accounts.google.com')) {
              results[platform] = { status: 'success', redirectUrl };
            } else {
              results[platform] = { status: 'unexpected_redirect', redirectUrl };
            }
          } else {
            results[platform] = { status: 'no_redirect' };
          }
        } else {
          results[platform] = { status: 'failed', statusCode: oauthResponse.status };
        }
        
      } catch (error) {
        console.error(`❌ ${platform} OAuth failed:`, error.message);
        results[platform] = { status: 'error', error: error.message };
      }
    }
    
    // Generate summary
    console.log('\n📋 OAuth System Test Summary:');
    console.log('='.repeat(50));
    
    let successCount = 0;
    for (const [platform, result] of Object.entries(results)) {
      if (result.status === 'success') {
        console.log(`✅ ${platform.toUpperCase()}: WORKING`);
        successCount++;
      } else {
        console.log(`❌ ${platform.toUpperCase()}: ${result.status} - ${result.error || 'Check configuration'}`);
      }
    }
    
    console.log(`\n📊 Success Rate: ${successCount}/5 platforms (${(successCount/5*100).toFixed(1)}%)`);
    
    if (successCount === 5) {
      console.log('🎉 ALL OAUTH SYSTEMS WORKING PERFECTLY!');
    } else {
      console.log(`⚠️  ${5-successCount} platform(s) need attention`);
    }
    
  } catch (error) {
    console.error('❌ OAuth system test failed:', error.message);
  }
}

testCompleteOAuthSystem();