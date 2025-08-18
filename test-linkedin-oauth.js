/**
 * Test LinkedIn OAuth Configuration
 * Checks if LinkedIn OAuth is properly configured and working
 */

import https from 'https';
import { URL } from 'url';

async function testLinkedInOAuth() {
  console.log('🔍 Testing LinkedIn OAuth configuration...');
  
  try {
    // Test LinkedIn OAuth initiation
    const options = {
      hostname: '4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev',
      path: '/auth/linkedin',
      method: 'GET',
      headers: {
        'Cookie': 'theagencyiq.session=s%3Aaiq_md10oner_zzltawpuqz.gYlCRNuFBOsoUjYhiJNYGPf6kNOnk8SvzUElLWNXR0w',
        'User-Agent': 'Mozilla/5.0'
      }
    };

    const req = https.request(options, (res) => {
      console.log('LinkedIn OAuth response status:', res.statusCode);
      console.log('LinkedIn OAuth response headers:', res.headers);
      
      if (res.statusCode === 302 && res.headers.location) {
        const redirectUrl = new URL(res.headers.location);
        console.log('✅ LinkedIn OAuth redirect URL generated:');
        console.log(res.headers.location);
        console.log('🔍 LinkedIn OAuth details:');
        console.log('- Client ID:', redirectUrl.searchParams.get('client_id'));
        console.log('- Callback URL:', redirectUrl.searchParams.get('redirect_uri'));
        console.log('- Scopes:', redirectUrl.searchParams.get('scope'));
        console.log('- State:', redirectUrl.searchParams.get('state'));
        
        if (redirectUrl.searchParams.get('client_id') === process.env.LINKEDIN_CLIENT_ID) {
          console.log('✅ LinkedIn OAuth using correct client ID');
        } else {
          console.log('❌ LinkedIn OAuth client ID mismatch');
        }
      } else {
        console.log('❌ LinkedIn OAuth failed to generate redirect URL');
      }
      
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        if (data) {
          console.log('LinkedIn OAuth response body:', data.slice(0, 500));
        }
      });
    });

    req.on('error', (e) => {
      console.error('❌ LinkedIn OAuth request error:', e.message);
    });

    req.end();
    
  } catch (error) {
    console.error('❌ LinkedIn OAuth test failed:', error.message);
  }
}

testLinkedInOAuth();