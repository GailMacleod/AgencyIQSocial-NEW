/**
 * Test Publishing with OAuth Token Validation
 * Uses PostPublisherV2 with real OAuth token validation
 */

async function testPublishWithOAuth() {
  const baseUrl = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
  
  console.log('🚀 TESTING OAUTH PUBLISHING TO ALL PLATFORMS');
  console.log('=============================================');
  
  try {
    // Test the immediate publish service endpoint
    const response = await fetch(`${baseUrl}/api/posts/publish-immediate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': 'connect.sid=aiq_mcyk1d4x_t4gugjjmzhg'
      },
      body: JSON.stringify({
        content: 'Test',
        platforms: ['facebook', 'instagram', 'linkedin', 'x', 'youtube'],
        userId: 2
      })
    });
    
    console.log('Response status:', response.status);
    console.log('Response headers:', Object.fromEntries(response.headers.entries()));
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error('Error response:', errorText);
      return;
    }
    
    const result = await response.json();
    console.log('\n📊 Publishing Results:');
    console.log(JSON.stringify(result, null, 2));
    
    if (result.results && Array.isArray(result.results)) {
      console.log('\n📋 Platform Results Summary:');
      result.results.forEach(platformResult => {
        const status = platformResult.success ? '✅ SUCCESS' : '❌ FAILED';
        console.log(`  ${platformResult.platform.toUpperCase()}: ${status}`);
        if (platformResult.error) {
          console.log(`    Error: ${platformResult.error}`);
        }
        if (platformResult.postId) {
          console.log(`    Post ID: ${platformResult.postId}`);
        }
      });
    }
    
  } catch (error) {
    console.error('❌ Publishing test failed:', error.message);
  }
}

testPublishWithOAuth();