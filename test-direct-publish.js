/**
 * Test Direct Publishing to All Platforms
 * Uses DirectPostPublisher for immediate publishing
 */

async function testDirectPublish() {
  const baseUrl = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
  
  console.log('🚀 DIRECT PUBLISHING TEST TO ALL PLATFORMS');
  console.log('==========================================');
  
  try {
    // Use the PostPublisherV2 direct API
    console.log('📤 Sending direct publish request...');
    
    const response = await fetch(`${baseUrl}/api/test-direct-publish`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
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
      console.error('Direct publish failed:', errorText);
      
      // Try the immediate publish service instead
      console.log('\n🔄 Trying immediate publish service...');
      
      const immediateResponse = await fetch(`${baseUrl}/api/immediate-publish`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({
          userId: 2
        })
      });
      
      console.log('Immediate publish status:', immediateResponse.status);
      
      if (immediateResponse.ok) {
        const immediateResult = await immediateResponse.json();
        console.log('\n📊 Immediate Publish Results:');
        console.log(JSON.stringify(immediateResult, null, 2));
        
        if (immediateResult.platformResults) {
          console.log('\n📋 Platform Results Summary:');
          immediateResult.platformResults.forEach(result => {
            const status = result.success ? '✅ SUCCESS' : '❌ FAILED';
            console.log(`  ${result.platform.toUpperCase()}: ${status}`);
            if (result.error) {
              console.log(`    Error: ${result.error}`);
            }
            if (result.platformPostId) {
              console.log(`    Post ID: ${result.platformPostId}`);
            }
          });
        }
      } else {
        console.error('Immediate publish failed:', await immediateResponse.text());
      }
      
      return;
    }
    
    const result = await response.json();
    console.log('\n📊 Direct Publishing Results:');
    console.log(JSON.stringify(result, null, 2));
    
    if (result.results) {
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
    
    console.log(`\n📈 Overall Success: ${result.success ? 'Yes' : 'No'}`);
    console.log(`🎯 Successful Platforms: ${result.successfulPlatforms || 0}`);
    
  } catch (error) {
    console.error('❌ Direct publishing test failed:', error.message);
  }
}

testDirectPublish();