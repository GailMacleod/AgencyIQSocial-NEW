/**
 * Test Real Publishing to All Platforms
 * Uses the actual API endpoints with OAuth token validation
 */

async function testRealPublish() {
  const baseUrl = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
  
  console.log('🚀 TESTING REAL PUBLISHING TO ALL PLATFORMS');
  console.log('============================================');
  
  try {
    // First, get the user's posts to see current state
    console.log('📋 Getting current posts...');
    const postsResponse = await fetch(`${baseUrl}/api/posts`, {
      credentials: 'include'
    });
    
    const postsData = await postsResponse.json();
    console.log(`Current posts: ${postsData.length}`);
    
    // Create a test post first
    console.log('📝 Creating test post...');
    const createPostResponse = await fetch(`${baseUrl}/api/posts`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify({
        content: 'Test',
        platform: 'facebook', // We'll publish to all platforms
        scheduledFor: new Date().toISOString()
      })
    });
    
    if (!createPostResponse.ok) {
      console.error('Failed to create test post:', await createPostResponse.text());
      return;
    }
    
    const newPost = await createPostResponse.json();
    console.log('Test post created:', newPost);
    
    // Now publish to all platforms using the PostPublisher
    console.log('🚀 Publishing to all platforms...');
    const publishResponse = await fetch(`${baseUrl}/api/publish-post`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include',
      body: JSON.stringify({
        postId: newPost.id,
        platforms: ['facebook', 'instagram', 'linkedin', 'x', 'youtube']
      })
    });
    
    console.log('Publish response status:', publishResponse.status);
    
    if (!publishResponse.ok) {
      const errorText = await publishResponse.text();
      console.error('Publish failed:', errorText);
      return;
    }
    
    const publishResult = await publishResponse.json();
    console.log('\n📊 Publishing Results:');
    console.log(JSON.stringify(publishResult, null, 2));
    
    if (publishResult.results) {
      console.log('\n📋 Platform Results Summary:');
      Object.entries(publishResult.results).forEach(([platform, result]) => {
        const status = result.success ? '✅ SUCCESS' : '❌ FAILED';
        console.log(`  ${platform.toUpperCase()}: ${status}`);
        if (result.error) {
          console.log(`    Error: ${result.error}`);
        }
        if (result.platformPostId) {
          console.log(`    Post ID: ${result.platformPostId}`);
        }
      });
    }
    
    console.log(`\n📈 Overall Success: ${publishResult.success ? 'Yes' : 'No'}`);
    if (publishResult.remainingPosts !== undefined) {
      console.log(`🔢 Remaining Posts: ${publishResult.remainingPosts}`);
    }
    
  } catch (error) {
    console.error('❌ Real publishing test failed:', error.message);
  }
}

testRealPublish();