/**
 * Final OAuth System Test - Complete Integration Verification
 * Tests all OAuth credentials and token exchange functionality
 */

async function testCompleteOAuthSystem() {
  const baseUrl = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';
  
  console.log('🔐 COMPLETE OAUTH SYSTEM TEST');
  console.log('=============================');
  
  try {
    // First, get current posts to find one to publish
    console.log('📋 Getting current posts...');
    const postsResponse = await fetch(`${baseUrl}/api/posts`, {
      credentials: 'include'
    });
    
    if (!postsResponse.ok) {
      console.error('Failed to get posts:', await postsResponse.text());
      return;
    }
    
    const posts = await postsResponse.json();
    console.log(`Found ${posts.length} posts`);
    
    // Find a draft post to publish
    const draftPost = posts.find(p => p.status === 'draft');
    if (!draftPost) {
      console.log('No draft posts found');
      return;
    }
    
    console.log(`Using draft post: ${draftPost.id} - "${draftPost.content.substring(0, 50)}..."`);
    
    // Test publishing to each platform individually
    const platforms = ['facebook', 'instagram', 'linkedin', 'x', 'youtube'];
    const results = [];
    
    for (const platform of platforms) {
      console.log(`\n🚀 Testing ${platform.toUpperCase()} publishing...`);
      
      try {
        const publishResponse = await fetch(`${baseUrl}/api/publish-post`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          credentials: 'include',
          body: JSON.stringify({
            postId: draftPost.id,
            platform: platform
          })
        });
        
        console.log(`${platform} response status: ${publishResponse.status}`);
        
        if (publishResponse.ok) {
          const result = await publishResponse.json();
          results.push({
            platform,
            success: true,
            message: result.message,
            postId: result.postId,
            remainingPosts: result.remainingPosts
          });
          console.log(`✅ ${platform} SUCCESS: ${result.message}`);
        } else {
          const errorResult = await publishResponse.json();
          results.push({
            platform,
            success: false,
            error: errorResult.message || errorResult.error,
            status: publishResponse.status
          });
          console.log(`❌ ${platform} FAILED: ${errorResult.message || errorResult.error}`);
        }
        
      } catch (error) {
        results.push({
          platform,
          success: false,
          error: error.message
        });
        console.log(`❌ ${platform} ERROR: ${error.message}`);
      }
    }
    
    // Summary results
    console.log('\n📊 OAUTH SYSTEM TEST RESULTS');
    console.log('============================');
    
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    
    console.log(`✅ Successful Platforms: ${successful.length}/5`);
    console.log(`❌ Failed Platforms: ${failed.length}/5`);
    
    if (successful.length > 0) {
      console.log('\nSuccessful Platforms:');
      successful.forEach(r => {
        console.log(`  ${r.platform}: ${r.message || 'Published successfully'}`);
      });
    }
    
    if (failed.length > 0) {
      console.log('\nFailed Platforms:');
      failed.forEach(r => {
        console.log(`  ${r.platform}: ${r.error}`);
      });
    }
    
    // OAuth token analysis
    console.log('\n🔍 TOKEN ANALYSIS');
    console.log('=================');
    
    const needsReauth = failed.filter(r => 
      r.error && (
        r.error.includes('Invalid access token') ||
        r.error.includes('Cannot parse access token') ||
        r.error.includes('Token expired') ||
        r.error.includes('not connected')
      )
    );
    
    if (needsReauth.length > 0) {
      console.log(`🔄 Platforms needing OAuth re-authentication: ${needsReauth.length}`);
      needsReauth.forEach(r => {
        console.log(`  ${r.platform}: ${r.error}`);
      });
      
      console.log('\n📋 NEXT STEPS:');
      console.log('1. Visit /connect-platforms page');
      console.log('2. Click "Reconnect" buttons for failed platforms');
      console.log('3. Complete OAuth flow in popup windows');
      console.log('4. Retry publishing test');
    }
    
    // Overall system status
    const systemStatus = successful.length >= 3 ? 'READY' : 'NEEDS_SETUP';
    console.log(`\n🎯 SYSTEM STATUS: ${systemStatus}`);
    
    if (systemStatus === 'READY') {
      console.log('✅ OAuth system is operational and ready for production use');
    } else {
      console.log('⚠️  OAuth system requires token refresh before full functionality');
    }
    
  } catch (error) {
    console.error('❌ Complete OAuth test failed:', error.message);
  }
}

testCompleteOAuthSystem();