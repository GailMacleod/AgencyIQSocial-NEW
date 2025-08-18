/**
 * FINAL USER EXPERIENCE TEST
 * Tests actual user workflows end-to-end
 */

const axios = require('axios');

const BASE_URL = 'http://localhost:5000';
const TEST_COOKIE = 'theagencyiq.session=s%3Aaiq_md9zaigr_aknyuyl19nd.BezvuNEUo23IMWaBetxnSP5hof3lSdNdsjLrdkNQtzs';

async function testUserWorkflows() {
  console.log('👤 FINAL USER EXPERIENCE TEST');
  console.log('==============================');
  
  let allTestsPassed = true;
  
  // Workflow 1: User logs in and sees their data
  console.log('🔐 Testing: User Authentication & Profile');
  try {
    const userResponse = await axios.get(`${BASE_URL}/api/user`, {
      headers: { 'Cookie': TEST_COOKIE }
    });
    
    const userStatusResponse = await axios.get(`${BASE_URL}/api/user-status`, {
      headers: { 'Cookie': TEST_COOKIE }
    });
    
    console.log(`   ✅ User authenticated: ${userResponse.data.email}`);
    console.log(`   ✅ Subscription: ${userStatusResponse.data.user.subscriptionPlan} (${userStatusResponse.data.user.remainingPosts}/${userStatusResponse.data.user.totalPosts} posts)`);
  } catch (error) {
    console.log(`   ❌ Authentication failed: ${error.message}`);
    allTestsPassed = false;
  }

  // Workflow 2: User views their brand purpose
  console.log('');
  console.log('🎯 Testing: Brand Purpose Management');
  try {
    const brandResponse = await axios.get(`${BASE_URL}/api/brand-purpose`, {
      headers: { 'Cookie': TEST_COOKIE }
    });
    
    console.log(`   ✅ Brand Name: ${brandResponse.data.brandName}`);
    console.log(`   ✅ Core Purpose: ${brandResponse.data.corePurpose?.substring(0, 50)}...`);
  } catch (error) {
    console.log(`   ❌ Brand purpose failed: ${error.message}`);
    allTestsPassed = false;
  }

  // Workflow 3: User views their posts
  console.log('');
  console.log('📝 Testing: Content Management');
  try {
    const postsResponse = await axios.get(`${BASE_URL}/api/posts`, {
      headers: { 'Cookie': TEST_COOKIE }
    });
    
    console.log(`   ✅ Total posts: ${postsResponse.data.length}`);
    
    if (postsResponse.data.length > 0) {
      const samplePost = postsResponse.data[0];
      console.log(`   ✅ Sample post platform: ${samplePost.platform}`);
      console.log(`   ✅ Sample post content: ${samplePost.content?.substring(0, 50)}...`);
    }
  } catch (error) {
    console.log(`   ❌ Posts retrieval failed: ${error.message}`);
    allTestsPassed = false;
  }

  // Workflow 4: User checks platform connections
  console.log('');
  console.log('🔗 Testing: Platform Connections');
  try {
    const connectionsResponse = await axios.get(`${BASE_URL}/api/platform-connections`, {
      headers: { 'Cookie': TEST_COOKIE }
    });
    
    console.log(`   ✅ Connected platforms: ${connectionsResponse.data.length}`);
    
    const platforms = connectionsResponse.data.map(c => c.platform).join(', ');
    console.log(`   ✅ Platforms: ${platforms}`);
  } catch (error) {
    console.log(`   ❌ Platform connections failed: ${error.message}`);
    allTestsPassed = false;
  }

  // Workflow 5: User generates a video
  console.log('');
  console.log('🎬 Testing: Video Generation Workflow');
  try {
    const videoResponse = await axios.post(`${BASE_URL}/api/video/render`, {
      promptType: 'cinematic-auto',
      promptPreview: 'User experience test video',
      editedText: 'Gold Coast restaurant digital marketing success',
      platform: 'instagram',
      postId: 7777
    }, {
      headers: { 'Cookie': TEST_COOKIE, 'Content-Type': 'application/json' }
    });
    
    console.log(`   ✅ Video generated: ${videoResponse.data.videoId}`);
    console.log(`   ✅ Platform: ${videoResponse.data.platform}`);
    console.log(`   ✅ Art directed: ${videoResponse.data.artDirected}`);
    console.log(`   ✅ Strategic intent: ${videoResponse.data.strategicIntent}`);
  } catch (error) {
    console.log(`   ❌ Video generation failed: ${error.message}`);
    allTestsPassed = false;
  }

  // Workflow 6: User views admin dashboard
  console.log('');
  console.log('📊 Testing: Admin Dashboard Access');
  try {
    const adminResponse = await axios.get(`${BASE_URL}/api/admin/video-prompts`, {
      headers: { 'Cookie': TEST_COOKIE }
    });
    
    console.log(`   ✅ Admin dashboard accessible`);
    console.log(`   ✅ Total prompts tracked: ${adminResponse.data.summary.totalPrompts}`);
    console.log(`   ✅ Last 24 hours: ${adminResponse.data.summary.last24Hours}`);
    
    if (adminResponse.data.prompts.length > 0) {
      const recentPrompt = adminResponse.data.prompts[0];
      console.log(`   ✅ Recent prompt platform: ${recentPrompt.platform}`);
      console.log(`   ✅ Recent prompt theme: ${recentPrompt.visualTheme}`);
    }
  } catch (error) {
    console.log(`   ❌ Admin dashboard failed: ${error.message}`);
    allTestsPassed = false;
  }

  // Final Summary
  console.log('');
  console.log('🎯 FINAL SYSTEM CONFIDENCE ASSESSMENT');
  console.log('=====================================');
  
  if (allTestsPassed) {
    console.log('🎉 ALL USER WORKFLOWS SUCCESSFUL');
    console.log('✅ System demonstrates full user experience reliability');
    console.log('✅ Authentication, content management, video generation, and admin features working');
    console.log('✅ Ready for continued development and new features');
    console.log('');
    console.log('📈 CONFIDENCE LEVEL: HIGH');
    console.log('🚀 RECOMMENDATION: System is stable and ready for further development');
  } else {
    console.log('⚠️  SOME USER WORKFLOWS FAILED');
    console.log('📈 CONFIDENCE LEVEL: MODERATE');
    console.log('🔧 RECOMMENDATION: Address failing workflows before adding new features');
  }
}

testUserWorkflows().catch(console.error);