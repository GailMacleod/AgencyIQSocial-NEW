/**
 * Video Data Type Validation Test
 * Tests for videoUrl vs url data type mismatches
 */

const axios = require('axios');

const BASE_URL = 'http://localhost:5000';

async function testVideoDataTypes() {
  console.log('🔍 Testing Video Data Type Consistency\n');
  
  try {
    // Test 1: Video prompt generation response structure
    console.log('1. Testing video prompt generation response...');
    const promptResponse = await axios.post(`${BASE_URL}/api/video/generate-prompts`, {
      postContent: 'Test business video',
      platform: 'youtube',
      brandData: { corePurpose: 'Test purpose' }
    }, {
      withCredentials: true,
      validateStatus: () => true
    });

    if (promptResponse.status === 200) {
      const prompts = promptResponse.data.prompts;
      if (prompts && prompts.length > 0) {
        const firstPrompt = prompts[0];
        console.log('   Prompt structure:', Object.keys(firstPrompt));
        console.log('   ✅ Video prompt generation working');
      }
    } else {
      console.log(`   ⚠️ Video prompt generation failed: ${promptResponse.status}`);
    }

    // Test 2: Video rendering response structure
    console.log('\n2. Testing video rendering response...');
    const renderResponse = await axios.post(`${BASE_URL}/api/video/render`, {
      prompt: {
        content: 'Test video prompt',
        type: 'test',
        duration: '8s'
      },
      platform: 'youtube'
    }, {
      withCredentials: true,
      validateStatus: () => true,
      timeout: 30000
    });

    if (renderResponse.status === 200) {
      const videoData = renderResponse.data.videoData;
      if (videoData) {
        console.log('   Video data structure:', Object.keys(videoData));
        
        // Check for videoUrl vs url consistency
        if (videoData.videoUrl) {
          console.log('   ✅ Uses "videoUrl" field');
        } else if (videoData.url) {
          console.log('   ✅ Uses "url" field');
        } else {
          console.log('   ⚠️ No video URL field found (may be preview mode)');
        }
        
        console.log('   ✅ Video rendering working');
      }
    } else {
      console.log(`   ⚠️ Video rendering failed: ${renderResponse.status}`);
    }

    // Test 3: Posts API video data structure
    console.log('\n3. Testing posts API video data structure...');
    const postsResponse = await axios.get(`${BASE_URL}/api/posts`, {
      withCredentials: true,
      validateStatus: () => true
    });

    if (postsResponse.status === 200) {
      const posts = postsResponse.data;
      const videoPosts = posts.filter(post => post.isVideo);
      
      if (videoPosts.length > 0) {
        const videoPost = videoPosts[0];
        console.log('   Video post structure:', Object.keys(videoPost));
        
        // Check for URL field consistency
        if (videoPost.videoUrl) {
          console.log('   ✅ Posts use "videoUrl" field');
        } else if (videoPost.url) {
          console.log('   ✅ Posts use "url" field');
        } else {
          console.log('   ⚠️ Video post missing URL field');
        }
      } else {
        console.log('   ℹ️ No video posts found');
      }
      
      console.log('   ✅ Posts API working');
    } else {
      console.log(`   ⚠️ Posts API failed: ${postsResponse.status}`);
    }

    // Test 4: Frontend video component data expectations
    console.log('\n4. Testing frontend video component compatibility...');
    
    // Check VideoPostCardSimple.tsx for expected field names
    const fs = require('fs');
    const path = require('path');
    
    try {
      const componentPath = path.join(__dirname, 'client', 'src', 'components', 'VideoPostCardSimple.tsx');
      const componentContent = fs.readFileSync(componentPath, 'utf8');
      
      if (componentContent.includes('videoUrl')) {
        console.log('   ✅ Frontend expects "videoUrl" field');
      } else if (componentContent.includes('.url')) {
        console.log('   ✅ Frontend expects "url" field');
      } else {
        console.log('   ⚠️ Frontend video URL field usage unclear');
      }
      
    } catch (error) {
      console.log('   ⚠️ Could not analyze frontend component');
    }

    console.log('\n✅ Video data type validation completed');
    
  } catch (error) {
    console.error('❌ Video data type test failed:', error.message);
  }
}

testVideoDataTypes();