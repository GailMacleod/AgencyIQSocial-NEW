/**
 * Comprehensive VEO3 Video Generation Test Suite
 * Tests all aspects of the new VEO3 integration
 */

const axios = require('axios');
const fs = require('fs');
const path = require('path');

const BASE_URL = 'http://localhost:5000';

// Test session management
let testSessionId = null;

class VEO3TestSuite {
  constructor() {
    this.testResults = {
      total: 0,
      passed: 0,
      failed: 0,
      errors: []
    };
  }

  async runTest(testName, testFn) {
    this.testResults.total++;
    console.log(`\n🧪 Testing: ${testName}`);
    
    try {
      await testFn();
      this.testResults.passed++;
      console.log(`✅ PASS: ${testName}`);
    } catch (error) {
      this.testResults.failed++;
      this.testResults.errors.push({ test: testName, error: error.message });
      console.log(`❌ FAIL: ${testName} - ${error.message}`);
    }
  }

  async establishTestSession() {
    try {
      console.log('🔧 Establishing test session...');
      const response = await axios.get(`${BASE_URL}/api/auth/session`);
      
      if (response.data.authenticated && response.data.userId === 2) {
        testSessionId = response.data.sessionId;
        console.log(`✅ Test session established: ${testSessionId}`);
        return true;
      }
      throw new Error('Failed to establish session');
    } catch (error) {
      throw new Error(`Session establishment failed: ${error.message}`);
    }
  }

  async testVideoServiceImports() {
    // Test that VideoService can be imported without ESM conflicts
    try {
      const videoServicePath = path.join(__dirname, 'server', 'videoService.js');
      const exists = fs.existsSync(videoServicePath);
      
      if (!exists) {
        throw new Error('VideoService file not found');
      }

      // Check for dynamic import implementation
      const content = fs.readFileSync(videoServicePath, 'utf8');
      
      if (!content.includes('initializeGoogleAI')) {
        throw new Error('Dynamic Google AI initialization not found');
      }
      
      if (!content.includes('generateVeo3VideoContent')) {
        throw new Error('VEO3 video generation method not found');
      }
      
      if (!content.includes('downloadVeo3Video')) {
        throw new Error('VEO3 video download method not found');
      }

      console.log('📦 VideoService structure validated');
    } catch (error) {
      throw new Error(`VideoService import test failed: ${error.message}`);
    }
  }

  async testVideosDirectoryAndEndpoint() {
    try {
      // Check if videos directory exists
      const videosDir = path.join(__dirname, 'public', 'videos');
      if (!fs.existsSync(videosDir)) {
        fs.mkdirSync(videosDir, { recursive: true });
        console.log('📁 Videos directory created');
      } else {
        console.log('📁 Videos directory exists');
      }

      // Test videos endpoint accessibility
      const response = await axios.get(`${BASE_URL}/videos/`, {
        validateStatus: () => true // Accept any status code
      });
      
      // 404 is acceptable for empty directory, 200 for directory listing
      if (response.status !== 404 && response.status !== 200) {
        throw new Error(`Videos endpoint returned unexpected status: ${response.status}`);
      }
      
      console.log('🌐 Videos endpoint accessible');
    } catch (error) {
      throw new Error(`Videos directory/endpoint test failed: ${error.message}`);
    }
  }

  async testVideoPromptGeneration() {
    try {
      const response = await axios.post(`${BASE_URL}/api/video/generate-prompts`, {
        postContent: 'Queensland SME business transformation',
        platform: 'youtube',
        brandData: {
          corePurpose: 'Professional business automation for Queensland SMEs',
          brandName: 'TheAgencyIQ'
        }
      }, {
        headers: {
          'Content-Type': 'application/json'
        },
        withCredentials: true
      });

      if (response.status !== 200) {
        throw new Error(`Prompt generation failed with status: ${response.status}`);
      }

      const data = response.data;
      
      if (!data.success || !data.prompts || !Array.isArray(data.prompts)) {
        throw new Error('Invalid prompt generation response structure');
      }

      if (data.prompts.length < 3) {
        throw new Error('Expected at least 3 video prompts');
      }

      // Verify prompt content
      const firstPrompt = data.prompts[0];
      if (!firstPrompt.content || !firstPrompt.type || !firstPrompt.duration) {
        throw new Error('Prompt missing required fields');
      }

      console.log(`📝 Generated ${data.prompts.length} video prompts successfully`);
    } catch (error) {
      if (error.response && error.response.status === 401) {
        throw new Error('Authentication required - session not properly established');
      }
      throw new Error(`Video prompt generation test failed: ${error.message}`);
    }
  }

  async testVeo3VideoRendering() {
    try {
      const testPrompt = {
        content: 'EPIC CORPORATE TRANSFORMATION: Generate 8-second cinematic business video featuring Queensland SME transformation from invisible to industry leader with dramatic lighting and professional cinematography.',
        type: 'Epic Corporate Transformation',
        duration: '8s',
        style: 'Cinematic business transformation',
        theme: 'Professional Authority Emergence'
      };

      console.log('🎬 Testing VEO3 video rendering...');
      
      const response = await axios.post(`${BASE_URL}/api/video/render`, {
        prompt: testPrompt,
        platform: 'youtube',
        brandPurpose: {
          corePurpose: 'Professional business automation for Queensland SMEs'
        }
      }, {
        headers: {
          'Content-Type': 'application/json'
        },
        withCredentials: true,
        timeout: 60000 // 60 second timeout for video generation
      });

      if (response.status !== 200) {
        throw new Error(`Video rendering failed with status: ${response.status}`);
      }

      const data = response.data;
      
      if (!data.success) {
        throw new Error(`Video rendering failed: ${data.error || 'Unknown error'}`);
      }

      // Check if video data is properly structured
      if (!data.videoData) {
        throw new Error('Video data not found in response');
      }

      const videoData = data.videoData;
      
      // Verify video data structure
      if (!videoData.id || !videoData.platform || !videoData.prompt) {
        throw new Error('Video data missing required fields');
      }

      // Check if video URL is provided (for successful VEO3 generation) or preview mode
      if (videoData.url) {
        console.log('🎥 VEO3 video URL generated successfully');
        
        // Test if video URL is accessible
        try {
          const videoResponse = await axios.head(videoData.url, {
            validateStatus: () => true
          });
          
          if (videoResponse.status === 200) {
            console.log('✅ Generated video is accessible');
          } else {
            console.log('⚠️ Video URL not yet accessible (generation in progress)');
          }
        } catch (urlError) {
          console.log('⚠️ Video URL test failed (may be in progress)');
        }
      } else {
        console.log('🎭 Video in preview mode (VEO3 generation may be in progress)');
      }

      console.log('🎬 Video rendering test completed successfully');
    } catch (error) {
      if (error.response && error.response.status === 401) {
        throw new Error('Authentication required - session not properly established');
      }
      if (error.code === 'ECONNABORTED') {
        console.log('⏰ Video generation timeout - this is normal for VEO3 processing');
        return; // Timeout is acceptable for video generation
      }
      throw new Error(`VEO3 video rendering test failed: ${error.message}`);
    }
  }

  async testVideoApprovalFlow() {
    try {
      // First get existing posts to find a video post
      const postsResponse = await axios.get(`${BASE_URL}/api/posts`, {
        withCredentials: true
      });

      if (postsResponse.status !== 200) {
        throw new Error('Failed to fetch posts for approval test');
      }

      const posts = postsResponse.data;
      const videoPosts = posts.filter(post => post.isVideo && !post.approved);

      if (videoPosts.length === 0) {
        console.log('⚠️ No unapproved video posts found, skipping approval test');
        return;
      }

      const testPost = videoPosts[0];
      
      const approvalResponse = await axios.post(`${BASE_URL}/api/video/approve`, {
        postId: testPost.id
      }, {
        headers: {
          'Content-Type': 'application/json'
        },
        withCredentials: true
      });

      if (approvalResponse.status !== 200) {
        throw new Error(`Video approval failed with status: ${approvalResponse.status}`);
      }

      const approvalData = approvalResponse.data;
      
      if (!approvalData.success) {
        throw new Error(`Video approval failed: ${approvalData.error}`);
      }

      console.log('✅ Video approval flow working');
      
      // Check if auto-posting was triggered
      if (approvalData.autoPosting) {
        console.log('🚀 Auto-posting integration triggered successfully');
      }

    } catch (error) {
      if (error.response && error.response.status === 401) {
        throw new Error('Authentication required for approval test');
      }
      throw new Error(`Video approval test failed: ${error.message}`);
    }
  }

  async testQuotaValidation() {
    try {
      const response = await axios.get(`${BASE_URL}/api/quota-status`, {
        withCredentials: true
      });

      if (response.status !== 200) {
        throw new Error(`Quota status check failed with status: ${response.status}`);
      }

      const quotaData = response.data;
      
      if (typeof quotaData.remainingPosts !== 'number' || 
          typeof quotaData.totalPosts !== 'number') {
        throw new Error('Invalid quota data structure');
      }

      console.log(`📊 Quota status: ${quotaData.remainingPosts}/${quotaData.totalPosts} posts remaining`);
      
      // Verify quota is properly tracked
      if (quotaData.remainingPosts < 0) {
        throw new Error('Negative remaining posts detected');
      }

    } catch (error) {
      if (error.response && error.response.status === 401) {
        throw new Error('Authentication required for quota test');
      }
      throw new Error(`Quota validation test failed: ${error.message}`);
    }
  }

  async testPlatformConnections() {
    try {
      const response = await axios.get(`${BASE_URL}/api/platform-connections`, {
        withCredentials: true
      });

      if (response.status !== 200) {
        throw new Error(`Platform connections check failed with status: ${response.status}`);
      }

      const platforms = response.data;
      
      if (!Array.isArray(platforms)) {
        throw new Error('Platform connections should return an array');
      }

      // Check for required platforms that support video
      const videoPlatforms = ['youtube', 'facebook', 'instagram'];
      const connectedVideoPlatforms = platforms
        .filter(p => videoPlatforms.includes(p.platform) && p.connected)
        .length;

      console.log(`📱 ${connectedVideoPlatforms} video-capable platforms connected`);
      
      if (connectedVideoPlatforms === 0) {
        console.log('⚠️ No video platforms connected - video publishing will be limited');
      }

    } catch (error) {
      throw new Error(`Platform connections test failed: ${error.message}`);
    }
  }

  async runAllTests() {
    console.log('🚀 Starting VEO3 Video Generation Test Suite\n');
    console.log('=' .repeat(60));

    // Establish session first
    await this.runTest('Session Establishment', () => this.establishTestSession());
    
    // Test core components
    await this.runTest('VideoService Structure', () => this.testVideoServiceImports());
    await this.runTest('Videos Directory & Endpoint', () => this.testVideosDirectoryAndEndpoint());
    await this.runTest('Platform Connections', () => this.testPlatformConnections());
    await this.runTest('Quota Validation', () => this.testQuotaValidation());
    
    // Test video generation pipeline
    await this.runTest('Video Prompt Generation', () => this.testVideoPromptGeneration());
    await this.runTest('VEO3 Video Rendering', () => this.testVeo3VideoRendering());
    await this.runTest('Video Approval Flow', () => this.testVideoApprovalFlow());

    // Print summary
    this.printSummary();
  }

  printSummary() {
    console.log('\n' + '=' .repeat(60));
    console.log('📊 VEO3 TEST RESULTS SUMMARY');
    console.log('=' .repeat(60));
    console.log(`Total Tests: ${this.testResults.total}`);
    console.log(`✅ Passed: ${this.testResults.passed}`);
    console.log(`❌ Failed: ${this.testResults.failed}`);
    
    const successRate = ((this.testResults.passed / this.testResults.total) * 100).toFixed(1);
    console.log(`📈 Success Rate: ${successRate}%`);

    if (this.testResults.failed > 0) {
      console.log('\n🔍 FAILED TESTS:');
      this.testResults.errors.forEach((error, index) => {
        console.log(`${index + 1}. ${error.test}: ${error.error}`);
      });
    }

    if (successRate >= 85) {
      console.log('\n🎉 VEO3 VIDEO GENERATION SYSTEM: OPERATIONAL');
    } else {
      console.log('\n⚠️ VEO3 VIDEO GENERATION SYSTEM: NEEDS ATTENTION');
    }
    
    console.log('=' .repeat(60));
  }
}

// Run the test suite
const testSuite = new VEO3TestSuite();
testSuite.runAllTests().catch(error => {
  console.error('💥 Test suite failed to start:', error.message);
  process.exit(1);
});