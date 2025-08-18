#!/usr/bin/env node

/**
 * Complete Platform Publishing Test
 * Tests publishing "TEST" to all 5 platforms: Facebook, Instagram, LinkedIn, X, YouTube
 */

const baseUrl = 'https://4fc77172-459a-4da7-8c33-5014abb1b73e-00-dqhtnud4ismj.worf.replit.dev';

async function testPlatformPublishing() {
  console.log('🚀 COMPREHENSIVE PLATFORM PUBLISHING TEST');
  console.log('==========================================');
  console.log('Testing publication of "TEST" to all platforms...\n');

  // Test 1: Direct Publishing API
  console.log('📝 TEST 1: Direct Publishing API');
  console.log('----------------------------------');
  
  try {
    const directResponse = await fetch(`${baseUrl}/api/direct-publish`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        content: 'TEST',
        platforms: ['facebook', 'instagram', 'linkedin', 'x', 'youtube']
      })
    });

    console.log(`Response Status: ${directResponse.status}`);
    
    if (directResponse.ok) {
      const result = await directResponse.json();
      console.log('✅ Direct Publishing Results:');
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
    } else {
      const errorText = await directResponse.text();
      console.log('❌ Direct Publishing Failed:', errorText);
    }
  } catch (error) {
    console.error('❌ Direct Publishing Error:', error.message);
  }

  console.log('\n' + '='.repeat(50));
  
  // Test 2: Create and Publish Post via Standard API
  console.log('📝 TEST 2: Standard Post Creation and Publishing');
  console.log('------------------------------------------------');
  
  try {
    // First create a post
    const createResponse = await fetch(`${baseUrl}/api/posts`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        content: 'TEST',
        platform: 'facebook', // Start with Facebook
        status: 'draft'
      })
    });

    if (createResponse.ok) {
      const newPost = await createResponse.json();
      console.log('✅ Post Created:', newPost.id);
      
      // Now publish to all platforms
      const publishResponse = await fetch(`${baseUrl}/api/publish-post`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          postId: newPost.id,
          platforms: ['facebook', 'instagram', 'linkedin', 'x', 'youtube']
        })
      });

      console.log(`Publish Response Status: ${publishResponse.status}`);
      
      if (publishResponse.ok) {
        const publishResult = await publishResponse.json();
        console.log('✅ Standard Publishing Results:');
        console.log(JSON.stringify(publishResult, null, 2));
        
        if (publishResult.results) {
          console.log('\n📋 Platform Results Summary:');
          Object.entries(publishResult.results).forEach(([platform, platformResult]) => {
            const status = platformResult.success ? '✅ SUCCESS' : '❌ FAILED';
            console.log(`  ${platform.toUpperCase()}: ${status}`);
            if (platformResult.error) {
              console.log(`    Error: ${platformResult.error}`);
            }
            if (platformResult.platformPostId) {
              console.log(`    Post ID: ${platformResult.platformPostId}`);
            }
          });
        }
      } else {
        const errorText = await publishResponse.text();
        console.log('❌ Standard Publishing Failed:', errorText);
      }
    } else {
      const errorText = await createResponse.text();
      console.log('❌ Post Creation Failed:', errorText);
    }
  } catch (error) {
    console.error('❌ Standard Publishing Error:', error.message);
  }

  console.log('\n' + '='.repeat(50));
  
  // Test 3: Individual Platform Tests
  console.log('📝 TEST 3: Individual Platform Connection Tests');
  console.log('-----------------------------------------------');
  
  const platforms = ['facebook', 'instagram', 'linkedin', 'x', 'youtube'];
  
  for (const platform of platforms) {
    console.log(`\n🔗 Testing ${platform.toUpperCase()} connection...`);
    
    try {
      const statusResponse = await fetch(`${baseUrl}/api/check-live-status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ platform })
      });

      if (statusResponse.ok) {
        const statusResult = await statusResponse.json();
        console.log(`   Status: ${statusResult.status}`);
        console.log(`   Connected: ${statusResult.status === 'connected' ? 'Yes' : 'No'}`);
        
        if (statusResult.status === 'connected') {
          // Try individual publishing
          const individualResponse = await fetch(`${baseUrl}/api/direct-publish`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              content: 'TEST',
              platforms: [platform]
            })
          });

          if (individualResponse.ok) {
            const individualResult = await individualResponse.json();
            const platformResult = individualResult.results[0];
            const status = platformResult.success ? '✅ SUCCESS' : '❌ FAILED';
            console.log(`   Publishing: ${status}`);
            if (platformResult.error) {
              console.log(`   Error: ${platformResult.error}`);
            }
            if (platformResult.postId) {
              console.log(`   Post ID: ${platformResult.postId}`);
            }
          } else {
            console.log(`   Publishing: ❌ FAILED (HTTP ${individualResponse.status})`);
          }
        } else {
          console.log(`   Publishing: ⏸️ SKIPPED (not connected)`);
        }
      } else {
        console.log(`   Status: ❌ FAILED (HTTP ${statusResponse.status})`);
      }
    } catch (error) {
      console.log(`   Error: ${error.message}`);
    }
  }

  console.log('\n' + '='.repeat(50));
  console.log('🏁 PUBLISHING TEST COMPLETE');
  console.log('Check the results above for each platform\'s success/failure status.');
  console.log('='.repeat(50));
}

// Run the test
testPlatformPublishing().catch(console.error);