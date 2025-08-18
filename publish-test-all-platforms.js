/**
 * PUBLISH TEST TO ALL PLATFORMS
 * Uses the unified state management system to publish "TEST" to all connected platforms
 */

class PlatformPublisher {
  constructor() {
    this.baseUrl = 'http://localhost:5000';
    this.cookies = '';
    this.testContent = 'TEST';
  }

  async publishToAllPlatforms() {
    console.log('🚀 PUBLISHING TEST TO ALL PLATFORMS');
    console.log('===================================');
    
    try {
      // Step 1: Establish session
      await this.establishSession();
      
      // Step 2: Get platform connections using unified endpoint
      const connections = await this.getConnections();
      
      // Step 3: Publish to each platform
      await this.publishToEachPlatform(connections);
      
      console.log('\n✅ PUBLISHING TEST COMPLETE');
      
    } catch (error) {
      console.error('❌ Publishing failed:', error);
    }
  }

  async establishSession() {
    console.log('\n📡 Establishing session...');
    
    const response = await fetch(`${this.baseUrl}/api/establish-session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'gailm@macleodglba.com.au',
        password: 'password123'
      })
    });

    if (response.ok) {
      const setCookie = response.headers.get('set-cookie');
      if (setCookie) {
        this.cookies = setCookie;
      }
      console.log('✅ Session established successfully');
    } else {
      throw new Error(`Session establishment failed: ${response.status}`);
    }
  }

  async getConnections() {
    console.log('\n🔗 Getting platform connections...');
    
    const response = await fetch(`${this.baseUrl}/api/platform-connections`, {
      method: 'GET',
      headers: {
        'Cookie': this.cookies,
        'Content-Type': 'application/json'
      }
    });

    if (response.ok) {
      const connections = await response.json();
      const publishableConnections = connections.filter(conn => 
        conn.isActive && conn.oauthStatus?.isValid && !conn.oauthStatus?.needsRefresh
      );
      
      console.log(`✅ Found ${publishableConnections.length} publishable connections`);
      
      if (publishableConnections.length > 0) {
        console.log('📝 Ready to publish to:');
        publishableConnections.forEach(conn => {
          console.log(`  - ${conn.platform}: ${conn.platformUsername || 'Connected'}`);
        });
      }
      
      return publishableConnections;
    } else {
      throw new Error(`Failed to get connections: ${response.status}`);
    }
  }

  async publishToEachPlatform(connections) {
    console.log('\n📤 Publishing to platforms...');
    
    const publishResults = [];
    
    for (const connection of connections) {
      console.log(`\n🔄 Publishing to ${connection.platform}...`);
      
      try {
        const result = await this.publishToPlatform(connection);
        publishResults.push(result);
        
        if (result.success) {
          console.log(`✅ ${connection.platform}: Published successfully`);
        } else {
          console.log(`❌ ${connection.platform}: ${result.error}`);
        }
      } catch (error) {
        console.log(`❌ ${connection.platform}: ${error.message}`);
        publishResults.push({
          platform: connection.platform,
          success: false,
          error: error.message
        });
      }
    }
    
    // Summary
    console.log('\n📊 PUBLISHING SUMMARY:');
    const successful = publishResults.filter(r => r.success).length;
    const failed = publishResults.filter(r => !r.success).length;
    
    console.log(`✅ Successful: ${successful}`);
    console.log(`❌ Failed: ${failed}`);
    
    publishResults.forEach(result => {
      const emoji = result.success ? '✅' : '❌';
      console.log(`${emoji} ${result.platform}: ${result.success ? 'Success' : result.error}`);
    });
  }

  async publishToPlatform(connection) {
    // Use the direct publishing endpoint with correct action parameter
    const response = await fetch(`${this.baseUrl}/api/direct-publish`, {
      method: 'POST',
      headers: {
        'Cookie': this.cookies,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        action: 'test_publish_all',
        content: this.testContent,
        platforms: [connection.platform]
      })
    });
    
    if (response.ok) {
      const result = await response.json();
      const platformResult = result.results && result.results[connection.platform];
      
      return {
        platform: connection.platform,
        success: platformResult ? platformResult.success : false,
        result: platformResult || result
      };
    } else {
      const error = await response.json().catch(() => ({ error: 'Unknown error' }));
      return {
        platform: connection.platform,
        success: false,
        error: error.error || error.message || `HTTP ${response.status}`
      };
    }
  }
}

// Run the publisher
const publisher = new PlatformPublisher();
publisher.publishToAllPlatforms().catch(console.error);